"""Composition root: wires settings, ledger, model and ports into the FastAPI app."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from langchain_core.language_models import BaseChatModel
from langchain_openai import ChatOpenAI
from openai import APIStatusError

from ledgerpilot.agents.approval import build_approval_agent
from ledgerpilot.agents.base import AgentFactory
from ledgerpilot.agents.inquiry import build_inquiry_agent
from ledgerpilot.agents.intake import build_intake_agent
from ledgerpilot.agents.matching import build_matching_agent
from ledgerpilot.agents.payment import build_payment_agent
from ledgerpilot.agents.vendor import build_vendor_agent
from ledgerpilot.api import create_router
from ledgerpilot.db.repositories import Ledger, connect
from ledgerpilot.pipeline import InvoicePipeline
from ledgerpilot.ports import EventSink, Guard, NoGuard, NullSink
from ledgerpilot.utils.config import Settings


# Provider error codes for a generation the provider itself rejected (400) before any reply reached us.
REJECTED_GENERATION_CODES = ("tool_use_failed", "output_parse_failed")
# Each retry samples a little more freely: at temperature 0 a retry reproduces the same rejected output.
RETRY_TEMPERATURES = (0.3, 0.6, 0.9)


def is_rejected_generation(error: Exception) -> bool:
    if not (isinstance(error, APIStatusError) and error.status_code == 400):
        return False
    return getattr(error, "code", None) in REJECTED_GENERATION_CODES or any(
        code in str(error) for code in REJECTED_GENERATION_CODES)


class _RetryingChatOpenAI(ChatOpenAI):
    """Groq's openai/gpt-oss models sometimes produce output Groq's own server rejects outright (400):
    a tool call whose name carries the harmony format's channel tag ("find_duplicates<|channel|>commentary",
    code ``tool_use_failed``) or output it cannot parse at all (``output_parse_failed``). Reproduced on
    legitimate requests too, so it is a provider-side generation fault (langchain-ai/langchain#32765), not
    something the request did. Only that rejection is asked again, at a slightly higher temperature each
    time; every other error is raised unchanged."""

    def _temperatures(self) -> tuple[float | None, ...]:
        floor = self.temperature or 0.0
        return (None, *(max(floor, t) for t in RETRY_TEMPERATURES))

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        *retries, last = self._temperatures()
        for temperature in retries:
            try:
                return super()._generate(messages, stop, run_manager, **_with(kwargs, temperature))
            except APIStatusError as error:
                if not is_rejected_generation(error):
                    raise
        return super()._generate(messages, stop, run_manager, **_with(kwargs, last))

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        *retries, last = self._temperatures()
        for temperature in retries:
            try:
                return await super()._agenerate(messages, stop, run_manager, **_with(kwargs, temperature))
            except APIStatusError as error:
                if not is_rejected_generation(error):
                    raise
        return await super()._agenerate(messages, stop, run_manager, **_with(kwargs, last))


def _with(kwargs: dict, temperature: float | None) -> dict:
    return kwargs if temperature is None else {**kwargs, "temperature": temperature}


def chat_model(settings: Settings) -> BaseChatModel:
    if settings.llm_provider == "local":
        return _local_chat_model(settings.llm_model)
    if not settings.llm_api_key.get_secret_value():
        raise RuntimeError("Set HF_TOKEN or LEDGERPILOT_LLM_API_KEY to reach the model endpoint.")
    return _RetryingChatOpenAI(
        model=settings.llm_model,
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
        temperature=settings.llm_temperature,
        reasoning_effort=settings.llm_reasoning_effort,
        max_retries=settings.llm_max_retries,
    )


def _local_chat_model(model_id: str) -> BaseChatModel:
    """A model run entirely on this machine (transformers/torch, already a base dependency) --
    no network call, no API key, no rate limit. Imported lazily so the normal OpenAI-compatible
    path never pays for loading transformers/torch at startup."""
    from langchain_huggingface import ChatHuggingFace, HuggingFacePipeline

    pipeline = HuggingFacePipeline.from_model_id(
        model_id=model_id, task="text-generation",
        pipeline_kwargs={"max_new_tokens": 512, "temperature": 0.7, "do_sample": True, "return_full_text": False},
    )
    return ChatHuggingFace(llm=pipeline)


def create_app(
    settings: Settings | None = None,
    llm: BaseChatModel | None = None,
    guard: Guard = NoGuard(),
    sink: EventSink = NullSink(),
) -> FastAPI:
    settings = settings or Settings()
    ledger = Ledger(connect(settings.db_path))
    factory = AgentFactory(llm or chat_model(settings), guard, sink)

    agents = {
        "intake": build_intake_agent(factory, ledger.emails, ledger.invoices),
        "vendor": build_vendor_agent(factory, ledger.vendors, ledger.invoices),
        "matching": build_matching_agent(factory, ledger.purchase_orders, ledger.receipts, ledger.invoices),
        "approval": build_approval_agent(factory, ledger.invoices, settings.approval_threshold),
        "payment": build_payment_agent(factory, ledger.payments),
    }
    pipeline = InvoicePipeline(agents, ledger.emails, ledger.invoices, ledger.vendors)
    inquiry = build_inquiry_agent(factory, ledger.console)

    app = FastAPI(title="LedgerPilot", description="Agentic accounts payable for a media-buying agency.")
    app.include_router(create_router(pipeline, inquiry, ledger))
    app.add_exception_handler(APIStatusError, model_endpoint_error)
    return app


async def model_endpoint_error(request: Request, exc: APIStatusError) -> JSONResponse:
    return JSONResponse(status_code=502, content={"detail": f"Model endpoint returned {exc.status_code}: {exc.message}"})
