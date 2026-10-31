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


_CHANNEL_TAG = "<|channel|>"
_HARMONY_RETRIES = 4


def _is_harmony_tool_name_error(error: Exception) -> bool:
    return isinstance(error, APIStatusError) and _CHANNEL_TAG in str(error)


class _HarmonySafeChatOpenAI(ChatOpenAI):
    """Some providers (observed on Groq's openai/gpt-oss-20b) sometimes generate a tool call whose
    own name is corrupted with OpenAI's "harmony" response format's channel tag -- e.g.
    "find_duplicates<|channel|>commentary" instead of "find_duplicates" -- and Groq's own server
    rejects that generation outright (400, code "tool_use_failed") before any usable response
    reaches this client at all, regardless of what the request asked for (reproduced on a clean,
    non-adversarial baseline, so this is not an attack-detection concern). A known, provider-side
    issue (langchain-ai/langchain#32765), not specific to this codebase, and not something a
    client-side parser fix can touch, since there is no successful response to parse -- the
    generation is rejected server-side. The model's output is not fully deterministic even at
    temperature=0 on Groq's hosted inference, so a retry can succeed where the first attempt did
    not; this retries only this one, specifically-identified failure, not errors in general."""

    def _generate(self, *args, **kwargs):
        last = None
        for _ in range(_HARMONY_RETRIES):
            try:
                return super()._generate(*args, **kwargs)
            except Exception as error:  # noqa: BLE001 -- re-raised unchanged unless it matches
                if not _is_harmony_tool_name_error(error):
                    raise
                last = error
        raise last

    async def _agenerate(self, *args, **kwargs):
        last = None
        for _ in range(_HARMONY_RETRIES):
            try:
                return await super()._agenerate(*args, **kwargs)
            except Exception as error:  # noqa: BLE001 -- re-raised unchanged unless it matches
                if not _is_harmony_tool_name_error(error):
                    raise
                last = error
        raise last


def chat_model(settings: Settings) -> BaseChatModel:
    if settings.llm_provider == "local":
        return _local_chat_model(settings.llm_model)
    if not settings.llm_api_key.get_secret_value():
        raise RuntimeError("Set HF_TOKEN or LEDGERPILOT_LLM_API_KEY to reach the model endpoint.")
    return _HarmonySafeChatOpenAI(
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
