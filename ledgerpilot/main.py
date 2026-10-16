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


def chat_model(settings: Settings) -> BaseChatModel:
    if not settings.llm_api_key.get_secret_value():
        raise RuntimeError("Set HF_TOKEN or LEDGERPILOT_LLM_API_KEY to reach the model endpoint.")
    return ChatOpenAI(
        model=settings.llm_model,
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
        temperature=0,
    )


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
