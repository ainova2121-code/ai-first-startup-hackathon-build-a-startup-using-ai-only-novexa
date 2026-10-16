import json
from collections.abc import Callable
from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from ledgerpilot.agents.base import Agent
from ledgerpilot.db.repositories import EmailRepository, InvoiceRepository, Row, VendorRepository

# Each stage runs only if the previous one left the invoice in the expected status.
STAGES = (
    ("vendor", "received"),
    ("matching", "vendor_verified"),
    ("approval", "matched"),
    ("payment", "approved"),
)


class InvoiceState(TypedDict):
    email_id: int
    invoice_id: int | None


class InvoicePipeline:
    """Intake → vendor → matching → approval → payment, as a LangGraph state machine."""

    def __init__(
        self,
        agents: dict[str, Agent],
        emails: EmailRepository,
        invoices: InvoiceRepository,
        vendors: VendorRepository,
    ) -> None:
        self._agents = agents
        self._emails = emails
        self._invoices = invoices
        self._vendors = vendors
        self._graph = self._build()

    def run(self, email_id: int) -> Row | None:
        state = self._graph.invoke({"email_id": email_id, "invoice_id": None})
        return self._invoices.get(state["invoice_id"]) if state["invoice_id"] else None

    def _build(self) -> CompiledStateGraph:
        graph = StateGraph(InvoiceState)
        graph.add_node("intake", self._intake)
        graph.add_edge(START, "intake")
        previous = "intake"
        for stage, required_status in STAGES:
            graph.add_node(stage, self._stage(self._agents[stage]))
            graph.add_conditional_edges(previous, self._gate(stage, required_status), [stage, END])
            previous = stage
        graph.add_edge(previous, END)
        return graph.compile()

    def _intake(self, state: InvoiceState) -> dict:
        self._agents["intake"].run(f"Email #{state['email_id']} has arrived in the accounts payable inbox.")
        invoice = self._invoices.for_email(state["email_id"])
        return {"invoice_id": invoice["id"] if invoice else None}

    def _stage(self, agent: Agent) -> Callable[[InvoiceState], dict]:
        def run(state: InvoiceState) -> dict:
            agent.run(self._case_file(state["invoice_id"]))
            return {}

        return run

    def _gate(self, stage: str, required_status: str) -> Callable[[InvoiceState], str]:
        def route(state: InvoiceState) -> str:
            invoice_id = state["invoice_id"]
            ready = invoice_id is not None and self._invoices.get(invoice_id)["status"] == required_status
            return stage if ready else END

        return route

    def _case_file(self, invoice_id: int) -> str:
        invoice = self._invoices.get(invoice_id)
        vendor = self._vendors.get(invoice["vendor_id"]) if invoice["vendor_id"] else None
        case = {"invoice": invoice, "vendor_on_file": vendor, "email": self._emails.message(invoice["email_id"])}
        return "Case file:\n" + json.dumps(case, indent=2, default=str)
