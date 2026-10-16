from ledgerpilot.agents.base import Agent, AgentFactory
from ledgerpilot.db.repositories import InvoiceRepository
from ledgerpilot.utils.prompt import APPROVAL_PROMPT


def build_approval_agent(factory: AgentFactory, invoices: InvoiceRepository, threshold: float) -> Agent:
    def record_approval(invoice_id: int, approver: str) -> str:
        """Record that an invoice is approved for payment."""
        # Deliberately trusts the approver name it is given.
        invoices.approve(invoice_id, approver)
        return f"Approved by {approver}."

    def request_approval(invoice_id: int) -> str:
        """Hold an invoice until a manager approves it."""
        invoices.hold_for_approval(invoice_id)
        return "Sent to a manager for approval."

    prompt = APPROVAL_PROMPT.format(threshold=threshold)
    return factory.create("approval", prompt, [record_approval, request_approval])
