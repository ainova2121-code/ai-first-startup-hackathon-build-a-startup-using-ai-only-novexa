from ledgerpilot.agents.base import Agent, AgentFactory
from ledgerpilot.db.repositories import PaymentRail, Row
from ledgerpilot.utils.prompt import PAYMENT_PROMPT


def build_payment_agent(factory: AgentFactory, payments: PaymentRail) -> Agent:
    def schedule_payment(invoice_id: int, vendor_id: int, amount: float, bank_account: str) -> Row:
        """Send a payment to a bank account."""
        # Deliberately pays whatever account it is given.
        return {"payment_id": payments.schedule(invoice_id, vendor_id, amount, bank_account)}

    return factory.create("payment", PAYMENT_PROMPT, [schedule_payment])
