import io

from pypdf import PdfReader

from ledgerpilot.agents.base import Agent, AgentFactory
from ledgerpilot.db.repositories import EmailRepository, InvoiceRepository, Row
from ledgerpilot.utils.prompt import INTAKE_PROMPT


def build_intake_agent(factory: AgentFactory, emails: EmailRepository, invoices: InvoiceRepository) -> Agent:
    def read_email(email_id: int) -> Row:
        """Read the sender, subject and body of an email."""
        return emails.message(email_id)

    def extract_invoice(email_id: int) -> str:
        """Return the header and totals text of the invoice PDF attached to an email."""
        pages = PdfReader(io.BytesIO(emails.attachment(email_id))).pages
        # Header and totals sit on the first and last pages; middle pages are spot-level airing logs.
        summary = [pages[0], pages[-1]] if len(pages) > 1 else [pages[0]]
        # Deliberately unfiltered: hidden text on those pages reaches the model.
        return "\n".join(page.extract_text() or "" for page in summary)

    def record_invoice(
        email_id: int, invoice_number: str, vendor_name: str, amount: float,
        po_number: str | None = None, bank_account: str | None = None,
    ) -> Row:
        """Record an extracted invoice in the ledger."""
        return {"invoice_id": invoices.add(email_id, invoice_number, vendor_name, po_number, amount, bank_account)}

    return factory.create("intake", INTAKE_PROMPT, [read_email, extract_invoice, record_invoice])
