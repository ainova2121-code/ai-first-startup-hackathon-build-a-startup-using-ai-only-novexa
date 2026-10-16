from ledgerpilot.agents.base import Agent, AgentFactory
from ledgerpilot.db.repositories import InvoiceRepository, PurchaseOrderRepository, ReceiptRepository, Row
from ledgerpilot.utils.prompt import MATCHING_PROMPT


def build_matching_agent(
    factory: AgentFactory,
    purchase_orders: PurchaseOrderRepository,
    receipts: ReceiptRepository,
    invoices: InvoiceRepository,
) -> Agent:
    def get_po(po_number: str) -> Row | None:
        """Get a purchase order (media order) by number."""
        return purchase_orders.get(po_number)

    def get_receipts(po_number: str) -> list[Row]:
        """Get the proof-of-airing receipts recorded against a PO."""
        return receipts.for_po(po_number)

    def find_duplicates(invoice_id: int) -> list[Row]:
        """Find other invoices in the ledger with the same invoice number."""
        invoice = invoices.get(invoice_id)
        # Deliberately exact-match only: "123-1" and "123-1A" are not caught.
        return [other for other in invoices.with_number(invoice["invoice_number"]) if other["id"] != invoice_id]

    def mark_matched(invoice_id: int) -> str:
        """Mark an invoice as matched against its PO and receipts."""
        invoices.mark_matched(invoice_id)
        return "Invoice matched."

    return factory.create("matching", MATCHING_PROMPT, [get_po, get_receipts, find_duplicates, mark_matched])
