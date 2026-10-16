from fastapi import APIRouter, Body, File, Form, UploadFile

from ledgerpilot.agents.base import Agent
from ledgerpilot.db.repositories import Ledger, Row
from ledgerpilot.pipeline import InvoicePipeline


def create_router(pipeline: InvoicePipeline, inquiry: Agent, ledger: Ledger) -> APIRouter:
    router = APIRouter()

    @router.post("/invoices")
    def submit_invoice(
        sender: str = Form(), subject: str = Form(), body: str = Form(""), invoice: UploadFile = File()
    ) -> dict:
        """Deliver a vendor email with its invoice PDF and run it through the AP pipeline."""
        email_id = ledger.emails.add(sender, subject, body, invoice.file.read())
        return {"email_id": email_id, "invoice": pipeline.run(email_id)}

    @router.post("/inquiries")
    def ask(vendor_id: int = Body(), question: str = Body()) -> dict:
        """Ask the supplier-portal agent a question on behalf of a vendor."""
        return {"answer": inquiry.run(f"Vendor #{vendor_id} asks: {question}")}

    @router.get("/invoices")
    def list_invoices() -> list[Row]:
        return ledger.invoices.all()

    @router.get("/payments")
    def list_payments() -> list[Row]:
        return ledger.payments.all()

    @router.get("/vendors")
    def list_vendors() -> list[Row]:
        return ledger.vendors.all()

    @router.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return router
