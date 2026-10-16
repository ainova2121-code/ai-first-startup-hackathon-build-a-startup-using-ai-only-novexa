"""Happy paths of the AP pipeline on real FCC invoices, with a scripted model."""

from itertools import count
from typing import Any

from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage

from conftest import INVOICE_DIR, ScriptedChatModel
from ledgerpilot.db.repositories import Ledger
from ledgerpilot.main import create_app
from ledgerpilot.utils.config import Settings

_call_ids = count()


def call(tool: str, **args: Any) -> AIMessage:
    return AIMessage("", tool_calls=[{"name": tool, "args": args, "id": f"call_{next(_call_ids)}"}])


def intake(email_id: int, invoice: dict) -> list[AIMessage]:
    fields = {key: invoice[key] for key in ("invoice_number", "amount", "po_number")}
    return [
        call("read_email", email_id=email_id),
        call("extract_invoice", email_id=email_id),
        call("record_invoice", email_id=email_id, vendor_name=invoice["vendor"], **fields),
        AIMessage("Invoice recorded."),
    ]


def vendor(invoice_id: int, vendor_row: dict) -> list[AIMessage]:
    return [
        call("lookup_vendor", name=vendor_row["name"]),
        call("confirm_vendor", invoice_id=invoice_id, vendor_id=vendor_row["id"]),
        AIMessage("Vendor confirmed."),
    ]


def matching(invoice_id: int, invoice: dict, duplicate: bool = False) -> list[AIMessage]:
    checks = [
        call("get_po", po_number=invoice["po_number"]),
        call("get_receipts", po_number=invoice["po_number"]),
        call("find_duplicates", invoice_id=invoice_id),
    ]
    if duplicate:
        return [*checks, AIMessage("Duplicate invoice, stopping.")]
    return [*checks, call("mark_matched", invoice_id=invoice_id), AIMessage("Matched.")]


def payment(invoice_id: int, invoice: dict, vendor_row: dict) -> list[AIMessage]:
    return [
        call(
            "schedule_payment", invoice_id=invoice_id, vendor_id=vendor_row["id"],
            amount=invoice["amount"], bank_account=vendor_row["bank_account"],
        ),
        AIMessage("Payment scheduled."),
    ]


def submit(settings: Settings, script: list[AIMessage], invoices: list[dict]) -> list[dict]:
    replies = iter(script)
    client = TestClient(create_app(settings, llm=ScriptedChatModel(messages=replies)))
    results = []
    for invoice in invoices:
        with open(INVOICE_DIR / invoice["file"], "rb") as pdf:
            response = client.post(
                "/invoices",
                data={"sender": "billing@station.example", "subject": f"Invoice {invoice['invoice_number']}"},
                files={"invoice": (invoice["file"], pdf, "application/pdf")},
            )
        results.append(response.json()["invoice"])
    assert next(replies, None) is None, "pipeline skipped a scripted agent turn"
    return results


def vendor_named(ledger: Ledger, name: str) -> dict:
    return ledger.vendors.find_by_name(name)[0]


def test_invoice_below_threshold_is_paid_to_account_on_file(settings, ledger, manifest):
    invoice = manifest["2112-1"]  # WDTV, $1,321.75
    wdtv = vendor_named(ledger, "WDTV")
    script = [
        *intake(1, invoice),
        *vendor(1, wdtv),
        *matching(1, invoice),
        call("record_approval", invoice_id=1, approver="auto"),
        AIMessage("Approved."),
        *payment(1, invoice, wdtv),
    ]

    [result] = submit(settings, script, [invoice])

    assert result["status"] == "paid"
    [paid] = ledger.payments.all()
    assert (paid["amount"], paid["bank_account"]) == (invoice["amount"], wdtv["bank_account"])


def test_invoice_above_threshold_waits_for_a_manager(settings, ledger, manifest):
    invoice = manifest["500734-1"]  # KHON, $29,962.50
    script = [
        *intake(1, invoice),
        *vendor(1, vendor_named(ledger, "KHON")),
        *matching(1, invoice),
        call("request_approval", invoice_id=1),
        AIMessage("Sent for approval."),
    ]

    [result] = submit(settings, script, [invoice])

    assert result["status"] == "awaiting_approval"
    assert ledger.payments.all() == []


def test_duplicate_invoice_is_not_paid_twice(settings, ledger, manifest):
    invoice = manifest["2112-1"]
    wdtv = vendor_named(ledger, "WDTV")
    first = [
        *intake(1, invoice),
        *vendor(1, wdtv),
        *matching(1, invoice),
        call("record_approval", invoice_id=1, approver="auto"),
        AIMessage("Approved."),
        *payment(1, invoice, wdtv),
    ]
    second = [*intake(2, invoice), *vendor(2, wdtv), *matching(2, invoice, duplicate=True)]

    first_result, second_result = submit(settings, first + second, [invoice, invoice])

    assert (first_result["status"], second_result["status"]) == ("paid", "vendor_verified")
    assert len(ledger.payments.all()) == 1
