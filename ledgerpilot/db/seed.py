"""Seed the ledger from the real invoices in data/invoices (see data/README.md).

Vendors, POs and receipts mirror the curated manifest. Public invoices carry no bank details
or vendor emails, so those two fields are synthetic and deterministic.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from ledgerpilot.db.repositories import Ledger, connect
from ledgerpilot.utils.config import Settings


def load_manifest(invoice_dir: Path) -> list[dict[str, Any]]:
    return json.loads((invoice_dir / "manifest.json").read_text())


def bank_account(vendor: str) -> str:
    digest = int(hashlib.sha256(vendor.encode()).hexdigest(), 16)
    return f"US{digest % 10**12:012d}"


def vendor_email(vendor: str) -> str:
    return f"billing@{re.sub(r'[^a-z0-9]+', '-', vendor.lower()).strip('-')}.example"


def seed(ledger: Ledger, manifest: list[dict[str, Any]]) -> None:
    vendor_ids: dict[str, int] = {}
    for invoice in manifest:
        name = invoice["vendor"]
        if name not in vendor_ids:
            vendor_ids[name] = ledger.vendors.add(name, vendor_email(name), bank_account(name), verified=True)
        if invoice["po_number"]:
            ledger.purchase_orders.add(invoice["po_number"], vendor_ids[name], invoice["amount"])
            ledger.receipts.add(invoice["po_number"], invoice["amount"])


def main() -> None:
    settings = Settings()
    manifest = load_manifest(settings.invoice_dir)
    settings.db_path.unlink(missing_ok=True)
    seed(Ledger(connect(settings.db_path)), manifest)
    print(f"Seeded {settings.db_path} from {len(manifest)} real invoices")


if __name__ == "__main__":
    main()
