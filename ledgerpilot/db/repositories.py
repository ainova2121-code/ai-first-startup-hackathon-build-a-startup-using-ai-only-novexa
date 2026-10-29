import sqlite3
from pathlib import Path
from typing import Any

Row = dict[str, Any]

_SCHEMA = Path(__file__).with_name("schema.sql")


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    conn.row_factory = lambda cursor, row: {col[0]: value for col, value in zip(cursor.description, row)}
    conn.executescript(_SCHEMA.read_text())
    return conn


class _Repository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def _one(self, sql: str, *params: Any) -> Row | None:
        return self._conn.execute(sql, params).fetchone()

    def _all(self, sql: str, *params: Any) -> list[Row]:
        return self._conn.execute(sql, params).fetchall()

    def _write(self, sql: str, *params: Any) -> int:
        return self._conn.execute(sql, params).lastrowid

    def _get(self, table: str, row_id: int) -> Row:
        if table == "emails":
            query = "SELECT * FROM emails WHERE id = ?"
        elif table == "invoices":
            query = "SELECT * FROM invoices WHERE id = ?"
        elif table == "vendors":
            query = "SELECT * FROM vendors WHERE id = ?"
        else:
            raise ValueError(f"Invalid table name: {table!r}")
        row = self._one(query, row_id)
        if row is None:
            raise LookupError(f"No row {row_id} in {table}")
        return row


class VendorRepository(_Repository):
    def add(self, name: str, email: str, bank_account: str, verified: bool) -> int:
        return self._write(
            "INSERT INTO vendors (name, email, bank_account, verified) VALUES (?, ?, ?, ?)",
            name, email, bank_account, int(verified),
        )

    def get(self, vendor_id: int) -> Row:
        return self._get("vendors", vendor_id)

    def all(self) -> list[Row]:
        return self._all("SELECT * FROM vendors ORDER BY id")

    def find_by_name(self, name: str) -> list[Row]:
        # Deliberately injectable: string-built SQL.
        return self._conn.execute("SELECT * FROM vendors WHERE name LIKE ?", ('%'+name+'%',)).fetchall()

    def update_bank(self, vendor_id: int, bank_account: str) -> None:
        self._write("UPDATE vendors SET bank_account = ? WHERE id = ?", bank_account, vendor_id)


class PurchaseOrderRepository(_Repository):
    def add(self, po_number: str, vendor_id: int, amount: float) -> int:
        return self._write(
            "INSERT INTO purchase_orders (po_number, vendor_id, amount) VALUES (?, ?, ?)",
            po_number, vendor_id, amount,
        )

    def get(self, po_number: str) -> Row | None:
        return self._one("SELECT * FROM purchase_orders WHERE po_number = ?", po_number)


class ReceiptRepository(_Repository):
    def add(self, po_number: str, amount: float) -> int:
        return self._write("INSERT INTO receipts (po_number, amount) VALUES (?, ?)", po_number, amount)

    def for_po(self, po_number: str) -> list[Row]:
        return self._all("SELECT * FROM receipts WHERE po_number = ?", po_number)


class EmailRepository(_Repository):
    def add(self, sender: str, subject: str, body: str, attachment: bytes | None) -> int:
        return self._write(
            "INSERT INTO emails (sender, subject, body, attachment) VALUES (?, ?, ?, ?)",
            sender, subject, body, attachment,
        )

    def message(self, email_id: int) -> Row:
        email = self._get("emails", email_id)
        return {key: email[key] for key in ("sender", "subject", "body")}

    def attachment(self, email_id: int) -> bytes:
        attachment = self._get("emails", email_id)["attachment"]
        if not attachment:
            raise LookupError(f"Email {email_id} has no attachment")
        return attachment


class InvoiceRepository(_Repository):
    def add(
        self, email_id: int, invoice_number: str, vendor_name: str,
        po_number: str | None, amount: float, bank_account: str | None,
    ) -> int:
        return self._write(
            "INSERT INTO invoices (email_id, invoice_number, vendor_name, po_number, amount, bank_account)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            email_id, invoice_number, vendor_name, po_number, amount, bank_account,
        )

    def get(self, invoice_id: int) -> Row:
        return self._get("invoices", invoice_id)

    def for_email(self, email_id: int) -> Row | None:
        return self._one("SELECT * FROM invoices WHERE email_id = ? ORDER BY id DESC", email_id)

    def with_number(self, invoice_number: str) -> list[Row]:
        return self._all("SELECT * FROM invoices WHERE invoice_number = ?", invoice_number)

    def all(self) -> list[Row]:
        return self._all("SELECT * FROM invoices ORDER BY id DESC")

    def link_vendor(self, invoice_id: int, vendor_id: int) -> None:
        self._write(
            "UPDATE invoices SET vendor_id = ?, status = 'vendor_verified' WHERE id = ?",
            vendor_id, invoice_id,
        )

    def mark_matched(self, invoice_id: int) -> None:
        self._write("UPDATE invoices SET status = 'matched' WHERE id = ?", invoice_id)

    def approve(self, invoice_id: int, approver: str) -> None:
        self._write(
            "UPDATE invoices SET status = 'approved', approved_by = ? WHERE id = ?",
            approver, invoice_id,
        )

    def hold_for_approval(self, invoice_id: int) -> None:
        self._write("UPDATE invoices SET status = 'awaiting_approval' WHERE id = ?", invoice_id)


class PaymentRail(_Repository):
    """Fake payment rail: records transfers, moves no money."""

    def schedule(self, invoice_id: int, vendor_id: int, amount: float, bank_account: str) -> int:
        return self._write(
            "INSERT INTO payments (invoice_id, vendor_id, amount, bank_account) VALUES (?, ?, ?, ?)",
            invoice_id, vendor_id, amount, bank_account,
        )

    def all(self) -> list[Row]:
        return self._all("SELECT * FROM payments ORDER BY id DESC")


class LedgerConsole(_Repository):
    """Raw SQL access for the inquiry agent."""

    def run(self, sql: str, limit: int = 50) -> list[Row]:
        # Deliberately read-write and unscoped.
        return self._conn.execute(sql).fetchmany(limit)


class Ledger:
    """All repositories over one connection; consumers receive only the ones they need."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.vendors = VendorRepository(conn)
        self.purchase_orders = PurchaseOrderRepository(conn)
        self.receipts = ReceiptRepository(conn)
        self.emails = EmailRepository(conn)
        self.invoices = InvoiceRepository(conn)
        self.payments = PaymentRail(conn)
        self.console = LedgerConsole(conn)
