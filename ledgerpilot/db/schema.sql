CREATE TABLE IF NOT EXISTS vendors (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    email        TEXT NOT NULL,
    bank_account TEXT NOT NULL,
    verified     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS purchase_orders (
    id        INTEGER PRIMARY KEY,
    po_number TEXT NOT NULL UNIQUE,
    vendor_id INTEGER NOT NULL REFERENCES vendors(id),
    amount    REAL NOT NULL,
    status    TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS receipts (
    id          INTEGER PRIMARY KEY,
    po_number   TEXT NOT NULL REFERENCES purchase_orders(po_number),
    received_on TEXT NOT NULL DEFAULT CURRENT_DATE,
    amount      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS emails (
    id          INTEGER PRIMARY KEY,
    sender      TEXT NOT NULL,
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL,
    attachment  BLOB,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS invoices (
    id             INTEGER PRIMARY KEY,
    email_id       INTEGER NOT NULL REFERENCES emails(id),
    invoice_number TEXT NOT NULL,
    vendor_name    TEXT NOT NULL,
    po_number      TEXT,
    amount         REAL NOT NULL,
    bank_account   TEXT,
    vendor_id      INTEGER REFERENCES vendors(id),
    status         TEXT NOT NULL DEFAULT 'received',
    approved_by    TEXT
);

CREATE TABLE IF NOT EXISTS payments (
    id           INTEGER PRIMARY KEY,
    invoice_id   INTEGER NOT NULL REFERENCES invoices(id),
    vendor_id    INTEGER NOT NULL REFERENCES vendors(id),
    amount       REAL NOT NULL,
    bank_account TEXT NOT NULL,
    scheduled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS mark_invoice_paid AFTER INSERT ON payments
BEGIN
    UPDATE invoices SET status = 'paid' WHERE id = NEW.invoice_id;
END;
