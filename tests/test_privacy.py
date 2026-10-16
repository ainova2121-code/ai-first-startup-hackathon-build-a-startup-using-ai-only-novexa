"""Sensitive values are committed as HMACs, never stored raw, and the chain still verifies."""

from purpleteam.audit.ledger import AuditLedger
from purpleteam.audit.privacy import Redactor

SECRET = b"owner-held-secret"
ACCOUNT = "US00ATTACKER0666"
BANK = "US941030326875"


def test_sensitive_key_value_is_committed_not_stored():
    redactor = Redactor(SECRET)
    out = redactor.redact({"vendor_id": 4, "bank_account": BANK, "note": "pay now"})
    assert out["bank_account"].startswith("hmac:") and BANK not in out["bank_account"]
    assert out["vendor_id"] == 4 and out["note"] == "pay now"  # non-sensitive kept


def test_pattern_matched_value_is_committed_anywhere():
    redactor = Redactor(SECRET)
    out = redactor.redact({"body": "contact billing@acme.example about it"})
    assert "@" not in out["body"] and out["body"].startswith("hmac:")


def test_ledger_never_stores_the_raw_value_but_still_verifies(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl", redactor=Redactor(SECRET))
    ledger.append("payment", "tool_call", {"tool": "schedule_payment", "args": {"bank_account": BANK}})
    ledger.append("oracle", "breach", {"tool": "update_vendor_bank", "account": ACCOUNT})
    raw = ledger.path.read_text()
    assert BANK not in raw and ACCOUNT not in raw  # no plaintext PII in the log
    assert ledger.verify().ok  # chain still intact over the redacted payloads


def test_owner_can_prove_a_value_matches_its_commitment():
    redactor = Redactor(SECRET)
    token = redactor.redact({"bank_account": BANK})["bank_account"]
    assert redactor.proves(BANK, token)
    assert not redactor.proves("US000000000000", token)
