"""The audit ledger is tamper-evident: any change to a sealed event breaks verification."""

from pathlib import Path

from purpleteam.audit.ledger import GENESIS, AuditLedger, merkle_root


def _ledger(tmp_path: Path) -> AuditLedger:
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("attacker", "attack", {"technique": "dan_1"})
    ledger.append("oracle", "breach", {"tool": "update_vendor_bank"})
    ledger.append("defender", "patch", {"patch_ids": ["P2", "P4"]})
    return ledger


def test_intact_ledger_verifies(tmp_path):
    assert _ledger(tmp_path).verify().ok


def test_tampering_with_a_payload_is_detected(tmp_path):
    ledger = _ledger(tmp_path)
    lines = ledger.path.read_text().splitlines()
    lines[1] = lines[1].replace("update_vendor_bank", "lookup_vendor")
    ledger.path.write_text("\n".join(lines) + "\n")
    result = ledger.verify()
    assert not result.ok and result.broken_at == 1


def test_per_actor_chain_links_same_actor_events(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    first = ledger.append("attacker", "attack", {"n": 1})
    ledger.append("oracle", "breach", {})
    second = ledger.append("attacker", "attack", {"n": 2})
    assert first["prev"] == GENESIS
    assert second["prev"] == first["hash"]  # same actor's chain, not the global previous event


def test_merkle_root_changes_when_any_event_changes(tmp_path):
    ledger = _ledger(tmp_path)
    before = ledger.seal()
    ledger.append("verifier", "verdict", {"safe_to_ship": True})
    assert ledger.seal() != before
    assert merkle_root([]) == GENESIS
