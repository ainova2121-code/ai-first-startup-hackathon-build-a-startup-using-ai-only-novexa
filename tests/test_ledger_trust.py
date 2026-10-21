"""Trust-bundle policy: strict schema, log identity, revocation, checkpoint policy, clocks, proofs."""

import json

import pytest

from fixtures.ledger import log_lines, make_ledger, rewrite_log
from purpleteam.audit.keys import AgentKeyring
from purpleteam.audit.ledger import AuditLedger, LedgerCorrupt
from purpleteam.audit.verify import verify_log, verify_proof


def test_strict_schema_rejects_extra_fields_and_loose_hex(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl", events=3)
    original = log_lines(ledger)
    first = json.loads(original[0])
    variants = [
        {**first, "note": "unsigned"},                       # field outside the signed core
        {**first, "sig": first["sig"].upper()},              # same bytes, different spelling
        {**first, "sig": f" {first['sig']}"},                # whitespace bytes.fromhex would tolerate
        {**first, "seq": True},                              # bool is not a sequence number
        {**first, "ts": float("nan")},
    ]
    for variant in variants:
        rewrite_log(ledger, [json.dumps(variant), *original[1:]])
        result = ledger.verify()
        assert not result.ok and result.reason == "malformed event", variant


def test_actor_names_with_trailing_newline_or_path_characters_are_rejected(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    for name in ("agent\n", "../x", "a/b", "a.b", "", "x" * 65):
        with pytest.raises(ValueError):
            ledger.append(name, "attack", {})


def test_a_broken_log_is_never_checkpointed(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl")
    lines = log_lines(ledger)
    rewrite_log(ledger, [lines[0].replace('"n":0', '"n":7'), *lines[1:]])
    with pytest.raises(LedgerCorrupt):
        ledger.export_trust()


def test_a_restart_with_a_pinned_checkpoint_refuses_a_truncated_log(tmp_path):
    keys = tmp_path / "keys"
    ledger = make_ledger(tmp_path / "audit.jsonl", AgentKeyring(keys, b"pw"))
    pinned = ledger.export_trust()["checkpoint"]
    rewrite_log(ledger, log_lines(ledger)[:-1])

    AuditLedger(ledger.path, keyring=AgentKeyring(keys, b"pw"))  # unpinned: starts without noticing
    with pytest.raises(LedgerCorrupt, match="truncated"):
        AuditLedger(ledger.path, keyring=AgentKeyring(keys, b"pw"), pinned_checkpoint=pinned)


def test_events_and_checkpoints_are_bound_to_their_own_log(tmp_path):
    keyring = AgentKeyring()
    first = make_ledger(tmp_path / "a.jsonl", keyring)
    second = make_ledger(tmp_path / "b.jsonl", keyring)
    trust = first.export_trust()

    spliced = first.events()[:2] + second.events()[2:]
    assert "different log" in verify_log(spliced, trust).reason
    assert "different log" in verify_log(second.events(), trust).reason  # a checkpoint of log A says nothing of B

    with pytest.raises(LedgerCorrupt):
        AuditLedger(tmp_path / "a.jsonl", keyring=keyring, log_id="0" * 32)
    with pytest.raises(ValueError):
        AuditLedger(tmp_path / "c.jsonl", log_id="NOT-HEX")


def test_revoked_keys_are_rejected_from_the_revocation_point(tmp_path):
    keyring = AgentKeyring()
    ledger = AuditLedger(tmp_path / "audit.jsonl", keyring=keyring)
    ledger.append("attacker", "attack", {"n": 0})
    ledger.append("attacker", "attack", {"n": 1})
    old_kid = keyring.kid("attacker")
    keyring.rotate("attacker")
    ledger.append("attacker", "attack", {"n": 2})
    keys = keyring.public_keys()

    assert verify_log(ledger.events(), {"keys": keys, "revoked": {old_kid: 2}}).ok  # revoked after its last use
    result = verify_log(ledger.events(), {"keys": keys, "revoked": {old_kid: 1}})
    assert not result.ok and result.broken_at == 1 and "revoked" in result.reason
    assert not verify_log(ledger.events(), {"keys": keys, "revoked": {old_kid: True}}).ok


def test_export_trust_carries_a_real_revocation_through_to_verify_log(tmp_path):
    """The production path, not a hand-rolled trust dict: keyring.revoke() alone is enough for a
    freshly exported trust bundle to reject what it protects against."""
    keyring = AgentKeyring()
    ledger = AuditLedger(tmp_path / "audit.jsonl", keyring=keyring)
    ledger.append("attacker", "attack", {"n": 0})
    old_kid = keyring.kid("attacker")
    keyring.rotate("attacker")
    ledger.append("attacker", "attack", {"n": 1})

    keyring.revoke("attacker", old_kid, as_of_seq=1)
    trust = ledger.export_trust()

    assert trust["revoked"] == {old_kid: 1}
    assert verify_log(ledger.events(), trust).ok  # the revoked key's own events are all before seq 1

    keyring.revoke("attacker", old_kid, as_of_seq=0)
    result = verify_log(ledger.events(), ledger.export_trust())
    assert not result.ok and result.broken_at == 0 and "revoked" in result.reason


def test_export_trust_omits_the_revoked_field_when_nothing_is_revoked(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl")
    assert "revoked" not in ledger.export_trust()


def test_a_revoked_checkpoint_key_voids_later_checkpoints(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl")
    trust = ledger.export_trust()
    ledger_kid = trust["checkpoint"]["kid"]
    assert ledger.verify({**trust, "revoked": {ledger_kid: 99}}).anchored
    assert not ledger.verify({**trust, "revoked": {ledger_kid: 0}}).ok


def test_checkpoint_policy_rejects_stale_or_thin_anchors(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl", events=2)
    trust = ledger.export_trust()
    for i in range(3):
        ledger.append("attacker", "attack", {"n": i})
    checkpoint_time = trust["checkpoint"]["ts"]

    assert ledger.verify(trust, min_checkpoint_size=2).anchored
    assert "too little" in ledger.verify(trust, min_checkpoint_size=5).reason
    assert "too old" in ledger.verify(trust, max_checkpoint_age=10, now=checkpoint_time + 1000).reason
    assert ledger.verify(trust, max_checkpoint_age=10, now=checkpoint_time + 5).anchored


def test_timestamps_that_run_backwards_are_flagged(tmp_path, monkeypatch):
    clock = iter([1000.0, 990.0, 100.0])  # one reading per append
    monkeypatch.setattr("purpleteam.audit.ledger.time.time", lambda: next(clock))
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    for i in range(3):
        ledger.append("attacker", "attack", {"n": i})
    result = ledger.verify(now=2000.0)  # 990 is inside the 60s skew allowance, 100 is not
    assert not result.ok and result.broken_at == 2 and "backwards" in result.reason


def test_a_proof_also_shows_the_previous_event_of_the_same_actor(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl", events=7)
    trust = ledger.export_trust()
    size = trust["checkpoint"]["size"]

    first_of_actor, later = ledger.prove(0, size), ledger.prove(4, size)
    assert first_of_actor["previous"] is None and verify_proof(first_of_actor, trust)
    assert later["previous"]["event"]["seq"] == 2 and verify_proof(later, trust)

    assert not verify_proof({**later, "previous": None}, trust)                       # link removed
    assert not verify_proof({**later, "previous": ledger.prove(1, size)["previous"]}, trust)
    other = ledger.prove(3, size)["previous"]                                         # wrong actor's event
    assert not verify_proof({**later, "previous": other}, trust)
    assert not verify_proof({**first_of_actor, "previous": later["previous"]}, trust)


def test_a_pinned_checkpoint_must_be_real_and_must_apply(tmp_path):
    keyring = AgentKeyring()
    ledger = make_ledger(tmp_path / "a.jsonl", keyring)
    other = make_ledger(tmp_path / "b.jsonl", keyring)
    pinned = ledger.export_trust()["checkpoint"]

    AuditLedger(ledger.path, keyring=keyring, pinned_checkpoint=pinned)  # an intact log passes
    for empty in ({}, "", [], 0):
        with pytest.raises(ValueError):
            AuditLedger(ledger.path, keyring=keyring, pinned_checkpoint=empty)  # never silently skipped
    with pytest.raises(LedgerCorrupt, match="different log"):
        AuditLedger(ledger.path, keyring=keyring, pinned_checkpoint=other.export_trust()["checkpoint"])
    with pytest.raises(LedgerCorrupt):
        AuditLedger(ledger.path, keyring=AgentKeyring(), pinned_checkpoint=pinned)  # signer unknown to this keyring
