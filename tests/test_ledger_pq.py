"""Hybrid signatures (Ed25519 + ML-DSA-65): both halves are required, nothing downgrades, and the
two signature contexts cannot be confused."""

import json

import pytest

from fixtures.ledger import log_lines, make_ledger, rewrite_log
from purpleteam.audit import keys
from purpleteam.audit.keys import CHECKPOINT_CONTEXT, EVENT_CONTEXT, AgentKeyring, kid_of, verify_pq, verify_signature
from purpleteam.audit.ledger import AuditLedger
from purpleteam.audit.verify import verify_log, verify_proof


def _flip(hex_text: str) -> str:
    return hex_text[:-1] + ("0" if hex_text[-1] != "0" else "1")


def test_events_checkpoints_and_trust_keys_are_hybrid_by_default(tmp_path):
    ledger = make_ledger(tmp_path / "a.jsonl", events=3)
    trust = ledger.export_trust()
    for event in ledger.events():
        assert len(event["sig"]) == 128 and len(event["pqsig"]) == 6618  # 64 B Ed25519 and 3309 B ML-DSA-65
        assert len(json.dumps(event)) < 12_000                              # the cost of the second signature
    assert len(trust["checkpoint"]["pqsig"]) == 6618
    for by_kid in trust["keys"].values():
        for kid, public in by_kid.items():
            assert set(public) == {"ed25519", "mldsa65"} and len(public["mldsa65"]) == 3904 and kid_of(public) == kid
    result = ledger.verify(trust, require_pq=True)
    assert result.ok and result.anchored


def test_a_hybrid_key_id_binds_both_public_keys_and_never_collides_with_a_classical_one():
    first, second = AgentKeyring(), AgentKeyring()
    kid = first.kid("a")
    second.kid("a")
    hybrid = first.public_keys()["a"][kid]
    other = next(iter(second.public_keys()["a"].values()))
    assert kid_of(hybrid) == kid != kid_of(hybrid["ed25519"])  # not the classical id of its own Ed25519 half
    assert kid_of({**hybrid, "mldsa65": other["mldsa65"]}) != kid  # changing either half changes the id
    assert kid_of({**hybrid, "ed25519": other["ed25519"]}) != kid


@pytest.mark.parametrize("mutate, reason", [
    (lambda e, other: e.pop("pqsig"), "invalid signature or unknown key"),                 # a downgrade
    (lambda e, other: e.update(sig=_flip(e["sig"])), "invalid signature or unknown key"),   # classical half broken
    (lambda e, other: e.update(pqsig=_flip(e["pqsig"])), "invalid signature or unknown key"),  # PQ half broken
    (lambda e, other: e.update(pqsig=other["pqsig"]), "invalid signature or unknown key"),  # a real PQ signature, wrong event
    (lambda e, other: e.update(sig=other["sig"]), "invalid signature or unknown key"),
    (lambda e, other: e.update(pqsig=e["pqsig"][:-2]), "malformed event"),
    (lambda e, other: e.update(pqsig=e["pqsig"].upper()), "malformed event"),
    (lambda e, other: e.update(pqsig=""), "malformed event"),
], ids=["drop-pqsig", "flip-sig", "flip-pqsig", "swap-pqsig", "swap-sig", "truncate-pqsig", "uppercase-pqsig",
        "empty-pqsig"])
def test_every_event_needs_both_halves_to_verify(tmp_path, mutate, reason):
    ledger = make_ledger(tmp_path / "a.jsonl", events=4)
    lines = log_lines(ledger)
    event, other = json.loads(lines[0]), json.loads(lines[2])  # same actor, a different message
    mutate(event, other)
    rewrite_log(ledger, [json.dumps(event), *lines[1:]])
    result = ledger.verify()
    assert not result.ok and result.broken_at == 0 and result.reason == reason


def test_a_checkpoint_needs_both_halves_too(tmp_path):
    ledger = make_ledger(tmp_path / "a.jsonl")
    trust = ledger.export_trust()
    for tampered in ({k: v for k, v in trust["checkpoint"].items() if k != "pqsig"},
                     {**trust["checkpoint"], "pqsig": _flip(trust["checkpoint"]["pqsig"])},
                     {**trust["checkpoint"], "sig": _flip(trust["checkpoint"]["sig"])}):
        result = ledger.verify({**trust, "checkpoint": tampered})
        assert not result.ok and "checkpoint" in result.reason


def test_the_contexts_keep_event_and_checkpoint_signatures_apart():
    keyring = AgentKeyring()
    signature = keyring.sign("a", b"data", EVENT_CONTEXT)
    public = next(iter(keyring.public_keys()["a"].values()))
    assert verify_pq(public["mldsa65"], b"data", signature.mldsa65, EVENT_CONTEXT)
    assert not verify_pq(public["mldsa65"], b"data", signature.mldsa65, CHECKPOINT_CONTEXT)
    assert not verify_pq(public["mldsa65"], b"other", signature.mldsa65, EVENT_CONTEXT)
    assert verify_signature(public["ed25519"], b"data", signature.ed25519)
    for garbage in ("", "zz", "00" * 10):
        assert not verify_pq(garbage, b"data", signature.mldsa65, EVENT_CONTEXT)
        assert not verify_pq(public["mldsa65"], b"data", garbage, EVENT_CONTEXT)


def test_a_classical_only_keyring_works_but_a_verifier_can_refuse_it(tmp_path):
    ledger = AuditLedger(tmp_path / "classical.jsonl", keyring=AgentKeyring(pq=False))
    ledger.append("attacker", "attack", {"n": 1})
    trust = ledger.export_trust()
    assert "pqsig" not in ledger.events()[0] and "pqsig" not in trust["checkpoint"]
    assert all(isinstance(public, str) for by_kid in trust["keys"].values() for public in by_kid.values())
    assert ledger.verify(trust).ok and ledger.verify(trust).anchored
    refused = ledger.verify(trust, require_pq=True)
    assert not refused.ok and refused.reason == "invalid signature or unknown key"


def test_a_stray_pqsig_on_a_classical_key_is_rejected(tmp_path):
    ledger = make_ledger(tmp_path / "hybrid.jsonl", events=1)
    classical = AuditLedger(tmp_path / "classical.jsonl", keyring=AgentKeyring(pq=False))
    classical.append("attacker", "attack", {"n": 0})
    event = classical.events()[0]
    event["pqsig"] = ledger.events()[0]["pqsig"]  # a borrowed ML-DSA signature does not upgrade a classical key
    result = verify_log([event], {"keys": classical.export_trust()["keys"]})
    assert not result.ok and result.reason == "invalid signature or unknown key"


def test_a_post_quantum_keyring_never_signs_classically_and_old_events_stay_verifiable(tmp_path):
    key_dir = tmp_path / "keys"
    path = tmp_path / "audit.jsonl"
    AuditLedger(path, keyring=AgentKeyring(key_dir, b"pw", pq=False)).append("attacker", "attack", {"n": 0})
    migrated = AuditLedger(path, keyring=AgentKeyring(key_dir, b"pw", allow_classical_history=True))  # explicit opt-in
    migrated.append("attacker", "attack", {"n": 1})                      # rotates to a hybrid key first

    events = migrated.events()
    assert "pqsig" not in events[0] and "pqsig" in events[1] and events[0]["kid"] != events[1]["kid"]
    assert migrated.verify().ok
    assert not migrated.verify(require_pq=True).ok  # the log still holds one classical event
    pinned = migrated.export_trust()["keys"]["attacker"]
    assert isinstance(pinned[events[0]["kid"]], str) and isinstance(pinned[events[1]["kid"]], dict)  # old vs new key
    names = sorted(p.name for p in key_dir.glob("attacker.*.pem"))
    assert len(names) == 3 and sum(n.endswith(".mldsa.pem") for n in names) == 1  # one classical file, then a pair


def test_stored_hybrid_keys_are_encrypted_complete_and_restart_cleanly(tmp_path):
    key_dir = tmp_path / "keys"
    ledger = AuditLedger(tmp_path / "audit.jsonl", keyring=AgentKeyring(key_dir, b"pw"))
    ledger.append("attacker", "attack", {"n": 1})
    files = sorted(key_dir.glob("*.pem"))
    assert len(files) == 2 and any(f.name.endswith(".mldsa.pem") for f in files)
    assert all(b"ENCRYPTED PRIVATE KEY" in f.read_bytes() for f in files)

    restarted = AuditLedger(tmp_path / "audit.jsonl", keyring=AgentKeyring(key_dir, b"pw"))
    restarted.append("attacker", "attack", {"n": 2})
    assert restarted.verify(require_pq=True).ok
    with pytest.raises(ValueError):
        AgentKeyring(key_dir, b"wrong")


def test_a_stored_key_missing_its_post_quantum_file_is_refused_not_downgraded(tmp_path):
    key_dir = tmp_path / "keys"
    AuditLedger(tmp_path / "audit.jsonl", keyring=AgentKeyring(key_dir, b"pw")).append("attacker", "attack", {})
    next(key_dir.glob("*.mldsa.pem")).unlink()
    with pytest.raises(ValueError, match="incomplete"):
        AgentKeyring(key_dir, b"pw")


def test_without_ml_dsa_a_hybrid_keyring_is_an_error_and_verification_fails_closed(tmp_path, monkeypatch):
    ledger = make_ledger(tmp_path / "a.jsonl", events=2)
    trust = ledger.export_trust()
    monkeypatch.setattr(keys, "PQ_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="post-quantum"):
        AgentKeyring()
    AgentKeyring(pq=False)  # explicitly classical is still allowed
    assert not verify_log(ledger.events(), trust).ok  # a verifier that cannot check ML-DSA must not accept it


def test_signing_uses_the_generation_named_by_the_key_id():
    keyring = AgentKeyring()
    old = keyring.kid("a")
    new = keyring.rotate("a")
    publics = keyring.public_keys()["a"]
    by_old = keyring.sign("a", b"x", EVENT_CONTEXT, kid=old)
    assert verify_signature(publics[old]["ed25519"], b"x", by_old.ed25519)
    assert not verify_signature(publics[new]["ed25519"], b"x", by_old.ed25519)
    assert verify_signature(publics[new]["ed25519"], b"x", keyring.sign("a", b"x", EVENT_CONTEXT).ed25519)
    with pytest.raises(ValueError):
        keyring.sign("a", b"x", EVENT_CONTEXT, kid="0" * 16)
    with pytest.raises(ValueError):
        keyring.sign("../a", b"x", EVENT_CONTEXT)


def test_revoking_the_current_key_rotates_to_a_fresh_one_on_next_use():
    keyring = AgentKeyring()
    old = keyring.kid("a")

    keyring.revoke("a", old, as_of_seq=3)

    assert keyring.revoked() == {old: 3}
    assert keyring.kid("a") != old  # _current auto-rotated past the revoked generation


def test_a_revoked_key_refuses_to_sign_even_when_named_by_kid():
    keyring = AgentKeyring()
    old = keyring.kid("a")
    keyring.rotate("a")

    keyring.revoke("a", old)

    with pytest.raises(ValueError, match="revoked"):
        keyring.sign("a", b"x", EVENT_CONTEXT, kid=old)


def test_revoke_validates_the_actor_owns_that_key_id_and_a_sane_sequence():
    keyring = AgentKeyring()
    kid = keyring.kid("a")
    keyring.kid("b")  # a second actor, so "wrong actor" has something real to fail against

    with pytest.raises(ValueError):
        keyring.revoke("b", kid)
    with pytest.raises(ValueError):
        keyring.revoke("a", kid, as_of_seq=-1)
    with pytest.raises(ValueError):
        keyring.revoke("a", "0" * 16)  # no such key at all


def test_revocations_persist_and_still_block_signing_after_a_restart(tmp_path):
    keyring = AgentKeyring(tmp_path, b"pw")
    kid = keyring.kid("a")
    keyring.rotate("a")
    keyring.revoke("a", kid, as_of_seq=5)

    reopened = AgentKeyring(tmp_path, b"pw")
    assert reopened.revoked() == {kid: 5}
    with pytest.raises(ValueError, match="revoked"):
        reopened.sign("a", b"x", EVENT_CONTEXT, kid=kid)


@pytest.mark.parametrize("damage", ["missing-pq", "extra-field", "short-pq", "uppercase", "wrong-kid", "not-a-key"])
def test_malformed_hybrid_entries_in_a_trust_bundle_are_rejected(tmp_path, damage):
    ledger = make_ledger(tmp_path / "a.jsonl", events=2)
    other = make_ledger(tmp_path / "b.jsonl", events=2)
    trust = ledger.export_trust()
    kid, entry = next(iter(trust["keys"]["attacker"].items()))
    swapped = next(iter(other.export_trust()["keys"]["attacker"].values()))
    trust["keys"]["attacker"][kid] = {
        "missing-pq": {"ed25519": entry["ed25519"]},
        "extra-field": {**entry, "extra": "x"},
        "short-pq": {**entry, "mldsa65": entry["mldsa65"][:-2]},
        "uppercase": {**entry, "mldsa65": entry["mldsa65"].upper()},
        "wrong-kid": swapped,  # a genuine hybrid key filed under someone else's id
        "not-a-key": ["ed25519", "mldsa65"],
    }[damage]
    result = ledger.verify(trust)
    assert not result.ok and result.reason == "malformed log or trust bundle"


def test_proofs_need_both_halves_as_well(tmp_path):
    ledger = make_ledger(tmp_path / "a.jsonl", events=7)
    trust = ledger.export_trust()
    size = trust["checkpoint"]["size"]
    proof = ledger.prove(4, size)
    assert verify_proof(proof, trust, require_pq=True)
    stripped = {**proof, "event": {k: v for k, v in proof["event"].items() if k != "pqsig"}}
    assert not verify_proof(stripped, trust)
    previous = {k: v for k, v in proof["previous"]["event"].items() if k != "pqsig"}
    assert not verify_proof({**proof, "previous": {**proof["previous"], "event": previous}}, trust)
    no_checkpoint_pq = {**trust, "checkpoint": {k: v for k, v in trust["checkpoint"].items() if k != "pqsig"}}
    assert not verify_proof(proof, no_checkpoint_pq)


def test_a_post_quantum_keyring_refuses_classical_keys_unless_history_is_allowed(tmp_path):
    key_dir = tmp_path / "keys"
    AuditLedger(tmp_path / "a.jsonl", keyring=AgentKeyring(key_dir, b"pw", pq=False)).append("attacker", "attack", {})
    with pytest.raises(ValueError, match="classical-only"):
        AgentKeyring(key_dir, b"pw")
    AgentKeyring(key_dir, b"pw", allow_classical_history=True)  # an explicit choice
    AgentKeyring(key_dir, b"pw", pq=False)                       # a classical keyring is unaffected


def test_a_hybrid_key_renamed_to_look_classical_is_refused(tmp_path):
    key_dir = tmp_path / "keys"
    keyring = AgentKeyring(key_dir, b"pw")
    kid = keyring.kid("attacker")
    classical_kid = kid_of(keyring.public_keys()["attacker"][kid]["ed25519"])
    (key_dir / f"attacker.0000.{kid}.pem").rename(key_dir / f"attacker.0000.{classical_kid}.pem")
    (key_dir / f"attacker.0000.{kid}.mldsa.pem").unlink()
    with pytest.raises(ValueError, match="classical-only"):
        AgentKeyring(key_dir, b"pw")


def test_a_post_quantum_keyring_never_signs_with_a_classical_generation(tmp_path):
    key_dir = tmp_path / "keys"
    old_kid = AgentKeyring(key_dir, b"pw", pq=False).kid("attacker")
    keyring = AgentKeyring(key_dir, b"pw", allow_classical_history=True)
    with pytest.raises(ValueError, match="does not sign"):
        keyring.sign("attacker", b"x", EVENT_CONTEXT, kid=old_kid)
    assert keyring.sign("attacker", b"x", EVENT_CONTEXT).mldsa65  # the default key rotated to a hybrid one


@pytest.mark.parametrize("value", [10 ** 400, -(10 ** 400), float("inf"), float("nan"), 2e15, True],
                         ids=["huge-int", "huge-negative", "infinity", "nan", "beyond-range", "bool"])
def test_absurd_timestamps_fail_verification_instead_of_raising(tmp_path, value):
    ledger = make_ledger(tmp_path / "a.jsonl", events=2)
    lines = log_lines(ledger)
    event = json.loads(lines[0])
    event["ts"] = value
    rewrite_log(ledger, [json.dumps(event), *lines[1:]])
    result = ledger.verify()
    assert not result.ok and result.reason == "malformed event"


def test_an_absurd_checkpoint_timestamp_fails_verification_instead_of_raising(tmp_path):
    ledger = make_ledger(tmp_path / "a.jsonl")
    trust = ledger.export_trust()
    trust["checkpoint"]["ts"] = 10 ** 400
    result = ledger.verify(trust)
    assert not result.ok and "checkpoint" in result.reason
