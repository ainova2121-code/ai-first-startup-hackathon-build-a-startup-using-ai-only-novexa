"""The ledger's verification, shown step by step: it must agree with ``verify_log`` (the authority) on every
log, honest or tampered, and name exactly which check failed on which event."""

import json

from purpleteam.audit.explain import explain_log
from purpleteam.audit.hashing import merkle_root
from purpleteam.audit.ledger import AuditLedger
from purpleteam.audit.verify import verify_log


def _sealed(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("attacker", "attack", {"id": "probe"})
    ledger.append("oracle", "breach", {"tool": "pay"})
    ledger.append("attacker", "attack", {"id": "second"})
    ledger.append("audit", "seal", {"merkle_root": ledger.seal()})
    return ledger.events(), ledger.export_trust()


def _failed(explained):
    return {(e["seq"], c["check"]) for e in explained["events"] for c in e["checks"] if c["ok"] is False}


def test_an_honest_log_passes_every_step_and_the_tree_rebuilds_the_signed_root(tmp_path):
    events, trust = _sealed(tmp_path)
    explained = explain_log(events, trust)
    assert verify_log(events, trust).ok and _failed(explained) == set()
    assert all(c["ok"] for c in explained["checkpoint"]["checks"])
    assert explained["tree"]["hash"] == trust["checkpoint"]["root"] == merkle_root([e["hash"] for e in events])
    second_attack = explained["events"][2]
    assert second_attack["prev_seq"] == 0 and second_attack["prev"] == events[0]["hash"]  # the attacker's own chain
    assert {c["check"] for c in second_attack["checks"]} >= {"Ed25519 signature", "ML-DSA-65 signature"}


def test_a_tampered_event_is_named_and_the_checkpoint_shows_the_rewrite(tmp_path):
    events, trust = _sealed(tmp_path)
    events[1] = {**events[1], "payload": {"tool": "something else"}}
    assert not verify_log(events, trust).ok
    assert _failed(explain_log(events, trust)) == {(1, "content hash")}  # exactly the event that was altered


def test_a_forged_signature_fails_only_the_signature_checks(tmp_path):
    events, trust = _sealed(tmp_path)
    events[2] = {**events[2], "sig": "0" * 128}
    assert not verify_log(events, trust).ok
    assert _failed(explain_log(events, trust)) == {(2, "Ed25519 signature")}


def test_a_run_explains_its_sealed_ledger(tmp_path):
    from purpleteam.run_history import RunStore

    run = RunStore(tmp_path / "runs").new()
    assert run.explain() is None  # nothing to verify against before it is sealed
    ledger = AuditLedger(run.ledger_path)
    ledger.append("attacker", "attack", {"id": "probe"})
    run.write_trust(ledger.export_trust())
    assert json.dumps(run.explain())  # plain JSON for the page


def test_a_timestamp_token_is_shown_verified_only_when_it_actually_verifies(tmp_path):
    events, trust = _sealed(tmp_path)
    assert explain_log(events, trust)["anchors"] == []  # none attached: nothing to show as verified
    forged = {**trust, "anchors": [{"authority": "freetsa", "response": "bm90IGEgdG9rZW4="}]}
    (anchor,) = explain_log(events, forged, {})["anchors"]
    assert anchor["ok"] is False and anchor["time"] is None and anchor["detail"]


def test_a_live_run_shows_each_signature_as_it_happens_and_verifies_it_before_the_seal(tmp_path):
    """Mid-run, every signed event is announced the moment it is on disk and already verifies against its signer's
    public key; there is no checkpoint until the run is sealed, and a half-written last record is not read."""
    from purpleteam.run_history import RunStore

    run = RunStore(tmp_path / "runs").new()
    announced = []
    ledger = AuditLedger(run.ledger_path, on_append=announced.append)
    ledger.append("attacker", "attack", {"id": "probe"})
    ledger.append("oracle", "breach", {"tool": "pay"})
    assert [e["seq"] for e in announced] == [0, 1]
    run.write_json("keys", ledger.public_keys())
    with run.ledger_path.open("a", encoding="utf-8") as log:
        log.write('{"seq": 2, "actor"')  # the next record, still being written
    live = run.explain()
    assert live["sealed"] is False and live["checkpoint"] is None and len(live["events"]) == 2
    assert _failed(live) == set() and live["tree"]["hash"] == merkle_root([e["hash"] for e in announced])
