"""Human oversight: a held action proceeds only after a person approves it."""

import pytest

from purpleteam.audit.ledger import AuditLedger
from purpleteam.oversight import HumanReviewGate, ReviewQueue
from purpleteam.patches.base import Blocked

ARGS = {"vendor_id": 4, "bank_account": "US00ATTACKER0666"}


def _gate(tmp_path, ledger=None):
    queue = ReviewQueue(tmp_path / "queue.json", ledger=ledger)
    return HumanReviewGate({"update_vendor_bank"}, queue), queue


def test_first_attempt_is_held_for_review(tmp_path):
    gate, queue = _gate(tmp_path)
    with pytest.raises(Blocked):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    assert len(queue.pending()) == 1


def test_approved_action_then_proceeds(tmp_path):
    gate, queue = _gate(tmp_path)
    with pytest.raises(Blocked):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    queue.approve(queue.pending()[0].id, by="finance-ops")
    gate.authorize("vendor", "update_vendor_bank", ARGS)  # no longer raises


def test_rejected_action_stays_blocked(tmp_path):
    gate, queue = _gate(tmp_path)
    with pytest.raises(Blocked):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    queue.reject(queue.pending()[0].id, by="finance-ops", reason="not a real vendor change")
    with pytest.raises(Blocked):
        gate.authorize("vendor", "update_vendor_bank", ARGS)


def test_safe_tool_is_not_held(tmp_path):
    gate, _ = _gate(tmp_path)
    gate.authorize("vendor", "lookup_vendor", {"name": "WDTV"})  # not a gated tool


def test_decisions_are_recorded_in_the_audit_ledger(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    gate, queue = _gate(tmp_path, ledger=ledger)
    with pytest.raises(Blocked):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    queue.approve(queue.pending()[0].id, by="finance-ops")
    kinds = [e["kind"] for e in ledger.events()]
    assert kinds.count("review") == 2  # the hold and the approval
    assert ledger.verify().ok
