"""Human oversight: a held action proceeds only after a person approves it -- once, for the agent
and exact call it was approved for, before it goes stale."""

import pytest

from purpleteam.audit.ledger import AuditLedger
from purpleteam.oversight import HumanReviewGate, ReviewQueue
from purpleteam.patches.base import Blocked, HoldForReview

ARGS = {"vendor_id": 4, "bank_account": "US00ATTACKER0666"}


def _gate(tmp_path, ledger=None, **queue_kwargs):
    queue = ReviewQueue(tmp_path / "queue.json", ledger=ledger, **queue_kwargs)
    return HumanReviewGate({("vendor", "update_vendor_bank")}, queue), queue


def test_first_attempt_is_held_for_review(tmp_path):
    gate, queue = _gate(tmp_path)
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    assert len(queue.pending()) == 1


def test_approved_action_then_proceeds(tmp_path):
    gate, queue = _gate(tmp_path)
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    queue.approve(queue.pending()[0].id, by="finance-ops")
    gate.authorize("vendor", "update_vendor_bank", ARGS)  # no longer raises


def test_an_approval_is_spent_after_one_use(tmp_path):
    """The real point of consume(): approving one transfer must never stand as a blanket pass for
    a later, identical-looking call."""
    gate, queue = _gate(tmp_path)
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    queue.approve(queue.pending()[0].id, by="finance-ops")
    gate.authorize("vendor", "update_vendor_bank", ARGS)  # spends the approval
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)  # a second call needs its own approval


def test_rejected_action_stays_blocked(tmp_path):
    gate, queue = _gate(tmp_path)
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    queue.reject(queue.pending()[0].id, by="finance-ops", reason="not a real vendor change")
    with pytest.raises(Blocked):
        gate.authorize("vendor", "update_vendor_bank", ARGS)


def test_safe_tool_is_not_held(tmp_path):
    gate, _ = _gate(tmp_path)
    gate.authorize("vendor", "lookup_vendor", {"name": "WDTV"})  # not a gated tool


def test_a_different_agent_calling_the_same_named_tool_is_not_gated_by_this_scope(tmp_path):
    """The exact bug this fixes: one agent's finding must never hold a different agent's call to
    a tool that merely happens to share the same name."""
    gate, _ = _gate(tmp_path)
    gate.authorize("other-agent", "update_vendor_bank", ARGS)  # not in scope, never held


def test_an_approval_for_one_agent_does_not_cover_another_agents_identical_call(tmp_path):
    queue = ReviewQueue(tmp_path / "queue.json")
    gate = HumanReviewGate({("vendor", "update_vendor_bank"), ("other-agent", "update_vendor_bank")}, queue)
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    queue.approve(queue.pending()[0].id, by="finance-ops")
    gate.authorize("vendor", "update_vendor_bank", ARGS)  # vendor's own approval works
    with pytest.raises(HoldForReview):
        gate.authorize("other-agent", "update_vendor_bank", ARGS)  # a different agent, still unapproved


def test_decisions_are_recorded_in_the_audit_ledger(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    gate, queue = _gate(tmp_path, ledger=ledger)
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    queue.approve(queue.pending()[0].id, by="finance-ops")
    kinds = [e["kind"] for e in ledger.events()]
    assert kinds.count("review") == 2  # the hold and the approval
    assert ledger.verify().ok


# -- expiry: a stale hold or a stale, never-used approval is not a standing pass ------------------

class _Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def test_an_unresolved_hold_expires_and_a_retry_opens_a_fresh_one(tmp_path):
    clock = _Clock()
    queue = ReviewQueue(tmp_path / "queue.json", ttl_seconds=60, clock=clock)
    gate = HumanReviewGate({("vendor", "update_vendor_bank")}, queue)
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    clock.now += 61
    assert queue.decision("vendor", "update_vendor_bank", ARGS) is None
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)  # a fresh hold, not the stale one


def test_an_approval_not_used_before_it_expires_is_no_longer_honoured(tmp_path):
    clock = _Clock()
    queue = ReviewQueue(tmp_path / "queue.json", ttl_seconds=60, clock=clock)
    gate = HumanReviewGate({("vendor", "update_vendor_bank")}, queue)
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    queue.approve(queue.pending()[0].id, by="finance-ops")
    clock.now += 61
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)  # the approval went stale before it was used


# -- reviewer authorization: only a named reviewer may decide ------------------------------------

def test_an_unauthorized_reviewer_cannot_approve_or_reject(tmp_path):
    gate, queue = _gate(tmp_path, authorized_reviewers={"finance-ops"})
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    item_id = queue.pending()[0].id
    with pytest.raises(PermissionError):
        queue.approve(item_id, by="random-person")
    with pytest.raises(PermissionError):
        queue.reject(item_id, by="random-person")
    queue.approve(item_id, by="finance-ops")  # the authorized name still works


# -- redaction: sensitive argument values are never written to disk in the clear -----------------

def test_sensitive_arguments_are_redacted_before_they_touch_disk(tmp_path):
    from purpleteam.audit.privacy import Redactor

    path = tmp_path / "queue.json"
    queue = ReviewQueue(path, redactor=Redactor(b"a long random owner-kept secret"))
    gate = HumanReviewGate({("vendor", "update_vendor_bank")}, queue)
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    on_disk = path.read_text()
    assert ARGS["bank_account"] not in on_disk
    # the live hold a reviewer actually sees still carries the real value to decide on
    assert queue.pending()[0].args["bank_account"] != ARGS["bank_account"]  # redacted in-process too, same discipline


# -- persistence: a hold/approval made before a restart is still honoured after one --------------

def test_a_held_item_survives_a_restart_and_can_still_be_approved(tmp_path):
    path = tmp_path / "queue.json"
    first = ReviewQueue(path)
    HumanReviewGate({("vendor", "update_vendor_bank")}, first)
    try:
        first.hold("vendor", "update_vendor_bank", ARGS, "needs review")
    except Exception:
        pass
    item_id = first.pending()[0].id

    second = ReviewQueue(path)  # a fresh process, same file: a "restart"
    second.approve(item_id, by="finance-ops")
    gate = HumanReviewGate({("vendor", "update_vendor_bank")}, second)
    gate.authorize("vendor", "update_vendor_bank", ARGS)  # no longer raises


def test_an_ephemeral_queue_without_a_path_works_but_writes_nothing_to_disk(tmp_path):
    queue = ReviewQueue()  # path=None
    gate = HumanReviewGate({("vendor", "update_vendor_bank")}, queue)
    with pytest.raises(HoldForReview):
        gate.authorize("vendor", "update_vendor_bank", ARGS)
    assert list(tmp_path.iterdir()) == []


def test_a_held_call_tells_the_agent_it_is_final_so_it_stops_retrying():
    from purpleteam.targets.ledgerpilot import _RecordingSink
    sink = _RecordingSink()
    message = sink.hold_for_review("inquiry", "query_ledger", {"sql": "SELECT 1"}, "needs review")
    assert "will not run until a person approves it" in message and "Do not retry" in message
    assert sink.pending_reviews == [{"agent": "inquiry", "tool": "query_ledger", "args": {"sql": "SELECT 1"},
                                     "reason": "needs review"}]
