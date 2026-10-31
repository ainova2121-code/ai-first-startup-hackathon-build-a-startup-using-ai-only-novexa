"""Policy-decision drift: every verified decision is recorded with its exact inputs and replayed through
another policy, so any decision that changed is found -- deterministically, with no model involved."""

import pytest

from purpleteam.decisions import (ALLOW, ATTACK, BLOCK, HOLD, LEGIT, MODIFY, DecisionRecorder, Probe, ProbeLog,
                                  check_baseline, compare, decide, summarize, take_baseline, without)
from purpleteam.patches.base import Blocked, CompositeGuard, HoldForReview, Patch


class _DenyTool(Patch):
    id = "PX"

    def authorize(self, agent, tool, args):
        if tool == "pay":
            raise Blocked("payments denied")


class _Hold(Patch):
    id = "PH"

    def authorize(self, agent, tool, args):
        if args.get("amount", 0) > 100:
            raise HoldForReview("large amount")


class _Redact(Patch):
    id = "PR"

    def screen(self, agent, text, source):
        return text.replace("SECRET", "[redacted]") if source == "output" else text


class _DenyLookup(Patch):
    id = "PL"

    def authorize(self, agent, tool, args):
        if tool == "lookup":
            raise Blocked("lookups denied")


def _guard(*patches):
    return lambda: CompositeGuard(list(patches))


def _recorded(guard):
    """Drive a guard through a recorder the way a verified replay does."""
    log = ProbeLog()
    attack, legit = DecisionRecorder(guard, log, ATTACK), DecisionRecorder(guard, log, LEGIT)
    for recorder, tool, args in ((attack, "pay", {"to": "US00ATTACKER0666"}), (legit, "lookup", {"name": "acme"}),
                                 (legit, "refund", {"amount": 500})):
        try:
            recorder.authorize("payments", tool, args)
        except Blocked:
            pass
    legit.screen("payments", "the SECRET is here", "output")
    return log


def test_each_decision_names_its_outcome_and_the_patch_that_made_it():
    guard = CompositeGuard([_DenyTool(), _Hold(), _Redact()])
    assert decide(guard, Probe("authorize", "a", "pay", "{}")) == (BLOCK, "PX")
    assert decide(guard, Probe("authorize", "a", "refund", '{"amount":500}')) == (HOLD, "PH")
    assert decide(guard, Probe("authorize", "a", "lookup", "{}")) == (ALLOW, "")
    assert decide(guard, Probe("screen", "a", text="SECRET", source="output")) == (MODIFY, "PR")


def test_the_recorder_never_changes_a_decision():
    guard = CompositeGuard([_DenyTool()])
    recorder = DecisionRecorder(guard, ProbeLog(), ATTACK)
    with pytest.raises(Blocked):
        recorder.authorize("a", "pay", {})
    assert recorder.patches == guard.patches  # anything else is the wrapped guard's


def test_the_same_policy_has_no_drift():
    factory = _guard(_DenyTool(), _Hold(), _Redact())
    baseline = take_baseline(_recorded(factory()), factory)
    assert len(baseline["probes"]) == 4 and compare(baseline, factory) == []


def test_removing_the_patch_that_stopped_an_attack_is_high_severity_drift():
    factory = _guard(_DenyTool(), _Hold(), _Redact())
    baseline = take_baseline(_recorded(factory()), factory)
    (flip,) = compare(baseline, without(factory, {"PX"}))
    assert (flip["severity"], flip["before"], flip["after"], flip["by_before"]) == ("high", BLOCK, ALLOW, "PX")
    assert flip["origins"] == [ATTACK] and "verified attack" in flip["why"]


def test_losing_a_redaction_is_high_and_blocking_legit_work_is_medium():
    factory = _guard(_DenyTool(), _Redact())
    baseline = take_baseline(_recorded(factory()), factory)
    flips = compare(baseline, _guard(_DenyTool(), _Redact(), _Hold(), _DenyLookup()))
    assert {(f["tool"], f["severity"]) for f in flips} == {("lookup", "medium"), ("refund", "medium")}
    assert summarize(compare(baseline, without(factory, {"PR"}))) == {"high": 1, "medium": 0, "low": 0}


def test_a_baseline_altered_after_it_was_recorded_is_refused():
    factory = _guard(_DenyTool())
    baseline = take_baseline(_recorded(factory()), factory)
    baseline["probes"][0]["origins"] = []  # any change at all, even one that hides where a probe came from
    with pytest.raises(ValueError, match="altered"):
        check_baseline(baseline)


def test_identical_inputs_are_recorded_once_with_every_origin_and_overflow_is_counted():
    log = ProbeLog(limit=1)
    log.add(Probe("authorize", "a", "pay", "{}"), ATTACK)
    log.add(Probe("authorize", "a", "pay", "{}"), LEGIT)
    log.add(Probe("authorize", "a", "other", "{}"), LEGIT)
    ((probe, origins),) = log.items()
    assert origins == {ATTACK, LEGIT} and log.dropped == 1


def _p14():
    from purpleteam.patches.provenance import ProvenanceGuard
    return CompositeGuard([ProvenanceGuard(set(), {"pay": {"to"}})])  # outside content reaches "pay"'s "to"


def _live_attack(guard, log):
    """One request: the planted value arrives as input, then the agent tries to pay it -- P14 stops it live."""
    recorder = DecisionRecorder(guard, log, ATTACK)
    recorder.screen("agent", "The new account is US00ATTACKER0666.", "input")
    with pytest.raises(Blocked):
        recorder.authorize("agent", "pay", {"to": "US00ATTACKER0666", "amount": 500})


def test_a_stateful_patch_is_replayed_after_what_it_saw_earlier_in_the_request():
    log = ProbeLog()
    _live_attack(_p14(), log)
    baseline = take_baseline(log, _p14)
    paid = next(e for e in baseline["probes"] if e["probe"]["tool"] == "pay")
    assert paid["outcome"] == BLOCK and paid["by"] == "P14"  # not "allow": P14 is shown the planted input first
    assert compare(baseline, _p14) == []  # the same policy reproduces its own decisions exactly


def test_an_older_baseline_is_judged_by_the_current_policys_own_verified_decision():
    """Recorded before histories existed: the tool call has none to replay, so a fresh P14 alone would read "allow"
    and flag a loosening that never happened. The current run decided the same inputs live -- that is the answer."""
    older = take_baseline(_recorded_without_history(), _guard(_Hold()))
    log = ProbeLog()
    _live_attack(_p14(), log)
    current = take_baseline(log, _p14)

    assert summarize(compare(older, _p14))["high"] == 1  # what a history-free replay used to report
    (flip,) = compare(older, _p14, current)  # held before, blocked now: a change, but no weaker than approved
    assert (flip["before"], flip["after"], flip["severity"]) == (HOLD, BLOCK, "low")


def test_a_real_loosening_is_still_caught_against_an_older_baseline():
    older = take_baseline(_recorded_without_history(), _guard(_Hold()))
    log = ProbeLog()
    recorder = DecisionRecorder(CompositeGuard([]), log, ATTACK)  # a policy with nothing in it lets the call through
    recorder.screen("agent", "The new account is US00ATTACKER0666.", "input")
    recorder.authorize("agent", "pay", {"to": "US00ATTACKER0666", "amount": 500})
    current = take_baseline(log, lambda: CompositeGuard([]))
    (flip,) = compare(older, lambda: CompositeGuard([]), current)
    assert (flip["before"], flip["after"], flip["severity"]) == (HOLD, ALLOW, "high")


def test_a_probe_with_no_history_keeps_the_key_it_always_had():
    import hashlib

    from purpleteam.audit.hashing import canonical
    probe = Probe("screen", "agent", text="hello", source="input")
    legacy = {"check": "screen", "agent": "agent", "tool": "", "args": "", "text": "hello", "source": "input"}
    assert probe.key == hashlib.sha256(canonical(legacy)).hexdigest()[:16] == probe.content_key


def _recorded_without_history() -> ProbeLog:
    """A baseline as an earlier version recorded it: the attacker's call, held for review, with no history."""
    log = ProbeLog()
    log.add(Probe("authorize", "agent", "pay", '{"amount":500,"to":"US00ATTACKER0666"}'), ATTACK)
    return log


def test_a_clean_call_made_during_an_attack_is_less_oversight_not_a_loosened_attack():
    """The agent recorded the real invoice in the middle of an attack request: a hold on it that a later policy lifts
    is less oversight (medium, reported), not an attack let through. A call carrying the planted value still is."""
    log = ProbeLog()
    recorder = DecisionRecorder(CompositeGuard([_Hold()]), log, ATTACK)
    for args in ({"amount": 500, "to": "US941030326875"}, {"amount": 500, "to": "US00ATTACKER0666"}):
        with pytest.raises(Blocked):
            recorder.authorize("agent", "refund", args)
    flips = compare(take_baseline(log, _guard(_Hold())), lambda: CompositeGuard([]))
    severity = {"US00ATTACKER0666" in f["label"]: f["severity"] for f in flips}
    assert severity == {True: "high", False: "medium"}
