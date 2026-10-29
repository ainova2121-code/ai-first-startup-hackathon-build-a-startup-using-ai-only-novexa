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
    for recorder, tool, args in ((attack, "pay", {"to": "attacker"}), (legit, "lookup", {"name": "acme"}),
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
