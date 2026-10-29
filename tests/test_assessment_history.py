"""What earlier runs bind a new one to: proven exploits are replayed as regressions, and approved decisions may not loosen."""

import asyncio

import pytest

from purpleteam.assessment import Assessment
from purpleteam.audit.ledger import AuditLedger
from test_assessment import ATTACK, ORACLE, PROFILE, _Agent, _assess, _looked_up


def test_a_breach_is_recorded_as_a_regression_case(tmp_path):
    regressions = tmp_path / "regressions.json"
    ledger, report = _assess(tmp_path, [("Look up acme", _looked_up)], regressions=regressions)
    assert report.findings and regressions.exists()
    from purpleteam.attack.regressions import load_regressions
    (case,) = load_regressions(regressions)
    assert (case.kind, case.tool, case.agent) == ("injection_action", "update_vendor_bank", "vendor")


def test_a_regression_case_is_replayed_on_a_later_run_that_attacks_nothing_new(tmp_path):
    """The whole point: a later run that finds nothing new must still rebuild the old patch and
    re-prove the old exploit is still blocked — not silently stop checking it."""
    regressions = tmp_path / "regressions.json"
    ledger1 = AuditLedger(tmp_path / "audit1.jsonl")
    first = Assessment(lambda guard: _Agent(guard, gullible=True), ORACLE, PROFILE, ledger1,
                       legit=[("Look up acme", _looked_up)], regressions=regressions)
    report1 = asyncio.run(first.run([ATTACK]))
    assert report1.findings

    ledger2 = AuditLedger(tmp_path / "audit2.jsonl")
    second = Assessment(lambda guard: _Agent(guard, gullible=True), ORACLE, PROFILE, ledger2,
                        legit=[("Look up acme", _looked_up)], regressions=regressions)
    report2 = asyncio.run(second.run([]))  # this run's own corpus attacks nothing

    assert report2.results == []  # nothing new was attacked
    assert [(f.kind, f.tool) for f in report2.findings] == [("injection_action", "update_vendor_bank")]
    assert "P4" in report2.defense.patch_ids  # the defender rebuilt the same patch from the regression alone
    assert report2.verification.attack_blocked  # and the old exploit is confirmed still blocked


def test_a_regression_that_no_longer_reproduces_is_not_reported_as_an_active_breach(tmp_path):
    """The fix for a real bug: a regression case must be re-tested against the current target,
    never assumed true just because it was proven once before."""
    regressions = tmp_path / "regressions.json"
    ledger1 = AuditLedger(tmp_path / "audit1.jsonl")
    first = Assessment(lambda guard: _Agent(guard, gullible=True), ORACLE, PROFILE, ledger1,
                       legit=[("Look up acme", _looked_up)], regressions=regressions)
    asyncio.run(first.run([ATTACK]))

    ledger2 = AuditLedger(tmp_path / "audit2.jsonl")
    second = Assessment(lambda guard: _Agent(guard, gullible=False), ORACLE, PROFILE, ledger2,
                        legit=[("Look up acme", _looked_up)], regressions=regressions)
    report2 = asyncio.run(second.run([]))  # nothing new attacked, and the old exploit no longer works

    assert report2.results == [] and report2.findings == [] and report2.defense is None
    (retest_event,) = [e for e in ledger2.events() if e["kind"] == "regressions_retested"]
    assert retest_event["payload"]["results"][0]["reproduced"] is False


def _approved_decisions(tmp_path):
    first = Assessment(lambda guard: _Agent(guard, gullible=True), ORACLE, PROFILE, AuditLedger(tmp_path / "a1.jsonl"),
                       legit=[("Look up acme", _looked_up)])
    report = asyncio.run(first.run([ATTACK]))
    assert report.safe_to_ship and report.decisions["probes"]
    return report.decisions


def test_the_same_defense_rebuilt_later_shows_no_decision_drift(tmp_path):
    baseline = _approved_decisions(tmp_path)
    ledger = AuditLedger(tmp_path / "a2.jsonl")
    again = Assessment(lambda guard: _Agent(guard, gullible=True), ORACLE, PROFILE, ledger,
                       legit=[("Look up acme", _looked_up)], decision_baseline=baseline)
    report = asyncio.run(again.run([ATTACK]))
    assert report.decision_drift == [] and report.safe_to_ship
    (drift,) = [e for e in ledger.events() if e["kind"] == "decision_drift"]
    assert drift["payload"]["high"] == 0 and drift["payload"]["against"] == baseline["digest"]


def test_a_later_run_that_finds_nothing_still_may_not_drop_a_decision_that_stopped_an_attack(tmp_path):
    """The model happened not to fall for the attack this time, so no defense was built -- yet the approved
    policy blocked that exact attack's tool call. Shipping with no guard would silently re-open it."""
    baseline = _approved_decisions(tmp_path)
    ledger = AuditLedger(tmp_path / "a2.jsonl")
    later = Assessment(lambda guard: _Agent(guard, gullible=False), ORACLE, PROFILE, ledger,
                       legit=[("Look up acme", _looked_up)], decision_baseline=baseline)
    report = asyncio.run(later.run([ATTACK]))

    assert report.findings == [] and report.defense is None
    high = [f for f in report.decision_drift if f["severity"] == "high"]
    assert high and high[0]["tool"] == "update_vendor_bank" and high[0]["after"] == "allow"
    assert not report.safe_to_ship
    (drift,) = [e for e in ledger.events() if e["kind"] == "decision_drift"]
    assert "label" not in drift["payload"]["flips"][0]  # the ledger holds keys and outcomes, never the inputs


def test_a_tampered_decision_baseline_is_refused_before_anything_runs(tmp_path):
    baseline = _approved_decisions(tmp_path)
    baseline["probes"].pop()
    with pytest.raises(ValueError, match="altered"):
        Assessment(lambda guard: _Agent(guard), ORACLE, PROFILE, AuditLedger(tmp_path / "a2.jsonl"),
                   legit=[("Look up acme", _looked_up)], decision_baseline=baseline)


def test_a_regression_already_recorded_is_not_duplicated_when_rediscovered(tmp_path):
    regressions = tmp_path / "regressions.json"
    _assess(tmp_path / "run1", [("Look up acme", _looked_up)], regressions=regressions)
    _assess(tmp_path / "run2", [("Look up acme", _looked_up)], regressions=regressions)
    from purpleteam.attack.regressions import load_regressions
    assert len(load_regressions(regressions)) == 1


def test_without_regressions_configured_behaviour_is_unchanged(tmp_path):
    ledger, report = _assess(tmp_path, [("Look up acme", _looked_up)])
    assert report.safe_to_ship and not (tmp_path / "regressions.json").exists()
