"""The CI gate fails on a new breach, passes when all attacks held, and honors waivers."""

import asyncio
import io
from contextlib import redirect_stdout

from purpleteam.attack.corpus import CorpusResult
from purpleteam.audit.ledger import AuditLedger
from purpleteam.ci import evaluate, report, run_gate
from purpleteam.oracle import CANARY_ACCOUNT, CanaryOracle
from test_assessment import ATTACK, PROFILE, _Agent

ORACLE = CanaryOracle({CANARY_ACCOUNT}, PROFILE.dangerous_tools)


def _result(id: str, breached: bool, kind: str = "") -> CorpusResult:
    return CorpusResult(id, "jailbreak", breached, "breached" if breached else "held", kind=kind)


def test_gate_fails_on_a_breach():
    gate = evaluate([_result("dan_1", True), _result("aim", False)], waived=set())
    assert not gate.passed
    assert [r.id for r in gate.breaches] == ["dan_1"]


def test_gate_passes_when_all_held():
    gate = evaluate([_result("dan_1", False), _result("aim", False)], waived=set())
    assert gate.passed and gate.breaches == []


def test_gate_fails_on_an_empty_run_instead_of_passing_vacuously():
    gate = evaluate([], waived=set())
    assert not gate.passed


def test_gate_fails_when_an_attack_never_completed_even_with_no_breach():
    inconclusive = CorpusResult("dan_1", "jailbreak", False, "not tested: timed out", outcome="inconclusive")
    gate = evaluate([inconclusive, _result("aim", False)], waived=set())
    assert not gate.passed
    assert [r.id for r in gate.inconclusive] == ["dan_1"]


def test_a_waived_inconclusive_attack_does_not_fail_the_gate():
    inconclusive = CorpusResult("dan_1", "jailbreak", False, "not tested: timed out", outcome="inconclusive")
    gate = evaluate([inconclusive, _result("aim", False)], waived={"dan_1"})
    assert gate.passed


def test_waiver_does_not_fail_the_gate():
    gate = evaluate([_result("dan_1", True)], waived={"dan_1"})
    assert gate.passed


def test_run_gate_with_a_ledger_seals_one_run_and_records_the_breach_kind(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    gate = asyncio.run(run_gate(_Agent(), ORACLE, templates=[ATTACK], ledger=ledger))

    assert not gate.passed
    assert [e["kind"] for e in ledger.events()] == ["attack", "breach", "seal"]
    (breach,) = [e for e in ledger.events() if e["kind"] == "breach"]
    assert breach["payload"]["kind"] == "injection_action"


def test_report_prints_the_trend_across_runs_when_a_ledger_is_given(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    asyncio.run(run_gate(_Agent(), ORACLE, templates=[ATTACK], ledger=ledger))  # run 1: breached
    gate = asyncio.run(run_gate(_Agent(gullible=False), ORACLE, templates=[ATTACK], ledger=ledger))  # run 2: clean

    out = io.StringIO()
    with redirect_stdout(out):
        report(gate, ledger)
    text = out.getvalue()
    assert "## Compliance trend" in text and "| 1 |" in text and "| 2 |" in text


def test_report_without_a_ledger_omits_the_trend_section():
    out = io.StringIO()
    with redirect_stdout(out):
        report(evaluate([_result("dan_1", False)], waived=set()))
    assert "Compliance trend" not in out.getvalue()


def build_gate_target():
    """A customer's own factory, as ``--target test_ci:build_gate_target`` would name it."""
    return _Agent(), PROFILE


def not_a_gate_target():
    return "not (target, profile)"


def test_the_gate_takes_any_target_through_a_factory_in_the_customers_own_code():
    import pytest

    from purpleteam.ci import load_target
    target, profile = load_target("test_ci:build_gate_target")
    assert isinstance(target, _Agent) and profile is PROFILE
    for bad in ("no-colon", ":factory", "test_ci:"):
        with pytest.raises(ValueError, match="package.module:factory"):
            load_target(bad)
    with pytest.raises(ValueError, match="must return"):
        load_target("test_ci:not_a_gate_target")  # a factory returning anything else is refused, not used
