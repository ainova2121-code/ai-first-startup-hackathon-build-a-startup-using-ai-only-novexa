"""Compliance trend: repeated ``Assessment.run()`` calls on one ledger read back as a history."""

import asyncio

from purpleteam.adapter import Observation, ToolCall
from purpleteam.assessment import Assessment
from purpleteam.audit.ledger import AuditLedger
from purpleteam.audit.trend import render, runs
from purpleteam.oracle import Verdict
from test_assessment import ATTACK, ORACLE, PROFILE, _Agent, _looked_up


def _run(ledger, gullible=True, **kwargs):
    assessment = Assessment(lambda guard: _Agent(guard, gullible), ORACLE, PROFILE, ledger,
                            legit=[("Look up acme", _looked_up)], **kwargs)
    return asyncio.run(assessment.run([ATTACK]))


def test_a_single_clean_run_is_one_safe_record_with_no_baseline_checked(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    _run(ledger, gullible=False)

    (record,) = runs(ledger.events())
    assert record.seq == 0 and record.size == len(ledger.events())
    assert record.safe_to_ship and record.breach_kinds == frozenset() and not record.baseline_checked


def test_a_breach_run_records_its_finding_kind_and_the_patches_applied(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    report = _run(ledger)

    (record,) = runs(ledger.events())
    assert record.breach_kinds == {"injection_action"}
    assert record.safe_to_ship  # patched and re-verified, so still safe to ship overall
    assert set(report.defense.patch_ids) == set(record.patch_ids)


def test_two_runs_on_the_same_ledger_are_ordered_and_a_new_breach_kind_is_flagged(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    _run(ledger, gullible=False)
    _run(ledger, gullible=True)

    history = runs(ledger.events())
    assert [r.seq for r in history] == [0, 1]
    assert history[0].breach_kinds == frozenset() and history[1].breach_kinds == {"injection_action"}
    assert history[0].size < history[1].size

    text = render(history)
    assert "| 1 |" in text and "| 2 |" in text
    assert "**New since the previous run:** injection_action" in text


def test_render_marks_baseline_as_not_checked_when_none_was_supplied(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    _run(ledger, gullible=False)
    text = render(runs(ledger.events()))
    assert "not checked" in text


def test_render_of_empty_history_is_empty():
    assert render([]) == ""


def test_an_unpatched_finding_is_named_in_the_render_notes(tmp_path, monkeypatch):
    import purpleteam.patches.catalog as catalog_module

    monkeypatch.setitem(catalog_module.FINDING_PATCHES, "mystery_kind", ["P-does-not-exist"])

    class _Mystery:
        name = "fake"

        def reset(self) -> None:
            pass

        def send(self, request: str) -> Observation:
            return Observation("done", [ToolCall("vendor", "update_vendor_bank", {"bank_account": "US00ATTACKER0666"})])

    class _UnknownKindOracle:
        def judge(self, observation: Observation):
            for call in observation.tool_calls:
                if call.tool == "update_vendor_bank":
                    return Verdict(True, "breached", "mystery_kind", call.tool, call.agent)
            return Verdict(False, "no breach")

    ledger = AuditLedger(tmp_path / "audit.jsonl")
    assessment = Assessment(lambda guard: _Mystery(), _UnknownKindOracle(), PROFILE, ledger, legit=[])
    asyncio.run(assessment.run([ATTACK]))

    (record,) = runs(ledger.events())
    assert record.unpatched == ("mystery_kind",) and not record.safe_to_ship
    assert "**Run 1 had no patch for:** mystery_kind" in render([record])
