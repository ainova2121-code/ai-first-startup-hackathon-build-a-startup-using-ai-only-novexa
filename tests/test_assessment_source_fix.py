"""An assessment that edits the target's own source must reload it and re-test the edited code, and
a source-level finding is only resolved by a real edit -- never by a guard on tool "" ."""

import asyncio

from purpleteam.assessment import Assessment, AssessmentReport
from purpleteam.audit.ledger import AuditLedger
from purpleteam.codemods.catalog import CodemodCatalog
from purpleteam.codemods.restore import SourceSnapshots
from test_assessment import ORACLE, PROFILE, _Agent, _looked_up
from test_source_fix import FIXED, ORIGINAL, _complete, _Scanner


def _assessment(tmp_path, *, complete, reload_target=None):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "vendor.py").write_text(f"x = 1\n{ORIGINAL}\n", encoding="utf-8")
    reloads = []
    assessment = Assessment(
        lambda guard: _Agent(guard, gullible=False), ORACLE, PROFILE, AuditLedger(tmp_path / "audit.jsonl"),
        legit=[("Look up acme", _looked_up)], scanner=_Scanner(), repo=repo,
        codemod_catalog=CodemodCatalog(tmp_path / "catalog"), codemod_complete=complete,
        source_snapshots=SourceSnapshots(tmp_path / "snap.json"),
        reload_target=(lambda: reloads.append(True)) if reload_target else None)
    return assessment, repo, reloads


def _run(assessment):
    events = []
    report = asyncio.run(assessment.run(on_event=events.append))
    return report, events


def test_a_verified_source_fix_is_written_reloaded_and_re_tested(tmp_path):
    assessment, repo, reloads = _assessment(tmp_path, complete=_complete(FIXED), reload_target=True)
    report, events = _run(assessment)

    assert FIXED in (repo / "vendor.py").read_text()
    assert reloads == [True]  # the edited code was loaded before the replay
    types = [e["type"] for e in events]
    assert types.index("source_patch") < types.index("target_reloaded") < types.index("patch_applied")
    assert not any("source" in e for e in report.verification.errors)
    patch = next(e for e in events if e["type"] == "patch_applied")
    assert patch["source_changes"][0]["path"] == "repo/vendor.py" and patch["source_gaps"] == []


def test_a_source_edit_without_a_reload_is_never_safe_to_ship(tmp_path):
    assessment, _, _ = _assessment(tmp_path, complete=_complete(FIXED))
    report, _ = _run(assessment)
    assert not report.safe_to_ship
    assert any("could not reload" in e for e in report.verification.errors)


def test_an_unfixed_source_finding_is_a_gap_not_a_guard_on_tool_nothing(tmp_path):
    assessment, repo, _ = _assessment(tmp_path, complete=None, reload_target=True)
    report, events = _run(assessment)

    assert ORIGINAL in (repo / "vendor.py").read_text()
    assert "P8" not in report.defense.patch_ids  # no SQL firewall on tool "" claiming to fix a source line
    assert any("no verified source fix" in e for e in report.verification.errors)
    assert not report.safe_to_ship


def test_a_focused_run_that_skipped_a_topic_is_not_safe_to_ship():
    report = AssessmentReport("t", [], scope={"skipped": {"memory": "no memory tools"}}, chain_ok=True)
    report.results = [type("R", (), {"outcome": "held"})()]
    assert not report.safe_to_ship
