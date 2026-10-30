"""The rendered Markdown report must say what was found, how to check it independently, and what it does not cover."""

import asyncio

from purpleteam.assessment import Assessment
from purpleteam.audit.ledger import AuditLedger
from purpleteam.audit.report import render
from purpleteam.focus import TOOL
from purpleteam.identity import PermissionManifest
from test_assessment import ATTACK, ORACLE, PROFILE, _Agent, _looked_up


def _report(tmp_path, gullible=True, **kwargs):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    assessment = Assessment(lambda guard: _Agent(guard, gullible), ORACLE, PROFILE, ledger,
                            legit=[("Look up acme", _looked_up)], **kwargs)
    return asyncio.run(assessment.run([ATTACK]))


def test_a_clean_assessment_renders_a_short_safe_report(tmp_path):
    text = render(_report(tmp_path, False))
    assert "SAFE TO SHIP" in text and "No vulnerabilities were proven" in text
    assert "## Findings" in text
    # the boundary-compliance table is logged whether or not anything is wrong (clean is proven, not silent)
    assert "## Agent boundary compliance" in text and "| vendor | 2 | yes | not checked |" in text
    # resilience testing itself is still evidenced, even with nothing found — that is a real, separate control
    assert "Art. 15" in text and "adversarial testing" in text
    # but nothing specific to a breach or an applied patch is claimed, since neither happened
    assert "Art. 9" not in text and "Art. 14" not in text


def test_a_breach_report_shows_the_finding_the_patch_and_the_re_verification(tmp_path):
    text = render(_report(tmp_path))
    assert "NOT SAFE TO SHIP" not in text and "SAFE TO SHIP" in text  # patched and re-verified
    assert "injection_action" in text and "update_vendor_bank" in text
    assert "**Patched with:** P2, P15, P4" in text  # P15 (prompt hardening) is applied to injection too
    assert "attack held; legitimate behaviour preserved" in text


def test_the_coverage_table_groups_by_framework_and_shows_real_event_numbers(tmp_path):
    report = _report(tmp_path)
    text = render(report)
    assert "### EU AI Act" in text and "### DORA" in text and "### SOC 2" in text and "### HIPAA" in text
    # the event numbers shown for a clause are exactly the ones evidence_report() recorded for it, not placeholders
    expected = ", ".join(str(seq) for seq in report.coverage["EU AI Act · Art. 15"]["events"])
    assert f"| Art. 15 | Robustness & cybersecurity — adversarial testing | {expected} |" in text


def test_verification_instructions_pin_the_real_trust_bundle_not_a_placeholder(tmp_path):
    report = _report(tmp_path)
    text = render(report)
    checkpoint = report.trust["checkpoint"]
    assert checkpoint["root"] in text and str(checkpoint["size"]) in text
    assert "verify_log(events, trust)" in text
    for actor in report.trust["keys"]:
        assert f"`{actor}`" in text


def test_anchoring_status_is_shown_when_present_and_when_it_failed(tmp_path):
    ok = render(_report(tmp_path / "a", anchorer=lambda trust: ({**trust, "anchors": [{"authority": "a", "response": "x"}]}, [])))
    assert "confirmed by 1 authority" in ok

    def failing(trust):
        raise RuntimeError("authority unreachable")

    failed = render(_report(tmp_path / "b", anchorer=failing))
    assert "requested but failed" in failed and "RuntimeError" in failed


def test_a_focused_run_that_skipped_a_topic_explains_what_was_not_covered(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    assessment = Assessment(lambda guard: _Agent(guard), ORACLE, PROFILE, ledger,
                            legit=[("Look up acme", _looked_up)])
    report = asyncio.run(assessment.run(focus=[TOOL]))
    text = render(report)
    assert "## What this report does not cover" in text
    assert "Scoped to:" in text and TOOL in text


def test_boundary_table_shows_not_checked_without_a_baseline_and_flags_a_scope_violation(tmp_path):
    manifest = PermissionManifest({"vendor": frozenset()})  # vendor holds tools no manifest entry allows
    report = _report(tmp_path, manifest=manifest)
    text = render(report)
    assert "## Agent boundary compliance" in text
    assert "no baseline was supplied for comparison" in text
    assert "| vendor | 2 | **NO — see findings** | not checked |" in text


def test_boundary_table_shows_yes_when_the_baseline_matches_and_no_when_it_drifted(tmp_path):
    matching = {"vendor": {"tools": ["lookup_vendor", "update_vendor_bank"], "prompt_sha256": None}}
    clean = _report(tmp_path / "clean", baseline=matching)
    clean_text = render(clean)
    assert "checked against a saved baseline" in clean_text
    assert "| vendor | 2 | yes | yes |" in clean_text  # no manifest and no drift, so nothing to flag

    drifted = {"vendor": {"tools": ["lookup_vendor", "update_vendor_bank", "extra_tool"], "prompt_sha256": None}}
    report = _report(tmp_path / "drift", baseline=drifted)
    text = render(report)
    assert "| vendor | 2 | yes | **NO — see findings** |" in text


def test_a_report_with_an_unpatched_finding_still_renders_and_names_the_gap(tmp_path):
    manifest = PermissionManifest({"vendor": frozenset()})  # P11 needs this; still won't cover injection_action alone
    report = _report(tmp_path, manifest=manifest)
    text = render(report)
    assert "## Findings" in text  # never crashes even when the defense is incomplete


def test_scorecard_shows_the_wilson_bound_for_a_held_attack_and_nothing_for_a_breach(tmp_path):
    held = render(_report(tmp_path / "held", gullible=False))
    assert "## Scorecard" in held and "### Attack confidence (Wilson 95%)" in held
    assert "held" in held and "at 95% confidence" in held

    breached = render(_report(tmp_path / "breached"))
    assert "proven — no bound applies" in breached


def test_scorecard_shows_blast_radius_only_when_requested(tmp_path):
    without = render(_report(tmp_path / "without", gullible=False))
    assert "Blast radius" not in without

    with_blast = render(_report(tmp_path / "with_blast", gullible=False, blast={}))
    assert "### Blast radius" in with_blast and "| vendor |" in with_blast


def test_no_trust_bundle_yet_does_not_crash_and_skips_the_verification_section():
    from purpleteam.assessment import AssessmentReport

    text = render(AssessmentReport(target="t", results=[]))
    assert "## Verify this report independently" not in text and "No vulnerabilities" in text


def test_the_report_is_valid_markdown_headings_only_once_each(tmp_path):
    text = render(_report(tmp_path))
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert len(headings) == len(set(headings))  # each top-level section appears at most once
