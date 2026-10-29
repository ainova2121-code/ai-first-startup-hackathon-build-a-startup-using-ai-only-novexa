"""A static finding from reading the target's source goes through the same defend-and-verify
pipeline as a dynamic breach, is sealed into the ledger, and is clearly marked as static in the report."""

import asyncio
from pathlib import Path

from purpleteam.assessment import Assessment
from purpleteam.audit.ledger import AuditLedger
from purpleteam.audit.report import render
from purpleteam.sast import ScanFailed, StaticFinding
from test_assessment import ORACLE, PROFILE, _Agent, _looked_up


class _FakeScanner:
    def __init__(self, findings):
        self._findings = findings

    def scan(self, repo: Path):
        return self._findings


def _assess(tmp_path, scanner, gullible=False):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    assessment = Assessment(lambda guard: _Agent(guard, gullible), ORACLE, PROFILE, ledger,
                            legit=[("Look up acme", _looked_up)], scanner=scanner, repo=tmp_path)
    return ledger, asyncio.run(assessment.run([]))


def test_a_static_only_finding_is_logged_and_left_as_a_gap_without_a_source_fix(tmp_path):
    """A source-level finding names a line, not a tool: a SQL firewall on tool "" would guard nothing
    while reading as "patched". Without a verified source edit it stays an explicit, blocking gap."""
    scanner = _FakeScanner([StaticFinding("sql_injection", "vendor.py", 12, "f-string SQL query")])
    ledger, report = _assess(tmp_path, scanner)

    assert [(f.kind, f.source) for f in report.findings] == [("sql_injection", "static")]
    assert "P8" not in report.defense.patch_ids
    assert any("vendor.py:12: no verified source fix" in e for e in report.verification.errors)
    assert not report.safe_to_ship
    assert [e["kind"] for e in ledger.events()] == ["identity", "static", "scope", "patch", "decision_baseline",
                                                    "verdict", "seal"]
    (scan_event,) = [e for e in ledger.events() if e["kind"] == "static"]
    assert scan_event["payload"]["findings"] == [{"kind": "sql_injection", "file": "vendor.py", "line": 12,
                                                  "severity": "medium"}]


def test_a_scan_that_fails_is_a_coverage_gap_never_a_clean_result(tmp_path):
    class _Broken:
        def scan(self, repo):
            raise ScanFailed("bandit is not installed")

    ledger, report = _assess(tmp_path, _Broken())
    assert report.coverage_gaps == ["the static scan did not complete: bandit is not installed"]
    assert not report.safe_to_ship
    (scan_event,) = [e for e in ledger.events() if e["kind"] == "static"]
    assert scan_event["payload"]["gaps"] == report.coverage_gaps


def test_source_in_a_language_the_scanner_cannot_read_is_reported_as_unchecked(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "ui.ts").write_text("export const x = 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("module.exports = 1\n")  # a dependency, not the project's
    scanner = _FakeScanner([])
    scanner.languages = frozenset({".py"})

    _, report = _assess(tmp_path, scanner)
    assert report.coverage_gaps == ["source no configured scanner reads was not statically checked (1 .ts files)"]


def test_a_low_severity_unmapped_finding_is_advisory_not_blocking(tmp_path):
    scanner = _FakeScanner([StaticFinding("bandit:B101", "vendor.py", 3, "assert used", "low")])
    ledger, report = _assess(tmp_path, scanner)
    (patch,) = [e for e in ledger.events() if e["kind"] == "patch"]
    assert patch["payload"]["source_gaps"] == []
    assert patch["payload"]["advisories"] == [f"bandit:B101 at {tmp_path.name}/vendor.py:3 (low severity, advisory)"]
    assert not any("vendor.py:3" in e for e in report.verification.errors)


def test_no_scanner_configured_logs_nothing_extra(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    assessment = Assessment(lambda guard: _Agent(guard, False), ORACLE, PROFILE, ledger,
                            legit=[("Look up acme", _looked_up)])
    report = asyncio.run(assessment.run([]))
    assert report.findings == [] and "static" not in [e["kind"] for e in ledger.events()]


def test_the_report_marks_a_static_finding_distinctly_and_notes_it_was_not_re_exploited(tmp_path):
    scanner = _FakeScanner([StaticFinding("sql_injection", "vendor.py", 12, "f-string SQL query")])
    _, report = _assess(tmp_path, scanner)
    text = render(report)

    assert "found by reading the source" in text
    assert "vendor.py:12" in text
    assert "no working payload exists to replay" in text
    assert "were not dynamically re-exploited after patching" in text


def test_a_clean_scan_is_still_logged_and_adds_no_finding(tmp_path):
    ledger, report = _assess(tmp_path, _FakeScanner([]))
    assert report.findings == []
    (scan_event,) = [e for e in ledger.events() if e["kind"] == "static"]
    assert scan_event["payload"]["findings"] == []
