"""A static finding from reading the target's source goes through the same defend-and-verify
pipeline as a dynamic breach, is sealed into the ledger, and is clearly marked as static in the report."""

import asyncio
from pathlib import Path

from purpleteam.assessment import Assessment
from purpleteam.audit.ledger import AuditLedger
from purpleteam.audit.report import render
from purpleteam.sast import StaticFinding
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


def test_a_static_only_finding_is_patched_and_logged_even_with_no_breach(tmp_path):
    scanner = _FakeScanner([StaticFinding("sql_injection", "vendor.py", 12, "f-string SQL query")])
    ledger, report = _assess(tmp_path, scanner)

    assert [(f.kind, f.source) for f in report.findings] == [("sql_injection", "static")]
    assert "P8" in report.defense.patch_ids
    assert [e["kind"] for e in ledger.events()] == ["identity", "static", "patch", "verdict", "seal"]
    (scan_event,) = [e for e in ledger.events() if e["kind"] == "static"]
    assert scan_event["payload"]["findings"] == [{"kind": "sql_injection", "file": "vendor.py", "line": 12,
                                                  "severity": "medium"}]


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
