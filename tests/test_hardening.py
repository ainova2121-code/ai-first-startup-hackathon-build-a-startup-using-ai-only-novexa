"""Prompt / tool-description hardening: the scanner flags an unhardened agent prompt or dangerous-tool
description, and the deterministic codemod appends a fixed clause, proven by the same rescan + invariant
as every other source fix. The clause is added once and is reversible like all the rest."""

import ast

from purpleteam.codemods.context import source_statement
from purpleteam.codemods.hardening import hardening_candidate
from purpleteam.codemods.verify import verify
from purpleteam.hardening_scan import MARKER_TAG, CompositeScanner, PromptHardeningScanner
from purpleteam.sast import BanditScanner

PROMPT_TEXT = "You are the intake clerk. Read the email and record the invoice."
TOOL_TEXT = "Find vendors whose name contains the given text."
SOURCE = f'''INTAKE_PROMPT = """{PROMPT_TEXT}"""


def lookup_vendor(name):
    """{TOOL_TEXT}"""
    return []
'''


def _target(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "mod.py").write_text(SOURCE, encoding="utf-8")
    scanner = CompositeScanner([BanditScanner(), PromptHardeningScanner({"intake": PROMPT_TEXT},
                                                                        {"lookup_vendor": TOOL_TEXT})])
    return repo, scanner


def test_scanner_flags_the_discovered_prompt_and_tool_description(tmp_path):
    repo, scanner = _target(tmp_path)
    found = {f.kind: f.subject for f in scanner.scan(repo) if f.kind.startswith("unhardened")}
    assert found == {"unhardened_prompt": "intake", "unhardened_tool": "lookup_vendor"}


def test_hardening_codemod_is_verified_and_bakes_the_clause_into_the_value(tmp_path):
    repo, scanner = _target(tmp_path)
    path = repo / "mod.py"
    for finding in [f for f in scanner.scan(repo) if f.kind.startswith("unhardened")]:
        original = source_statement(path, finding.line)
        candidate = hardening_candidate(finding, original)
        verified = verify(candidate, finding, path, scanner)
        assert "invariant" in verified.verified_by  # proven independently, not by a re-scan alone
        text = path.read_text(encoding="utf-8")
        at = text.index(candidate.original)
        path.write_text(text[:at] + candidate.replacement + text[at + len(candidate.original):], encoding="utf-8")

    # The file still parses, the scanner no longer flags anything, and the runtime values carry the marker.
    namespace: dict = {}
    exec(compile(path.read_text(encoding="utf-8"), "mod", "exec"), namespace)  # noqa: S102 - test fixture only
    assert [f for f in scanner.scan(repo) if f.kind.startswith("unhardened")] == []
    assert MARKER_TAG in namespace["INTAKE_PROMPT"]
    assert MARKER_TAG in namespace["lookup_vendor"].__doc__


def test_already_hardened_text_is_not_flagged_again(tmp_path):
    repo, scanner = _target(tmp_path)
    path = repo / "mod.py"
    finding = next(f for f in scanner.scan(repo) if f.kind == "unhardened_prompt")
    candidate = hardening_candidate(finding, source_statement(path, finding.line))
    text = path.read_text(encoding="utf-8")
    at = text.index(candidate.original)
    path.write_text(text[:at] + candidate.replacement + text[at + len(candidate.original):], encoding="utf-8")
    assert not any(f.kind == "unhardened_prompt" for f in scanner.scan(repo))


def test_no_candidate_when_the_statement_does_not_end_in_a_string(tmp_path):
    from purpleteam.sast import StaticFinding
    finding = StaticFinding("unhardened_prompt", "mod.py", 1, "x", "low", "a")
    assert hardening_candidate(finding, "value = compute(42)") is None
