"""propose(): reuse an approved codemod without touching the model or the scanner; otherwise
draft and verify once, never auto-approving — a human still has to call catalog.approve()."""

import asyncio
import json

from purpleteam.codemods.catalog import CodemodCatalog, pattern_key
from purpleteam.codemods.propose import propose
from purpleteam.sast import StaticFinding

ORIGINAL = "cursor.execute(f'SELECT * FROM t WHERE id={x}')"
FIXED = "cursor.execute('SELECT * FROM t WHERE id=?', (x,))"
FINDING = StaticFinding("sql_injection", "vendor.py", 1, "string-built SQL query")


class _ScriptedScanner:
    def __init__(self, by_text):
        self._by_text = by_text
        self.scan_calls = 0

    def scan(self, repo):
        self.scan_calls += 1
        (file_path,) = list(repo.iterdir())
        text = file_path.read_text(encoding="utf-8")
        return [StaticFinding(kind, file_path.name, line, "scripted") for kind, line in self._by_text.get(text, [])]


def _complete(reply=None, *, fails=False):
    async def fake(system_prompt, user_content):
        fake.calls += 1
        if fails:
            return "not json"
        return reply
    fake.calls = 0
    return fake


def _file(tmp_path, text=ORIGINAL):
    path = tmp_path / "vendor.py"
    path.write_text(text, encoding="utf-8")
    return path


def test_an_approved_pattern_is_reused_without_calling_the_model_or_the_scanner(tmp_path):
    path = _file(tmp_path)
    catalog = CodemodCatalog(tmp_path / "catalog")
    from purpleteam.codemods.base import VerifiedCodemod
    cached = VerifiedCodemod("sql_injection", ORIGINAL, FIXED, "already proven")
    catalog.approve(pattern_key(FINDING.kind, ORIGINAL), cached)

    scanner = _ScriptedScanner({})
    complete = _complete()
    result = asyncio.run(propose(FINDING, path, scanner, catalog, complete=complete))

    assert result == cached and complete.calls == 0 and scanner.scan_calls == 0


def test_a_new_pattern_is_drafted_and_verified_but_not_auto_approved(tmp_path):
    path = _file(tmp_path)
    catalog = CodemodCatalog(tmp_path / "catalog")
    scanner = _ScriptedScanner({ORIGINAL: [("sql_injection", 1)], FIXED: []})
    reply = json.dumps({"replacement": FIXED, "explanation": "parameterized"})
    complete = _complete(reply)

    result = asyncio.run(propose(FINDING, path, scanner, catalog, complete=complete))

    assert result is not None and result.replacement == FIXED
    assert complete.calls == 1
    assert catalog.get(pattern_key(FINDING.kind, ORIGINAL)) is None  # propose never auto-persists


def test_a_model_that_cannot_draft_a_fix_yields_no_proposal(tmp_path):
    path = _file(tmp_path)
    catalog = CodemodCatalog(tmp_path / "catalog")
    scanner = _ScriptedScanner({})
    complete = _complete(fails=True)

    result = asyncio.run(propose(FINDING, path, scanner, catalog, complete=complete))
    assert result is None


def test_a_draft_that_fails_reverification_yields_no_proposal(tmp_path):
    path = _file(tmp_path)
    catalog = CodemodCatalog(tmp_path / "catalog")
    # the fix does not actually clear the finding on re-scan
    scanner = _ScriptedScanner({ORIGINAL: [("sql_injection", 1)], FIXED: [("sql_injection", 1)]})
    reply = json.dumps({"replacement": FIXED, "explanation": "should have worked"})
    complete = _complete(reply)

    result = asyncio.run(propose(FINDING, path, scanner, catalog, complete=complete))
    assert result is None
