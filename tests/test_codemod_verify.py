"""Re-verification: a candidate is only ever trusted after an independent re-scan proves the
finding is actually gone, the file still parses, and no new finding was introduced."""

import pytest

from purpleteam.codemods.base import CodemodCandidate, VerificationFailed
from purpleteam.codemods.verify import verify
from purpleteam.sast import StaticFinding


class _ScriptedScanner:
    """Returns findings keyed by the exact text it was given, so a test can script before/after
    scans without a real tool."""

    def __init__(self, by_text: dict[str, list[tuple[str, int]]]) -> None:
        self._by_text = by_text  # text -> [(kind, line), ...]

    def scan(self, repo):
        (file_path,) = list(repo.iterdir())
        text = file_path.read_text(encoding="utf-8")
        return [StaticFinding(kind, file_path.name, line, "scripted") for kind, line in self._by_text.get(text, [])]


FINDING = StaticFinding("sql_injection", "vendor.py", 1, "string-built SQL query")
ORIGINAL = "cursor.execute(f'SELECT * FROM t WHERE id={x}')"
FIXED = "cursor.execute('SELECT * FROM t WHERE id=?', (x,))"


def _file(tmp_path, text):
    path = tmp_path / "vendor.py"
    path.write_text(text, encoding="utf-8")
    return path


def test_a_fix_that_removes_the_finding_is_verified(tmp_path):
    path = _file(tmp_path, ORIGINAL)
    scanner = _ScriptedScanner({ORIGINAL: [("sql_injection", 1)], FIXED: []})
    candidate = CodemodCandidate("sql_injection", ORIGINAL, FIXED, "parameterized")
    verified = verify(candidate, FINDING, path, scanner)
    assert verified.replacement == FIXED


def test_a_fix_that_does_not_remove_the_finding_fails(tmp_path):
    path = _file(tmp_path, ORIGINAL)
    scanner = _ScriptedScanner({ORIGINAL: [("sql_injection", 1)], FIXED: [("sql_injection", 1)]})
    candidate = CodemodCandidate("sql_injection", ORIGINAL, FIXED, "did not actually help")
    with pytest.raises(VerificationFailed, match="still reported"):
        verify(candidate, FINDING, path, scanner)


def test_a_fix_that_introduces_a_new_finding_kind_fails(tmp_path):
    path = _file(tmp_path, ORIGINAL)
    scanner = _ScriptedScanner({ORIGINAL: [("sql_injection", 1)], FIXED: [("shell_command", 1)]})
    candidate = CodemodCandidate("sql_injection", ORIGINAL, FIXED, "swapped one hole for another")
    with pytest.raises(VerificationFailed, match="introduced new finding"):
        verify(candidate, FINDING, path, scanner)


def test_a_pre_existing_unrelated_finding_in_the_file_is_not_blamed_on_the_fix(tmp_path):
    # both before and after carry an unrelated "shell_command" finding already in the file —
    # the fix must not be blamed for something it did not introduce
    path = _file(tmp_path, ORIGINAL)
    scanner = _ScriptedScanner({
        ORIGINAL: [("sql_injection", 1), ("shell_command", 5)],
        FIXED: [("shell_command", 5)],
    })
    candidate = CodemodCandidate("sql_injection", ORIGINAL, FIXED, "parameterized")
    verified = verify(candidate, FINDING, path, scanner)
    assert verified.replacement == FIXED


def test_a_candidate_whose_original_text_no_longer_matches_the_file_fails(tmp_path):
    path = _file(tmp_path, "the file changed since the finding was recorded")
    scanner = _ScriptedScanner({})
    candidate = CodemodCandidate("sql_injection", ORIGINAL, FIXED, "stale")
    with pytest.raises(VerificationFailed, match="no longer match"):
        verify(candidate, FINDING, path, scanner)


def test_a_candidate_that_does_not_parse_fails_before_any_scan(tmp_path):
    path = _file(tmp_path, ORIGINAL)
    scanner = _ScriptedScanner({})  # never consulted
    candidate = CodemodCandidate("sql_injection", ORIGINAL, "cursor.execute(f'SELECT * FROM t WHERE id={x}", "broken")
    with pytest.raises(VerificationFailed, match="does not parse"):
        verify(candidate, FINDING, path, scanner)


def test_a_clean_sql_fix_is_verified_by_both_the_rescan_and_the_independent_invariant(tmp_path):
    path = _file(tmp_path, ORIGINAL)
    scanner = _ScriptedScanner({ORIGINAL: [("sql_injection", 1)], FIXED: []})
    candidate = CodemodCandidate("sql_injection", ORIGINAL, FIXED, "parameterized")
    verified = verify(candidate, FINDING, path, scanner)
    assert verified.verified_by == ("rescan", "invariant")


def test_a_fix_the_scanner_wrongly_calls_clean_is_still_caught_by_the_independent_invariant(tmp_path):
    """The whole point of an independent check: even a scanner that misses the real problem (or
    was fooled) must not be the only thing standing between a candidate and being shown as proven."""
    still_dynamic = "cursor.execute(f'SELECT * FROM t WHERE id={x}' + '')"
    path = _file(tmp_path, ORIGINAL)
    scanner = _ScriptedScanner({ORIGINAL: [("sql_injection", 1)], still_dynamic: []})  # the scanner is wrong here
    candidate = CodemodCandidate("sql_injection", ORIGINAL, still_dynamic, "did not actually help")
    with pytest.raises(VerificationFailed, match="independent security invariant failed"):
        verify(candidate, FINDING, path, scanner)


def test_a_kind_with_no_independent_invariant_is_verified_by_the_rescan_alone(tmp_path):
    original, fixed = "os.system(cmd)", "subprocess.run(cmd, shell=False)"
    path = _file(tmp_path, original)
    finding = StaticFinding("shell_command", "vendor.py", 1, "shell injection")
    scanner = _ScriptedScanner({original: [("shell_command", 1)], fixed: []})
    candidate = CodemodCandidate("shell_command", original, fixed, "no shell")
    verified = verify(candidate, finding, path, scanner)
    assert verified.verified_by == ("rescan",)
