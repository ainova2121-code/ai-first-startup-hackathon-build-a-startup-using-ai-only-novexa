"""Re-verification: a candidate is only ever trusted after an independent re-scan proves the
finding is actually gone, the file still parses, and no new finding was introduced."""

import pytest

from purpleteam.codemods.base import CodemodCandidate, VerificationFailed
from purpleteam.codemods.apply import apply_approved
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.codemods.verify import new_calls, verify
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


@pytest.mark.parametrize("sneaky, reason", [
    ("import requests\ncursor.execute('SELECT * FROM t WHERE id=?', (x,))", "adds an import"),
    ("\n" * 13 + "cursor.execute('SELECT * FROM t WHERE id=?', (x,))", "too broad"),
])
def test_a_fix_that_is_not_a_local_fix_is_never_verified(tmp_path, sneaky, reason):
    """Model-written code is untrusted: a fix stays local to what it replaces."""
    path = _file(tmp_path, ORIGINAL)
    scanner = _ScriptedScanner({ORIGINAL: [("sql_injection", 1)]})
    with pytest.raises(VerificationFailed, match=reason):
        verify(CodemodCandidate("sql_injection", ORIGINAL, sneaky, "x"), FINDING, path, scanner)


def test_a_fix_using_a_name_its_file_never_defines_is_rejected(tmp_path):
    """Clean on every security check, but a NameError the first time it runs."""
    original, fixed = "value = eval(text)", "value = ast.literal_eval(text)"
    path = _file(tmp_path, original)
    scanner = _ScriptedScanner({original: [("code_execution", 1)], fixed: []})
    finding = StaticFinding("code_execution", "vendor.py", 1, "eval")
    with pytest.raises(VerificationFailed, match="never defines: ast"):
        verify(CodemodCandidate("code_execution", original, fixed, "x"), finding, path, scanner)
    path.write_text(f"import ast\n{original}", encoding="utf-8")  # the same fix, in a file that imports ast
    scanner = _ScriptedScanner({f"import ast\n{original}": [("code_execution", 2)], f"import ast\n{fixed}": []})
    finding = StaticFinding("code_execution", "vendor.py", 2, "eval")
    verified = verify(CodemodCandidate("code_execution", original, fixed, "x"), finding, path, scanner)
    assert verified.verified_by == ("rescan", "invariant") and new_calls(path.read_text(), fixed) == set()


def test_a_crlf_file_keeps_its_line_endings_through_an_edit_and_restores_to_the_same_bytes(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "vendor.py"
    original_bytes = f"x = 1\r\n{ORIGINAL}\r\ny = 2\r\n".encode()
    target.write_bytes(original_bytes)
    finding = StaticFinding("sql_injection", "vendor.py", 2, "string-built SQL query")
    scanner = _LineScanner()
    codemod = verify(CodemodCandidate("sql_injection", ORIGINAL, FIXED, "parameterized"), finding, target, scanner)
    change = apply_approved(codemod, finding, repo, scanner)
    assert target.read_bytes() == f"x = 1\r\n{FIXED}\r\ny = 2\r\n".encode()  # only the fixed line changed
    snapshots = SourceSnapshots(tmp_path / "snap.json")
    snapshots.record(change["path"], change["before"], change["after"])
    assert [r["status"] for r in snapshots.restore_all(repo)] == ["restored"]
    assert target.read_bytes() == original_bytes


class _LineScanner:
    def scan(self, repo):
        (path,) = [p for p in repo.iterdir() if p.suffix == ".py"]
        return [StaticFinding("sql_injection", path.name, n, "x")
                for n, line in enumerate(path.read_text().splitlines(), 1) if "execute(f'" in line]


def test_calls_a_fix_adds_are_named_so_it_is_never_auto_applied():
    assert new_calls(ORIGINAL, "post(x)\n" + FIXED) == {"post"}
    assert new_calls(ORIGINAL, "if x is None:\n    raise ValueError(x)\n" + FIXED) == set()


def test_an_invariant_the_vulnerable_original_already_passes_is_not_counted_as_evidence(tmp_path):
    """A check that cannot tell the vulnerable code from the fix proves nothing about the fix: the
    fix is then rescan-only (left for human review), never labelled independently verified."""
    original, fixed = "query = 'SELECT * FROM t WHERE id=' + str(x)", "query = 'SELECT 1'"
    path = _file(tmp_path, original)
    scanner = _ScriptedScanner({original: [("sql_injection", 1)], fixed: []})
    verified = verify(CodemodCandidate("sql_injection", original, fixed, "x"), FINDING, path, scanner)
    assert verified.verified_by == ("rescan", "invariant")  # this original IS rejected by the invariant

    original, fixed = "rows = helper(table_name)", "rows = helper('vendors')"  # nothing SQL-shaped to reject
    path = _file(tmp_path, original)
    scanner = _ScriptedScanner({original: [("sql_injection", 1)], fixed: []})
    verified = verify(CodemodCandidate("sql_injection", original, fixed, "x"), FINDING, path, scanner)
    assert verified.verified_by == ("rescan",)


def test_a_fix_the_scanner_wrongly_calls_clean_is_still_caught_by_the_independent_invariant(tmp_path):
    """The whole point of an independent check: even a scanner that misses the real problem (or
    was fooled) must not be the only thing standing between a candidate and being shown as proven."""
    still_dynamic = "cursor.execute(f'SELECT * FROM t WHERE id={x}' + '')"
    path = _file(tmp_path, ORIGINAL)
    scanner = _ScriptedScanner({ORIGINAL: [("sql_injection", 1)], still_dynamic: []})  # the scanner is wrong here
    candidate = CodemodCandidate("sql_injection", ORIGINAL, still_dynamic, "did not actually help")
    with pytest.raises(VerificationFailed, match="independent security invariant failed"):
        verify(candidate, FINDING, path, scanner)


TWO_FINDINGS = f"x = 1\n{ORIGINAL}\nrow = one(f'SELECT * FROM {{table}}')\n"
ONE_FIXED = TWO_FINDINGS.replace(ORIGINAL, FIXED)


def test_fixing_one_of_two_same_kind_findings_in_a_file_is_verified(tmp_path):
    """The bug this guards against: an unrelated, still-present finding of the same kind elsewhere
    in the file used to fail every correct fix, so no single-line fix could ever verify."""
    path = _file(tmp_path, TWO_FINDINGS)
    scanner = _ScriptedScanner({TWO_FINDINGS: [("sql_injection", 2), ("sql_injection", 3)],
                                ONE_FIXED: [("sql_injection", 3)]})
    finding = StaticFinding("sql_injection", "vendor.py", 2, "string-built SQL query")
    verified = verify(CodemodCandidate("sql_injection", ORIGINAL, FIXED, "parameterized"), finding, path, scanner)
    assert verified.verified_by == ("rescan", "invariant")


def test_a_fix_whose_own_line_is_still_flagged_fails_even_with_another_finding_present(tmp_path):
    path = _file(tmp_path, TWO_FINDINGS)
    scanner = _ScriptedScanner({TWO_FINDINGS: [("sql_injection", 2), ("sql_injection", 3)],
                                ONE_FIXED: [("sql_injection", 2), ("sql_injection", 3)]})
    finding = StaticFinding("sql_injection", "vendor.py", 2, "string-built SQL query")
    with pytest.raises(VerificationFailed, match="still reported"):
        verify(CodemodCandidate("sql_injection", ORIGINAL, FIXED, "no help"), finding, path, scanner)


def test_a_fix_that_adds_a_same_kind_finding_on_a_new_line_is_caught_as_introduced(tmp_path):
    two_lines = f"{FIXED}\ncursor.execute(f'DELETE FROM t WHERE id={{x}}')"
    path = _file(tmp_path, ORIGINAL)
    scanner = _ScriptedScanner({ORIGINAL: [("sql_injection", 1)], two_lines: [("sql_injection", 2)]})
    with pytest.raises(VerificationFailed):
        verify(CodemodCandidate("sql_injection", ORIGINAL, two_lines, "smuggled"), FINDING, path, scanner)


def test_a_kind_with_no_independent_invariant_is_verified_by_the_rescan_alone(tmp_path):
    original, fixed = "os.system(cmd)", "subprocess.run(cmd, shell=False)"
    path = _file(tmp_path, f"import subprocess\n{original}")
    finding = StaticFinding("shell_command", "vendor.py", 2, "shell injection")
    scanner = _ScriptedScanner({f"import subprocess\n{original}": [("shell_command", 2)],
                                f"import subprocess\n{fixed}": []})
    candidate = CodemodCandidate("shell_command", original, fixed, "no shell")
    verified = verify(candidate, finding, path, scanner)
    assert verified.verified_by == ("rescan",)
