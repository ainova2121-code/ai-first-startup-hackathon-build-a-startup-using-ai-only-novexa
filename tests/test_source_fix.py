"""Source fixes: written to the real file only when proven by the rescan *and* the independent
invariant, recorded so they can be restored, and logged by path and hash -- never source text."""

import asyncio
import json

from purpleteam.audit.ledger import AuditLedger
from purpleteam.codemods.catalog import CodemodCatalog
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.sast import StaticFinding
from purpleteam.source_fix import fix_sources

ORIGINAL = "cursor.execute(f'SELECT * FROM t WHERE id={x}')"
FIXED = "cursor.execute('SELECT * FROM t WHERE id=?', (x,))"


class _Scanner:
    """Flags every line that still builds SQL with an f-string, like Bandit's B608 would."""

    def __init__(self, kind="sql_injection", marker="execute(f'"):
        self.kind, self.marker = kind, marker

    def scan(self, repo):
        found = []
        for path in repo.iterdir():
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if self.marker in line:
                    found.append(StaticFinding(self.kind, path.name, number, "string-built"))
        return found


def _setup(tmp_path, text=f"x = 1\n{ORIGINAL}\n"):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "vendor.py").write_bytes(text.encode())  # exact bytes: no platform newline translation
    return repo, AuditLedger(tmp_path / "audit.jsonl"), CodemodCatalog(tmp_path / "catalog"), SourceSnapshots(tmp_path / "snap.json")


def _complete(replacement):
    async def complete(system, user):
        return json.dumps({"replacement": replacement, "explanation": "parameterized"})
    return complete


def _run(repo, ledger, catalog, snapshots, complete, scanner=None):
    scanner = scanner or _Scanner()
    events = []
    result = asyncio.run(fix_sources(scanner.scan(repo), repo, scanner, catalog, complete=complete,
                                     snapshots=snapshots, ledger=ledger, emit=events.append))
    return result, events


def test_a_fix_proven_by_rescan_and_invariant_is_auto_applied_to_the_real_file(tmp_path):
    repo, ledger, catalog, snapshots = _setup(tmp_path)
    result, events = _run(repo, ledger, catalog, snapshots, _complete(FIXED))

    assert (repo / "vendor.py").read_text() == f"x = 1\n{FIXED}\n"
    (change,) = result.changes
    assert change["path"] == "repo/vendor.py" and change["line"] == 2
    assert change["verified_by"] == ["rescan", "invariant"] and "not human-reviewed" in change["approval"]
    assert [e["type"] for e in events] == ["source_fix_attempt", "source_patch"]
    assert events[-1]["content"] == (repo / "vendor.py").read_text()  # the whole file exactly as written
    assert (events[-1]["before_lines"], events[-1]["after_lines"]) == ([ORIGINAL], [FIXED])
    assert snapshots.modified() == ["vendor.py"]
    assert ORIGINAL not in (tmp_path / "audit.jsonl").read_text()  # the ledger never holds source text


def test_a_fix_with_no_independent_invariant_is_not_written_and_says_why(tmp_path):
    repo, ledger, catalog, snapshots = _setup(tmp_path, "import subprocess\nos.system(f'ls {d}')\n")
    scanner = _Scanner(kind="shell_command", marker="os.system(f'")  # a kind with no invariant
    result, events = _run(repo, ledger, catalog, snapshots, _complete("subprocess.run(['ls', d])"), scanner)

    assert (repo / "vendor.py").read_text() == "import subprocess\nos.system(f'ls {d}')\n"
    assert not result.changes and "needs human review" in result.skipped[0]["reason"]
    assert events[-1]["type"] == "source_patch_skipped" and snapshots.modified() == []


def test_a_proven_fix_that_adds_a_new_call_is_left_for_human_review(tmp_path):
    repo, ledger, catalog, snapshots = _setup(tmp_path, f"audit = print\n{ORIGINAL}\n")  # known, never called
    result, _ = _run(repo, ledger, catalog, snapshots, _complete(f"audit(x)\n{FIXED}"))
    assert not result.changes and "adds calls the file never made (audit)" in result.skipped[0]["reason"]
    assert ORIGINAL in (repo / "vendor.py").read_text()


def test_a_failing_fix_author_skips_that_finding_and_never_crashes_the_run(tmp_path):
    repo, ledger, catalog, snapshots = _setup(tmp_path)

    async def unreachable(system, user):
        raise RuntimeError("no model key configured")

    result, events = _run(repo, ledger, catalog, snapshots, unreachable)
    assert not result.changes and "drafting a fix failed (RuntimeError)" in result.skipped[0]["reason"]
    assert events[-1]["type"] == "source_patch_skipped" and ORIGINAL in (repo / "vendor.py").read_text()


def test_without_a_catalog_entry_or_a_model_nothing_is_written(tmp_path):
    repo, ledger, catalog, snapshots = _setup(tmp_path)
    result, _ = _run(repo, ledger, catalog, snapshots, complete=None)
    assert not result.changes and "no model configured" in result.skipped[0]["reason"]
    assert ORIGINAL in (repo / "vendor.py").read_text()


def test_a_fix_approved_once_is_reused_without_drafting_again(tmp_path):
    repo, ledger, catalog, snapshots = _setup(tmp_path)
    _run(repo, ledger, catalog, snapshots, _complete(FIXED))
    snapshots.restore_all(repo)
    assert ORIGINAL in (repo / "vendor.py").read_text()

    async def never(system, user):
        raise AssertionError("an exact-match approved fix must not be drafted again")

    result, _ = _run(repo, ledger, catalog, snapshots, never)
    assert result.changes and "catalog" in result.changes[0]["approval"]
    assert "not human-reviewed" in result.changes[0]["approval"]  # an auto-approval stays labelled on every reuse


def _plant(catalog_dir, codemod, approval=None):
    """A catalog entry written by hand, as anyone with write access to the operator's folder could."""
    from dataclasses import asdict

    from purpleteam.codemods.catalog import pattern_key
    entry = {**asdict(codemod), **({"approval": approval} if approval else {})}
    (catalog_dir / f"{pattern_key(codemod.kind, codemod.original)}.codemod.json").write_text(json.dumps(entry))


def test_an_unreviewed_catalog_entry_that_adds_a_call_is_never_applied(tmp_path):
    from purpleteam.codemods.base import VerifiedCodemod
    repo, ledger, catalog, snapshots = _setup(tmp_path)
    sneaky = f"{FIXED}; cursor.close()"  # passes the rescan and the invariant, but adds behaviour
    _plant(tmp_path / "catalog", VerifiedCodemod("sql_injection", ORIGINAL, sneaky, "x", ("rescan", "invariant")))
    result, _ = _run(repo, ledger, catalog, snapshots, complete=None)
    assert result.changes == [] and "adds calls" in result.skipped[0]["reason"]
    assert (repo / "vendor.py").read_text() == f"x = 1\n{ORIGINAL}\n"


def test_an_older_catalog_entry_without_a_recorded_approval_is_not_presented_as_human_reviewed(tmp_path):
    from purpleteam.codemods.base import VerifiedCodemod
    repo, ledger, catalog, snapshots = _setup(tmp_path)
    _plant(tmp_path / "catalog", VerifiedCodemod("sql_injection", ORIGINAL, FIXED, "x", ("rescan", "invariant")))
    result, _ = _run(repo, ledger, catalog, snapshots, complete=None)
    (change,) = result.changes  # it still meets the automatic bar, so it is applied -- labelled as what it is
    assert "treated as not human-reviewed" in change["approval"]


def test_a_human_reviewed_catalog_entry_is_applied_on_the_rescan_alone(tmp_path):
    """A person's approval is the operator's catalog contract: the invariant is not required on top of it."""
    from purpleteam.codemods.base import VerifiedCodemod
    repo, ledger, catalog, snapshots = _setup(tmp_path, "import subprocess\nos.system(f'ls {d}')\n")
    fixed = "subprocess.run(['ls', d])"
    _plant(tmp_path / "catalog", VerifiedCodemod("shell_injection", "os.system(f'ls {d}')", fixed, "x"),
           approval="human-reviewed")
    result, _ = _run(repo, ledger, catalog, snapshots, complete=None, scanner=_Scanner("shell_injection", "os.system("))
    (change,) = result.changes
    assert change["approval"].endswith(": human-reviewed") and fixed in (repo / "vendor.py").read_text()


def test_two_findings_in_one_file_are_fixed_bottom_up(tmp_path):
    second = "cursor.execute(f'DELETE FROM t WHERE id={y}')"
    repo, ledger, catalog, snapshots = _setup(tmp_path, f"{ORIGINAL}\nz = 2\n{second}\n")

    async def complete(system, user):
        source = json.loads(user)["source"]
        fixed = FIXED if "SELECT" in source else "cursor.execute('DELETE FROM t WHERE id=?', (y,))"
        return json.dumps({"replacement": fixed, "explanation": "parameterized"})

    result, _ = _run(repo, ledger, catalog, snapshots, complete)
    assert [c["line"] for c in result.changes] == [3, 1]
    assert "execute(f'" not in (repo / "vendor.py").read_text()


def test_the_same_vulnerable_line_twice_in_a_file_is_fixed_at_each_place(tmp_path):
    """Found on a real project: an identical request line appeared twice and neither was fixed."""
    repo, ledger, catalog, snapshots = _setup(tmp_path, f"{ORIGINAL}\nz = 2\n{ORIGINAL}\n")
    result, _ = _run(repo, ledger, catalog, snapshots, _complete(FIXED))
    assert [c["line"] for c in result.changes] == [3, 1]
    assert (repo / "vendor.py").read_text() == f"{FIXED}\nz = 2\n{FIXED}\n"


def test_fixes_are_drafted_concurrently_but_written_one_at_a_time(tmp_path):
    second = "cursor.execute(f'DELETE FROM t WHERE id={y}')"
    repo, ledger, catalog, snapshots = _setup(tmp_path, f"{ORIGINAL}\n{second}\n")
    both_drafting = asyncio.Event()
    in_flight = 0

    async def complete(system, user):
        nonlocal in_flight
        in_flight += 1
        if in_flight == 2:
            both_drafting.set()
        await asyncio.wait_for(both_drafting.wait(), timeout=5)  # times out if drafts ran one by one
        source = json.loads(user)["source"]
        fixed = FIXED if "SELECT" in source else "cursor.execute('DELETE FROM t WHERE id=?', (y,))"
        return json.dumps({"replacement": fixed, "explanation": "parameterized"})

    result, _ = _run(repo, ledger, catalog, snapshots, complete)
    assert [c["line"] for c in result.changes] == [2, 1]  # still applied bottom-up
    assert "execute(f'" not in (repo / "vendor.py").read_text()
