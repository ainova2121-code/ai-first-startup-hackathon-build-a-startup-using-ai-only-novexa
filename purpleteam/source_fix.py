"""Fix the target's own source for what static analysis found: an exact-match catalog codemod, or a
freshly drafted one, written to the real file only once it is proven twice over.

A drafted fix is auto-approved -- with no human click -- only when it passed both the rescan by the
scanner that found the issue *and* the independent invariant check (``codemods.invariants``); a fix
proven by the rescan alone, or one for a kind with no invariant, is reported as needing human review
and never written. Every write is recorded first in ``SourceSnapshots`` (so it can be restored) and
then in the signed ledger by path and hash only: source text can hold credentials or proprietary
code, so the full before/after goes only to the local caller's ``emit``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from purpleteam.codemods.apply import apply_approved
from purpleteam.codemods.author import Complete
from purpleteam.codemods.base import VerificationFailed, VerifiedCodemod
from purpleteam.codemods.catalog import CodemodCatalog, pattern_key
from purpleteam.codemods.context import fix_context, source_statement
from purpleteam.codemods.propose import propose
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.codemods.verify import new_calls
from purpleteam.concurrency import limit
from purpleteam.sast import Scanner, StaticFinding

AUTO_APPROVAL = "auto-approved by verification (rescan + invariant), not human-reviewed"


@dataclass
class SourceFixResult:
    changes: list[dict] = field(default_factory=list)   # what was written, with full before/after
    skipped: list[dict] = field(default_factory=list)   # {kind, path, line, reason}
    resolved: set[tuple[str, str, int]] = field(default_factory=set)  # (kind, file, line) of fixed findings


def resolve(repo: Path, file: str) -> Path:
    """A scanner may report a path relative to the scan root or including its final directory name."""
    path = Path(file)
    if path.is_absolute():
        return path
    if not (repo / path).exists() and path.parts and path.parts[0] == repo.name:
        return repo.joinpath(*path.parts[1:])
    return repo / path


def display(repo: Path, file: str) -> str:
    """``<repo name>/<path inside it>`` for people -- never a machine-specific absolute path."""
    path = resolve(repo, file)
    try:
        return f"{repo.name}/{path.resolve().relative_to(repo.resolve()).as_posix()}"
    except ValueError:
        return Path(file).as_posix()


async def fix_sources(findings: list[StaticFinding], repo: Path, scanner: Scanner, catalog: CodemodCatalog, *,
                      complete: Complete | None, snapshots: SourceSnapshots | None, ledger: Any,
                      emit: Callable[[dict], None] = lambda event: None) -> SourceFixResult:
    result = SourceFixResult()
    # Bottom-up within each file: an edit never shifts the line number of a finding still to come.
    ordered = sorted(findings, key=lambda f: (f.file, -f.line))
    for finding in ordered:
        emit({"type": "source_fix_attempt", "kind": finding.kind, "path": display(repo, finding.file),
              "line": finding.line})
    # Drafting and proving every fix is independent work, so it runs concurrently (bounded); writing
    # them stays strictly one at a time, below, in bottom-up order.
    gate = asyncio.Semaphore(limit())

    async def approve(finding: StaticFinding) -> tuple[VerifiedCodemod | str, str]:
        async with gate:
            try:
                return await _approved(finding, repo, resolve(repo, finding.file), scanner, catalog, complete,
                                       ledger, display(repo, finding.file))
            except (OSError, ValueError, VerificationFailed) as error:
                return str(error), ""
            except Exception as error:  # an unexpected failure on one finding must not sink every other fix
                return f"drafting a fix failed ({type(error).__name__}); nothing was changed", ""

    approvals = await asyncio.gather(*(approve(finding) for finding in ordered))
    for finding, (codemod, approval) in zip(ordered, approvals):
        shown = display(repo, finding.file)
        try:
            if isinstance(codemod, str):
                raise VerificationFailed(codemod)
            change = apply_approved(codemod, finding, repo, scanner)
        except (OSError, ValueError, VerificationFailed) as error:
            skip = {"kind": finding.kind, "path": shown, "line": finding.line, "reason": str(error)}
            result.skipped.append(skip)
            ledger.append("defender", "source_patch_skipped", skip)
            emit({"type": "source_patch_skipped", **skip})
            continue
        if snapshots is not None:
            snapshots.record(change["path"], change["before"], change["after"])
        record = {"kind": finding.kind, "path": shown, "line": change["line_start"], "sha256": change["sha256"],
                  "verified_by": change["verified_by"], "approval": approval}
        ledger.append("defender", "source_patch", {**record, "applied": True})
        result.changes.append({**record, "before_lines": change["before_lines"],
                               "after_lines": change["after_lines"], "diff": change["diff"],
                               "content": change["after"],  # the whole file exactly as written, for the local UI
                               "explanation": codemod.explanation})
        result.resolved.add((finding.kind, finding.file, finding.line))
        emit({"type": "source_patch", **result.changes[-1]})
    return result


async def _approved(finding: StaticFinding, repo: Path, path: Path, scanner: Scanner, catalog: CodemodCatalog,
                    complete: Complete | None, ledger: Any, display: str) -> tuple[VerifiedCodemod | str, str]:
    """(codemod, how it was approved), or (reason it cannot be applied, "")."""
    key = pattern_key(finding.kind, source_statement(path, finding.line))
    cached = catalog.get(key)
    if cached is not None:
        return cached, "approved earlier (catalog, exact source match)"
    if complete is None:
        return "no approved fix in the catalog, and no model configured to draft one", ""
    drafted = await propose(finding, path, scanner, catalog, complete=complete,
                            context=fix_context(repo, path, finding.line))
    if drafted is None:
        return "no fix could be drafted that passed verification", ""
    if "invariant" not in drafted.verified_by:
        return "verified by rescan only, with no independent invariant: needs human review", ""
    added = new_calls(path.read_text(encoding="utf-8"), drafted.replacement)
    if added:
        return f"the fix adds calls the file never made ({', '.join(sorted(added))}): needs human review", ""
    catalog.approve(key, drafted)
    ledger.append("defender", "source_patch_approved", {"kind": finding.kind, "path": display,
                                                        "verified_by": list(drafted.verified_by),
                                                        "approval": AUTO_APPROVAL})
    return drafted, AUTO_APPROVAL
