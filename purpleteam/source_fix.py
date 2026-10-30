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
from purpleteam.codemods.catalog import HUMAN_REVIEWED, CodemodCatalog, pattern_key
from purpleteam.codemods.context import fix_context, source_statement
from purpleteam.codemods.gate import gate_candidate
from purpleteam.codemods.hardening import hardening_candidate
from purpleteam.codemods.propose import propose
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.codemods.verify import new_calls, verify
from purpleteam.concurrency import limit
from purpleteam.gate_scan import GATE_KIND
from purpleteam.hardening_scan import HARDENING_KINDS
from purpleteam.sast import Scanner, StaticFinding

AUTO_APPROVAL = "auto-approved by verification (rescan + invariant), not human-reviewed"
HARDENING_APPROVAL = "auto-approved: fixed hardening clause appended, proven by rescan + invariant (not human-reviewed)"
GATE_APPROVAL = "auto-approved: fixed human-approval gate, proven by rescan + invariant (not human-reviewed)"


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

    async def approve(finding: StaticFinding) -> tuple[VerifiedCodemod | str, str, bool]:
        async with gate:
            try:
                return await _approved(finding, repo, resolve(repo, finding.file), scanner, catalog, complete,
                                       ledger, display(repo, finding.file))
            except (OSError, ValueError, VerificationFailed) as error:
                return str(error), "", False
            except Exception as error:  # an unexpected failure on one finding must not sink every other fix
                return f"drafting a fix failed ({type(error).__name__}); nothing was changed", "", False

    approvals = await asyncio.gather(*(approve(finding) for finding in ordered))
    for finding, (codemod, approval, human_reviewed) in zip(ordered, approvals):
        shown = display(repo, finding.file)
        try:
            if isinstance(codemod, str):
                raise VerificationFailed(codemod)
            change = apply_approved(codemod, finding, repo, scanner, human_reviewed=human_reviewed)
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
                    complete: Complete | None, ledger: Any,
                    display: str) -> tuple[VerifiedCodemod | str, str, bool]:
    """(codemod, how it was approved, whether a human reviewed it), or (reason it cannot be applied, "", False)."""
    original = source_statement(path, finding.line)
    key = pattern_key(finding.kind, original)
    cached = catalog.get(key)
    if cached is not None:  # the label it was approved under travels with every reuse
        approval = catalog.approval(key)
        return cached, f"reused from the catalog (exact source match): {approval}", approval == HUMAN_REVIEWED
    if finding.kind in HARDENING_KINDS or finding.kind == GATE_KIND:  # a fixed transform -- no model, still proven
        return await _deterministic(finding, original, path, scanner, catalog, ledger, display)
    if complete is None:
        return "no approved fix in the catalog, and no model configured to draft one", "", False
    drafted = await propose(finding, path, scanner, catalog, complete=complete,
                            context=fix_context(repo, path, finding.line))
    if drafted is None:
        return "no fix could be drafted that passed verification", "", False
    if "invariant" not in drafted.verified_by:
        return "verified by rescan only, with no independent invariant: needs human review", "", False
    added = new_calls(path.read_text(encoding="utf-8"), drafted.replacement)
    if added:
        return f"the fix adds calls the file never made ({', '.join(sorted(added))}): needs human review", "", False
    catalog.approve(key, drafted, approval=AUTO_APPROVAL)
    ledger.append("defender", "source_patch_approved", {"kind": finding.kind, "path": display,
                                                        "verified_by": list(drafted.verified_by),
                                                        "approval": AUTO_APPROVAL})
    return drafted, AUTO_APPROVAL, False


async def _deterministic(finding: StaticFinding, original: str, path: Path, scanner: Scanner,
                         catalog: CodemodCatalog, ledger: Any, display: str) -> tuple[VerifiedCodemod | str, str, bool]:
    """A fixed transform -- the hardening clause appended to a prompt / tool description, or the human-approval
    gate in an unguarded dangerous tool -- proven the same way a drafted fix is: the scanner rescan no longer
    flags it and the independent invariant holds. No model, but never written unverified, and only ever applied
    once -- the scanners skip text already hardened or gated."""
    if finding.kind == GATE_KIND:
        candidate, approval = gate_candidate(finding, original), GATE_APPROVAL
        unusable = "the tool's first statement is not a single simple statement the gate can replace"
    else:
        candidate, approval = hardening_candidate(finding, original), HARDENING_APPROVAL
        unusable = "the statement does not end in a string the hardening clause can attach to"
    if candidate is None:
        return unusable, "", False
    try:
        verified = await asyncio.to_thread(verify, candidate, finding, path, scanner)
    except VerificationFailed as error:
        return str(error), "", False
    if "invariant" not in verified.verified_by:
        return "the fixed transform could not be independently verified", "", False
    catalog.approve(pattern_key(finding.kind, original), verified, approval=approval)
    ledger.append("defender", "source_patch_approved", {"kind": finding.kind, "path": display,
                                                        "verified_by": list(verified.verified_by),
                                                        "approval": approval})
    return verified, approval, False
