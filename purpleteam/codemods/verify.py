"""Re-verify a drafted candidate against the same scanner that found the original issue.

Never trust the model's claim that it fixed something — prove it the same way every other claim
in this platform is proven: re-check with an independent, deterministic tool, on a throwaway
scratch copy, never the target's real file.
"""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path

from purpleteam.codemods.base import CodemodCandidate, VerificationFailed, VerifiedCodemod
from purpleteam.codemods.invariants import INVARIANTS
from purpleteam.sast import Scanner, StaticFinding


def verify(candidate: CodemodCandidate, finding: StaticFinding, file_path: Path, scanner: Scanner) -> VerifiedCodemod:
    """Raises VerificationFailed (never returns a half-checked result) unless: the patched file
    still parses, the original finding is gone, the fix introduced no new finding of its own
    (compared against the *original*, unpatched file's own findings — a pre-existing, unrelated
    issue elsewhere in the file must never be blamed on this fix), and — when one exists for this
    kind (``codemods.invariants``) — an independent, differently-implemented check of the same
    property also passes; a clean re-scan alone is never presented as more than it is."""
    original_text = file_path.read_text(encoding="utf-8")
    if candidate.original not in original_text:
        raise VerificationFailed("the original line(s) no longer match the file; stale finding")
    patched_text = original_text.replace(candidate.original, candidate.replacement, 1)
    try:
        ast.parse(patched_text)
    except SyntaxError as error:
        raise VerificationFailed(f"the candidate does not parse: {error}") from error

    before = _scan_text(scanner, file_path.name, original_text)
    after = _scan_text(scanner, file_path.name, patched_text)
    if any(f.kind == finding.kind for f in after):
        raise VerificationFailed("the finding is still reported after the fix")
    introduced = {f.kind for f in after} - {f.kind for f in before}
    if introduced:
        raise VerificationFailed(f"the fix introduced new finding kind(s): {', '.join(sorted(introduced))}")

    verified_by = ["rescan"]
    checker = INVARIANTS.get(finding.kind)
    if checker is not None:
        problem = checker(patched_text)
        if problem is not None:
            raise VerificationFailed(f"independent security invariant failed: {problem}")
        verified_by.append("invariant")
    return VerifiedCodemod(finding.kind, candidate.original, candidate.replacement, candidate.explanation,
                           verified_by=tuple(verified_by))


def _scan_text(scanner: Scanner, filename: str, text: str) -> list[StaticFinding]:
    with tempfile.TemporaryDirectory(prefix="codemod-verify-") as scratch:
        (Path(scratch) / filename).write_text(text, encoding="utf-8")
        return scanner.scan(Path(scratch))
