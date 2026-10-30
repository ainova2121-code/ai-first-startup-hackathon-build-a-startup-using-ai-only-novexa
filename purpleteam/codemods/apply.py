"""Apply only an already-approved codemod to the exact source it was verified against.

This is deliberately separate from drafting: a model candidate is never eligible for direct
application. The source file is rechecked with the configured scanner immediately before writing,
the replacement is atomic, and the returned diff is generated from the bytes actually written.
A fix no human reviewed must also pass, freshly, the bar it was auto-approved on (the independent
invariant, and no call its file did not already make), however it reached here -- including a reused
or hand-edited catalog entry, whose stored claims are never trusted.
"""

from __future__ import annotations

import difflib
import hashlib
import os
import tempfile
from pathlib import Path

from purpleteam.codemods.base import CodemodCandidate, VerifiedCodemod, VerificationFailed
from purpleteam.codemods.context import occurrence
from purpleteam.codemods.restore import read_exact
from purpleteam.codemods.verify import new_calls, verify
from purpleteam.sast import Scanner, StaticFinding


def apply_approved(codemod: VerifiedCodemod, finding: StaticFinding, repo: Path,
                   scanner: Scanner, *, human_reviewed: bool = False) -> dict:
    """Apply a verified codemod to its target file and return an evidence-backed change record.

    Raises ``VerificationFailed`` without changing the file if the path escapes ``repo``, the
    exact source is stale/ambiguous, or a fresh scanner/invariant check fails. Unless
    ``human_reviewed``, the fresh check must include the invariant and the fix may add no new call.
    """
    root = repo.resolve()
    candidate_path = Path(finding.file)
    if candidate_path.is_absolute():
        path = candidate_path.resolve()
    else:
        path = (root / candidate_path).resolve()
        # Scanners vary: some return paths relative to the scan root, others include its final
        # directory name. Normalize the latter without ever relaxing the containment check.
        if not path.exists() and candidate_path.parts and candidate_path.parts[0] == root.name:
            path = (root.joinpath(*candidate_path.parts[1:])).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise VerificationFailed("finding path is outside the configured target repository") from error
    if not path.is_file():
        raise VerificationFailed("finding file no longer exists")

    before = read_exact(path)
    newline = "\r\n" if "\r\n" in before else "\n"  # edit in the file's own line endings, never rewrite them all
    original, replacement = codemod.original.replace("\n", newline), codemod.replacement.replace("\n", newline)
    at = occurrence(before, original, finding.line)  # the copy the finding names, even if the text repeats
    if at < 0:
        raise VerificationFailed("approved source text no longer matches the file at that line; no edit was made")
    candidate = CodemodCandidate(codemod.kind, codemod.original, codemod.replacement, codemod.explanation)
    freshly_verified = verify(candidate, finding, path, scanner)
    if freshly_verified.replacement != codemod.replacement:
        raise VerificationFailed("re-verification did not reproduce the approved replacement")
    if not human_reviewed:
        if "invariant" not in freshly_verified.verified_by:
            raise VerificationFailed("not human-reviewed, and not independently verified by an invariant: "
                                     "needs human review")
        if added := new_calls(before, codemod.replacement):
            raise VerificationFailed(f"not human-reviewed, and the fix adds calls the file never made "
                                     f"({', '.join(sorted(added))}): needs human review")

    after = before[:at] + replacement + before[at + len(original):]
    # Write to the same directory so os.replace is atomic on the target filesystem.
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".codemod", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(after)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise

    actual = read_exact(path)
    if actual != after:
        # Do not leave an unexpected write behind if the filesystem changed under us.
        path.write_bytes(before.encode("utf-8"))  # exact bytes back: write_text would re-translate newlines
        raise VerificationFailed("written source did not match the verified replacement")
    diff = "".join(difflib.unified_diff(before.splitlines(keepends=True), actual.splitlines(keepends=True),
                                       fromfile=f"a/{finding.file}", tofile=f"b/{finding.file}"))
    old_start = before[:at].count("\n") + 1
    before_lines = codemod.original.splitlines()
    after_lines = codemod.replacement.splitlines()
    return {
        "path": path.relative_to(root).as_posix(),
        "before": before,
        "after": actual,
        "diff": diff,
        "line_start": old_start,
        "before_lines": before_lines,
        "after_lines": after_lines,
        "sha256": hashlib.sha256(actual.encode("utf-8")).hexdigest(),
        "verified_by": list(freshly_verified.verified_by),
        "applied": True,
    }
