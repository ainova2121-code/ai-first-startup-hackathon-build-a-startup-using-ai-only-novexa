"""The one-time authoring loop: reuse an exact-match approved codemod if one exists; otherwise
draft a fresh candidate and verify it by re-running the original scanner before it is ever
proposed to a human. Never a guess, never applied unverified, never re-drafted for a pattern
already proven and approved.
"""

from __future__ import annotations

from pathlib import Path

from purpleteam.codemods.author import Complete, draft
from purpleteam.codemods.base import VerificationFailed, VerifiedCodemod
from purpleteam.codemods.catalog import CodemodCatalog, pattern_key
from purpleteam.codemods.verify import verify
from purpleteam.sast import Scanner, StaticFinding


def source_line(file_path: Path, line: int) -> str:
    lines = file_path.read_text(encoding="utf-8").splitlines()
    if not 1 <= line <= len(lines):
        raise ValueError(f"{file_path}:{line} is out of range")
    return lines[line - 1]


async def propose(finding: StaticFinding, file_path: Path, scanner: Scanner, catalog: CodemodCatalog,
                  *, complete: Complete) -> VerifiedCodemod | None:
    """None when nothing confident and proven could be produced — report the finding as-is,
    exactly as if no codemod system existed, rather than show anything unverified."""
    original = source_line(file_path, finding.line)
    key = pattern_key(finding.kind, original)
    cached = catalog.get(key)
    if cached is not None:
        return cached
    candidate = await draft(finding, original, complete=complete)
    if candidate is None:
        return None
    try:
        return verify(candidate, finding, file_path, scanner)
    except VerificationFailed:
        return None
