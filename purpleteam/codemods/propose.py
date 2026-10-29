"""The one-time authoring loop: reuse an exact-match approved codemod if one exists; otherwise
draft a fresh candidate and verify it by re-running the original scanner before it is ever
proposed to a human. Never a guess, never applied unverified, never re-drafted for a pattern
already proven and approved.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from purpleteam.codemods.author import Complete, draft
from purpleteam.codemods.base import VerificationFailed, VerifiedCodemod
from purpleteam.codemods.catalog import CodemodCatalog, pattern_key
from purpleteam.codemods.context import source_statement
from purpleteam.codemods.verify import verify
from purpleteam.sast import Scanner, StaticFinding


async def propose(finding: StaticFinding, file_path: Path, scanner: Scanner, catalog: CodemodCatalog,
                  *, complete: Complete, attempts: int = 3, context: dict | None = None) -> VerifiedCodemod | None:
    """None when nothing confident and proven could be produced — report the finding as-is,
    exactly as if no codemod system existed, rather than show anything unverified. A model's drafts
    vary run to run (a correct one, then a subtly broken one), so up to ``attempts`` drafts are tried;
    each must pass verification on its own, and a rejected draft is never kept or applied."""
    original = source_statement(file_path, finding.line)
    key = pattern_key(finding.kind, original)
    cached = catalog.get(key)
    if cached is not None:
        return cached
    for _ in range(attempts):
        candidate = await draft(finding, original, complete=complete, context=context)
        if candidate is None:
            continue
        try:  # the rescan runs a real scanner process: off the event loop, so other drafts keep moving
            return await asyncio.to_thread(verify, candidate, finding, file_path, scanner)
        except VerificationFailed:
            continue
    return None
