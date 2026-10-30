"""A persisted catalog of approved codemods, reused verbatim without ever calling the LLM
or re-verifying again for the exact same pattern.

Keyed by (kind, the exact original source text) rather than kind alone: a stored fix is proven
correct only for the specific snippet it was verified against, so it is only ever reused when
that exact snippet recurs (a literal pattern copy-pasted elsewhere, or the same file re-scanned
later) — never applied to a different piece of code just because the finding kind matches.

Every entry records how it was approved: by a human, or automatically by verification. A reused entry keeps
that label, so an auto-approved fix is never presented as human-reviewed, and an entry written before
approvals were recorded is treated as not human-reviewed.

Lives under a directory the operator owns, not bundled with the platform package: BYOC, same as
every other piece of persisted platform state.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from purpleteam.codemods.base import VerifiedCodemod

_SUFFIX = ".codemod.json"
HUMAN_REVIEWED = "human-reviewed"
UNRECORDED = "approval not recorded (an older catalog entry), treated as not human-reviewed"


def pattern_key(kind: str, original: str) -> str:
    digest = hashlib.sha256(original.encode("utf-8")).hexdigest()[:16]
    return f"{kind}_{digest}"


class CodemodCatalog:
    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str) -> VerifiedCodemod | None:
        data = self._read(key)
        if data is None:
            return None
        data.pop("approval", None)
        data["verified_by"] = tuple(data.get("verified_by", ("rescan",)))  # JSON has no tuple type
        return VerifiedCodemod(**data)

    def approval(self, key: str) -> str | None:
        """How the entry was approved, as recorded with it; ``None`` when there is no entry."""
        data = self._read(key)
        if data is None:
            return None
        approval = data.get("approval")
        return approval if isinstance(approval, str) and approval else UNRECORDED

    def approve(self, key: str, codemod: VerifiedCodemod, approval: str = HUMAN_REVIEWED) -> None:
        """Make this proven candidate a permanent, reusable entry. ``approval`` says who approved it: leave the
        default only when a human reviewed it; an automatic approval passes its own label."""
        entry = {**asdict(codemod), "approval": approval}
        self._path(key).write_text(json.dumps(entry, indent=2), encoding="utf-8")

    def _read(self, key: str) -> dict | None:
        path = self._path(key)
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def _path(self, key: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "_-" else "_" for c in key)
        return self._dir / f"{safe}{_SUFFIX}"
