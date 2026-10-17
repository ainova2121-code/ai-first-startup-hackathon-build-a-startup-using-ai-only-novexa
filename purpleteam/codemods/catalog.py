"""A persisted catalog of human-approved codemods, reused verbatim without ever calling the LLM
or re-verifying again for the exact same pattern.

Keyed by (kind, the exact original source text) rather than kind alone: a stored fix is proven
correct only for the specific snippet it was verified against, so it is only ever reused when
that exact snippet recurs (a literal pattern copy-pasted elsewhere, or the same file re-scanned
later) — never applied to a different piece of code just because the finding kind matches.

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


def pattern_key(kind: str, original: str) -> str:
    digest = hashlib.sha256(original.encode("utf-8")).hexdigest()[:16]
    return f"{kind}_{digest}"


class CodemodCatalog:
    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str) -> VerifiedCodemod | None:
        path = self._path(key)
        if not path.exists():
            return None
        return VerifiedCodemod(**json.loads(path.read_text(encoding="utf-8")))

    def approve(self, key: str, codemod: VerifiedCodemod) -> None:
        """A human has reviewed this proven candidate; it becomes a permanent, reusable entry."""
        self._path(key).write_text(json.dumps(asdict(codemod), indent=2), encoding="utf-8")

    def _path(self, key: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "_-" else "_" for c in key)
        return self._dir / f"{safe}{_SUFFIX}"
