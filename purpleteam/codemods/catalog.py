"""A persisted catalog of approved codemods, reused verbatim without ever calling the LLM
or re-verifying again for the exact same pattern.

Keyed by (kind, the exact original source text) rather than kind alone: a stored fix is proven
correct only for the specific snippet it was verified against, so it is only ever reused when
that exact snippet recurs (a literal pattern copy-pasted elsewhere, or the same file re-scanned
later) — never applied to a different piece of code just because the finding kind matches.

Every entry records how it was approved: by a human, or automatically by verification. A reused entry keeps
that label, so an auto-approved fix is never presented as human-reviewed, and an entry written before
approvals were recorded is treated as not human-reviewed. The label is believed only under the operator's seal
(``purpleteam.operator_seal``): an entry anyone else wrote or edited still gets reused, but as not human-reviewed,
so it must pass the full re-verification before it can touch a file.

Lives under a directory the operator owns, not bundled with the platform package: BYOC, same as
every other piece of persisted platform state.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from purpleteam.codemods.base import VerifiedCodemod
from purpleteam.operator_seal import OperatorSeal

_SUFFIX = ".codemod.json"
_PURPOSE = "codemod-catalog"
HUMAN_REVIEWED = "human-reviewed"
UNRECORDED = "approval not recorded (an older catalog entry), treated as not human-reviewed"
UNSEALED = "not sealed by this operator (written or edited outside the platform), treated as not human-reviewed"


def pattern_key(kind: str, original: str) -> str:
    digest = hashlib.sha256(original.encode("utf-8")).hexdigest()[:16]
    return f"{kind}_{digest}"


class CodemodCatalog:
    def __init__(self, directory: str | Path, seal: OperatorSeal | None = None) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._seal = seal

    def get(self, key: str) -> VerifiedCodemod | None:
        data = self._read(key)
        if data is None:
            return None
        data.pop("approval", None)
        data.pop("seal", None)
        data["verified_by"] = tuple(data.get("verified_by", ("rescan",)))  # JSON has no tuple type
        return VerifiedCodemod(**data)

    def approval(self, key: str) -> str | None:
        """How the entry was approved, as recorded with it and sealed by this operator; ``None`` when there is
        no entry. An unsealed or altered entry never claims to be human-reviewed."""
        data = self._read(key)
        if data is None:
            return None
        seal = data.pop("seal", None)
        sealed = self._sealer().verify(_PURPOSE, {"key": key, **data}, seal)
        approval = data.get("approval")
        if not (isinstance(approval, str) and approval):
            return UNRECORDED
        return approval if sealed else UNSEALED

    def approve(self, key: str, codemod: VerifiedCodemod, approval: str = HUMAN_REVIEWED) -> None:
        """Make this proven candidate a permanent, reusable entry. ``approval`` says who approved it: leave the
        default only when a human reviewed it; an automatic approval passes its own label."""
        entry = {**asdict(codemod), "approval": approval}
        entry["seal"] = self._sealer().seal(_PURPOSE, {"key": key, **entry})
        self._path(key).write_text(json.dumps(entry, indent=2), encoding="utf-8")

    def _sealer(self) -> OperatorSeal:
        if self._seal is None:
            self._seal = OperatorSeal.default()
        return self._seal

    def _read(self, key: str) -> dict | None:
        path = self._path(key)
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def _path(self, key: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "_-" else "_" for c in key)
        return self._dir / f"{safe}{_SUFFIX}"
