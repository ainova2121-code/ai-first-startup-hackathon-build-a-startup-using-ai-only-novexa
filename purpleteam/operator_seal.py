"""A keyed seal on the operator's own state files -- approved codemods, snapshots of edited target source -- so a
file someone else wrote or edited is caught before the platform acts on it.

HMAC-SHA256 under a secret kept outside the directory it protects: ``PURPLETEAM_OPERATOR_KEY`` (64 hex characters),
else the key file ``PURPLETEAM_OPERATOR_KEY_FILE``, by default ``~/.purpleteam/operator.key``, created owner-only
with 32 random bytes on first use. Target processes never see it (``targets.process`` strips every ``PURPLETEAM_``
variable). It stops anyone who can write the operator directory but cannot read the operator's own key; it does
not stop code already running as the operator.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from purpleteam.audit.hashing import canonical

KEY_BYTES = 32


class OperatorSeal:
    def __init__(self, key: bytes) -> None:
        if len(key) < KEY_BYTES:
            raise ValueError(f"the operator key must be at least {KEY_BYTES} bytes")
        self._key = key

    @classmethod
    def default(cls) -> "OperatorSeal":
        """The operator's key from the environment, else its key file (created the first time)."""
        configured = os.environ.get("PURPLETEAM_OPERATOR_KEY")
        if configured:
            try:
                return cls(bytes.fromhex(configured))
            except ValueError:
                raise ValueError("PURPLETEAM_OPERATOR_KEY must be at least 64 hex characters") from None
        path = Path(os.environ.get("PURPLETEAM_OPERATOR_KEY_FILE", Path.home() / ".purpleteam" / "operator.key"))
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(secrets.token_bytes(KEY_BYTES))
            except FileExistsError:  # another process created it first: use theirs
                pass
        return cls(path.read_bytes())

    def seal(self, purpose: str, data: object) -> str:
        """The seal over ``data`` for one ``purpose``, so a seal made for one file never fits another."""
        return hmac.new(self._key, purpose.encode("utf-8") + b"\x00" + canonical(data), hashlib.sha256).hexdigest()

    def verify(self, purpose: str, data: object, seal: object) -> bool:
        return isinstance(seal, str) and hmac.compare_digest(self.seal(purpose, data), seal)
