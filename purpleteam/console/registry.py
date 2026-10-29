"""The fleet of gateways this console watches. Each one's admin key is encrypted at rest and
decrypted only for the poller -- list_targets() and get_target() never return it.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from purpleteam.console import crypto
from purpleteam.console.db.repositories import TargetRepository


@dataclass(frozen=True)
class Target:
    id: str
    name: str
    base_url: str
    log_id: str | None
    last_seq: int
    status: str
    last_error: str | None
    polled_at: float | None


def _target(row: dict) -> Target:
    return Target(row["id"], row["name"], row["base_url"], row["log_id"], row["last_seq"],
                 row["status"], row["last_error"], row["polled_at"])


class FleetRegistry:
    def __init__(self, targets: TargetRepository, key: bytes) -> None:
        self._targets, self._key = targets, key

    def add_target(self, name: str, base_url: str, admin_key: str) -> str:
        target_id = uuid.uuid4().hex
        self._targets.add(target_id, name, base_url, crypto.encrypt(admin_key, self._key), time.time())
        return target_id

    def list_targets(self) -> list[Target]:
        return [_target(row) for row in self._targets.list_all()]

    def get_target(self, target_id: str) -> Target | None:
        row = self._targets.get(target_id)
        return _target(row) if row else None

    def credentials_for(self, target_id: str) -> tuple[str, str] | None:
        """(base_url, decrypted admin key) for the poller only -- nothing else needs the secret."""
        row = self._targets.get(target_id)
        if row is None:
            return None
        return row["base_url"], crypto.decrypt(row["admin_key_enc"], self._key)

    def remove_target(self, target_id: str) -> None:
        self._targets.remove(target_id)

    def record_poll_result(self, target_id: str, *, log_id: str | None, last_seq: int, status: str,
                           last_error: str | None) -> None:
        self._targets.record_poll_result(target_id, log_id=log_id, last_seq=last_seq, status=status,
                                         last_error=last_error, polled_at=time.time())

    def set_status(self, target_id: str, *, size: int, safe_to_ship: bool | None, sealed_at: float | None,
                  breach_kinds_json: str) -> None:
        self._targets.set_status(target_id, size=size, safe_to_ship=safe_to_ship, sealed_at=sealed_at,
                                 breach_kinds_json=breach_kinds_json, updated_at=time.time())

    def get_status(self, target_id: str) -> dict | None:
        return self._targets.get_status(target_id)
