"""The fleet of gateways this console watches. Each one's admin key is encrypted at rest and
decrypted only for the poller -- list_targets() and get_target() never return it.
"""

from __future__ import annotations

import ipaddress
import json
import time
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from purpleteam.audit.stream import StreamVerifier
from purpleteam.console import crypto
from purpleteam.console.db.repositories import TargetRepository

OPERATOR, FIRST_USE = "operator", "first use"  # who pinned a gateway's keys
_TRUST_FIELDS = ("keys", "revoked", "hardware")


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
    trust_source: str | None = None  # None until the gateway's keys are pinned


def _target(row: dict) -> Target:
    return Target(row["id"], row["name"], row["base_url"], row["log_id"], row["last_seq"],
                 row["status"], row["last_error"], row["polled_at"], row.get("trust_source"))


def check_base_url(url: str) -> str:
    """A gateway is reached over https, so its admin key and evidence never cross the network in the clear; plain
    http only to this machine's own loopback (a local trial). Raises ValueError otherwise."""
    parts = urlsplit(url.strip())
    host = parts.hostname or ""
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if (parts.scheme == "https" or (parts.scheme == "http" and loopback)) and host and not (
            parts.username or parts.password or parts.query or parts.fragment):
        return url.strip().rstrip("/")
    raise ValueError("the base URL must be https (plain http only to this machine's loopback), with no "
                     "credentials, query or fragment")


def pinnable(trust: object) -> dict:
    """The public part of a gateway's trust bundle, refused (ValueError) unless every key in it is well formed."""
    if not isinstance(trust, dict):
        raise ValueError("a trust bundle is a JSON object with the gateway's public keys")
    kept = {field: trust[field] for field in _TRUST_FIELDS if trust.get(field)}
    StreamVerifier(kept)  # the same check every later page is verified with
    return kept


class FleetRegistry:
    def __init__(self, targets: TargetRepository, key: bytes) -> None:
        self._targets, self._key = targets, key

    def add_target(self, name: str, base_url: str, admin_key: str, trust: dict | None = None) -> str:
        """``trust``: the gateway's public keys, pasted by the operator. Without it they are pinned on first use."""
        target_id = uuid.uuid4().hex
        pinned = None if trust is None else json.dumps(pinnable(trust))
        self._targets.add(target_id, name, base_url, crypto.encrypt(admin_key, self._key), time.time(),
                          pinned, OPERATOR if pinned else None)
        return target_id

    def trust_for(self, target_id: str) -> dict | None:
        row = self._targets.get(target_id)
        return json.loads(row["trust_json"]) if row and row["trust_json"] else None

    def pin_trust(self, target_id: str, trust: dict, source: str) -> dict:
        """Pin ``trust`` (validated) for this target; its whole log is then verified again from the first event."""
        pinned = pinnable(trust)
        self._targets.pin_trust(target_id, json.dumps(pinned), source)
        return pinned

    def verifier_state(self, target_id: str) -> dict | None:
        row = self._targets.get(target_id)
        return json.loads(row["verifier_json"]) if row and row["verifier_json"] else None

    def save_verifier(self, target_id: str, state: dict) -> None:
        self._targets.save_verifier(target_id, json.dumps(state))

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
