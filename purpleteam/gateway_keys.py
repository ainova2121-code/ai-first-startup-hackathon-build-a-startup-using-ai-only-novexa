"""Credentials for the gateway: short-lived, scoped, budgeted keys instead of one shared secret.

A ``target`` key may be bound to one agent (``agent=``). The gateway then knows who is calling because the key
says so, instead of guessing from a prompt or trusting a header the caller sets itself: that binding is the agent's
authenticated identity. Give each agent its own key.

Each key is issued for one purpose and dies on its own: it has a role (``target`` may send model traffic,
``admin`` may read the profile; neither may do the other's job), a hard expiry, a request budget and a rate
limit, so a leaked key can spend only a little, only briefly. Several keys can be live at once, which is
how a key is rotated: issue the new one, move the target over, revoke the old one.

Only a SHA-256 digest of each secret is kept (the secrets are 256 random bits, so a plain digest is
enough), checked in constant time, and a wrong id costs the same work as a wrong secret so timing does not
reveal which ids exist. A request is counted only after its secret is proven, so an outsider can neither
probe nor drain a key's limits. Keys live in memory by default, which suits a gateway run for one
assessment; pass ``store=`` (a ``KeyStore``; ``FileKeyStore`` is the default-use one) for a long-lived
gateway, so a restart does not drop every issued credential. Only what proves a key is still the same
credential (its digest, role, expiry, budget, agent) is persisted — never the secret itself, and never the
spent-budget/rate-limit bookkeeping, which starts fresh on every restart exactly as it does today; the part
that matters is that the credential itself keeps working.

Issuing, revoking and every refused request go to the audit sink (a signed ledger in production). A flood
of bad requests writes one event per reason and key per minute, with the count it held back, so an
attacker cannot grow the log at will. Secrets never appear in an event.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from purpleteam.identity import valid_name

PREFIX = "ptgw"
TARGET, ADMIN = "target", "admin"
ROLES = (TARGET, ADMIN)
MAX_TTL, MAX_KEYS, AUDIT_WINDOW = 30 * 24 * 3600, 1000, 60
_LABEL = re.compile(r"[\w .:/-]{1,64}")
_NONE = hashlib.sha256(b"").digest()  # stands in for a missing key so a wrong id takes as long as a wrong secret

Audit = Callable[[str, dict], None]


class AuthError(Exception):
    def __init__(self, status: int, reason: str, key_id: str = "unknown") -> None:
        super().__init__(reason)
        self.status, self.reason, self.key_id = status, reason, key_id  # the id is named only once the secret is proven


@dataclass(frozen=True)
class Grant:
    key_id: str
    label: str
    role: str
    agent: str | None = None  # the agent this key is bound to: its authenticated identity


@dataclass
class _Key:
    digest: bytes
    label: str
    role: str
    expires: float
    max_requests: int
    per_minute: int
    agent: str | None = None
    used: int = 0
    tokens: float = 0.0
    stamp: float = 0.0
    revoked: bool = False


class KeyStore(Protocol):
    """Where issued keys outlive one process. Only ever asked to persist what proves a credential
    still is what it was (see the module docstring) — never the secret, never the usage counters."""

    def save(self, key_id: str, record: dict) -> None: ...
    def delete(self, key_id: str) -> None: ...
    def load_all(self) -> dict[str, dict]: ...


class FileKeyStore:
    """The default ``KeyStore``: one JSON file, written atomically. A multi-replica deployment
    needs a shared backend (Redis, a database) implementing the same three methods instead."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def load_all(self) -> dict[str, dict]:
        if not self._path.exists():
            return {}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"the key store at {self._path} does not hold the expected object")
        return data

    def save(self, key_id: str, record: dict) -> None:
        records = self.load_all()
        records[key_id] = record
        self._write(records)

    def delete(self, key_id: str) -> None:
        records = self.load_all()
        if records.pop(key_id, None) is not None:
            self._write(records)

    def _write(self, records: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(f"{self._path.suffix}.tmp")
        tmp.write_text(json.dumps(records, indent=2), encoding="utf-8")
        tmp.replace(self._path)  # atomic on POSIX and Windows alike


class GatewayKeys:
    def __init__(self, audit: Audit | None = None, clock: Callable[[], float] = time.time,
                store: KeyStore | None = None) -> None:
        self._audit, self._clock, self._store = audit, clock, store
        self._keys: dict[str, _Key] = {}
        self._reported: dict[tuple[str, str], tuple[float, int]] = {}  # (reason, key id) -> (last written, held back)
        self._lock = threading.Lock()
        if store is not None:
            self._load(store)

    def _load(self, store: KeyStore) -> None:
        """Every not-yet-expired key the store holds, its usage counters starting fresh — a
        restart must never silently invalidate a credential a customer's integration still uses,
        but it also never claims to remember exactly how much of its budget was already spent."""
        now = self._clock()
        for key_id, record in store.load_all().items():
            try:
                key = _Key(bytes.fromhex(record["digest"]), record["label"], record["role"], record["expires"],
                           record["max_requests"], record["per_minute"], record.get("agent"),
                           tokens=float(record["per_minute"]), stamp=now, revoked=bool(record.get("revoked", False)))
            except (KeyError, ValueError, TypeError) as error:
                raise ValueError(f"the key store holds a malformed record for {key_id!r}: {error}") from error
            if key.expires > now:
                self._keys[key_id] = key

    def issue(self, label: str, role: str, *, ttl_seconds: float, max_requests: int, per_minute: int = 120,
              agent: str | None = None) -> str:
        """A new key as a bearer token. It is shown once: only its digest is kept. ``agent`` binds a target key
        to one agent's identity."""
        if role not in ROLES or not _LABEL.fullmatch(label or ""):
            raise ValueError(f"role must be one of {', '.join(ROLES)} and the label 1-64 plain characters")
        if agent is not None and (role != TARGET or not valid_name(agent)):
            raise ValueError("only a target key can be bound to an agent, and the agent needs a plain name")
        if not 0 < ttl_seconds <= MAX_TTL or max_requests < 1 or per_minute < 1:
            raise ValueError(f"a key needs a lifetime up to {MAX_TTL} seconds, a request budget and a rate limit")
        now = self._clock()
        with self._lock:
            dead = [i for i, k in self._keys.items() if k.expires <= now]
            for i in dead:
                del self._keys[i]  # forget the dead
            if len(self._keys) >= MAX_KEYS:
                raise ValueError(f"at most {MAX_KEYS} live keys")
            key_id = secrets.token_hex(4)
            while key_id in self._keys:
                key_id = secrets.token_hex(4)
            secret = secrets.token_urlsafe(32)
            self._keys[key_id] = _Key(_digest(secret), label, role, now + ttl_seconds, max_requests, per_minute,
                                      agent, tokens=float(per_minute), stamp=now)
        if self._store is not None:
            for i in dead:
                self._store.delete(i)
            self._store.save(key_id, self._record_dict(key_id))
        self._record("key_issued", {"key_id": key_id, "label": label, "role": role, "agent": agent or "",
                                    "expires": now + ttl_seconds, "max_requests": max_requests, "per_minute": per_minute})
        return f"{PREFIX}_{key_id}_{secret}"

    def is_active(self, key_id: str | None) -> bool:
        """Whether a key is still valid right now (not revoked, not expired). Costs nothing: no budget or rate is used.
        The gateway asks again before it releases an answer, so a key revoked mid-request gets nothing back."""
        with self._lock:
            key = self._keys.get(key_id or "")
            return key is not None and not key.revoked and self._clock() < key.expires

    def has_active_label(self, label: str) -> bool:
        """Whether a still-valid, non-revoked key with this exact label already exists — lets a
        caller treat issuing a particular key (a bootstrap credential, say) as a one-time setup
        step with a persistent store, rather than something to repeat on every restart."""
        now = self._clock()
        with self._lock:
            return any(k.label == label and not k.revoked and k.expires > now for k in self._keys.values())

    def revoke(self, key_id: str) -> None:
        with self._lock:
            if key_id not in self._keys:
                raise ValueError("no such key")
            self._keys[key_id].revoked = True
        if self._store is not None:
            self._store.save(key_id, self._record_dict(key_id))
        self._record("key_revoked", {"key_id": key_id})

    def _record_dict(self, key_id: str) -> dict:
        key = self._keys[key_id]
        return {"digest": key.digest.hex(), "label": key.label, "role": key.role, "expires": key.expires,
               "max_requests": key.max_requests, "per_minute": key.per_minute, "agent": key.agent,
               "revoked": key.revoked}

    def authenticate(self, header: str, role: str) -> Grant:
        """The grant for an ``Authorization`` header, or ``AuthError``: 401 not proven, 403 wrong role, 429 limited."""
        try:
            return self._check(header, role)
        except AuthError as error:
            self._refuse(error)
            raise

    def _check(self, header: str, role: str) -> Grant:
        scheme, _, token = (header or "").partition(" ")
        prefix, _, rest = token.partition("_")
        key_id, _, secret = rest.partition("_")
        with self._lock:
            key = self._keys.get(key_id) if scheme == "Bearer" and prefix == PREFIX else None
            proven = hmac.compare_digest(_digest(secret), key.digest if key else _NONE) and key is not None
            if not proven:
                raise AuthError(401, "invalid")
            now = self._clock()
            if key.revoked:
                raise AuthError(401, "revoked", key_id)
            if now >= key.expires:
                raise AuthError(401, "expired", key_id)
            if key.role != role:
                raise AuthError(403, "role", key_id)
            if key.used >= key.max_requests:
                raise AuthError(429, "budget", key_id)
            key.tokens = min(float(key.per_minute), key.tokens + (now - key.stamp) * key.per_minute / 60)
            key.stamp = now
            if key.tokens < 1:
                raise AuthError(429, "rate", key_id)
            key.tokens -= 1
            key.used += 1
            return Grant(key_id, key.label, key.role, key.agent)

    def _refuse(self, error: AuthError) -> None:
        now, slot = self._clock(), (error.reason, error.key_id)
        with self._lock:
            last, held = self._reported.get(slot, (-AUDIT_WINDOW, 0))
            if now - last < AUDIT_WINDOW:
                self._reported[slot] = (last, held + 1)
                return
            if len(self._reported) > 4 * MAX_KEYS:  # unknown ids are free to invent, so the table is bounded too
                self._reported.clear()
            self._reported[slot] = (now, 0)
        self._record("auth_refused", {"reason": error.reason, "key_id": error.key_id, "held_back": held})

    def _record(self, kind: str, payload: dict) -> None:
        if self._audit is not None:
            try:
                self._audit(kind, payload)
            except Exception:  # an audit outage must never turn a refusal into an approval
                pass


def _digest(secret: str) -> bytes:
    return hashlib.sha256(secret.encode()).digest()
