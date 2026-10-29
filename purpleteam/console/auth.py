"""Console user accounts and sessions: three roles, nothing fancier.

Mirrors gateway_keys.py's shape deliberately -- only a digest of a secret is ever stored, checked
in constant time, failures carry a status and a reason. This module takes plain strings, never a
FastAPI Request; the per-route role check (reading a cookie, raising HTTPException) belongs in the
app layer, exactly where gateway.py's own authorize() lives rather than inside gateway_keys.py.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from purpleteam.console.db.repositories import SessionRepository, UserRepository

ADMIN, ANALYST, AUDITOR = "admin", "analyst", "auditor"
ROLES = (ADMIN, ANALYST, AUDITOR)
SESSION_TTL = 12 * 3600
_ITERATIONS = 310_000  # OWASP's 2023 minimum for PBKDF2-HMAC-SHA256


class ConsoleAuthError(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status, self.reason = status, reason


@dataclass(frozen=True)
class Session:
    user_id: str
    email: str
    role: str


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), _ITERATIONS).hex()
    return f"pbkdf2_sha256${_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, digest = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)).hex()
    return hmac.compare_digest(candidate, digest)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class ConsoleAuth:
    def __init__(self, users: UserRepository, sessions: SessionRepository, clock: Callable[[], float] = time.time) -> None:
        self._users, self._sessions, self._clock = users, sessions, clock

    def login(self, email: str, password: str) -> str:
        user = self._users.get_by_email(email)
        if user is None or not verify_password(password, user["password_hash"]):
            raise ConsoleAuthError(401, "invalid email or password")
        token = secrets.token_urlsafe(32)
        now = self._clock()
        self._sessions.add(_digest(token), user["id"], now + SESSION_TTL, now)
        return token

    def authenticate(self, token: str | None) -> Session:
        if not token:
            raise ConsoleAuthError(401, "not signed in")
        row = self._sessions.get(_digest(token))
        if row is None or row["expires_at"] < self._clock():
            raise ConsoleAuthError(401, "session expired or unknown")
        user = self._users.get(row["user_id"])
        if user is None or user["disabled"]:
            raise ConsoleAuthError(401, "account no longer active")
        return Session(user["id"], user["email"], user["role"])

    def logout(self, token: str) -> None:
        self._sessions.delete(_digest(token))
