"""The console's own small store: a fleet registry, console user accounts, and their sessions.

Never a copy of ledger events -- the signed ledger on each gateway stays the one source of truth
for evidence; ``target_status`` is a derived cache only, rebuildable from scratch by re-polling.
"""

import sqlite3
from pathlib import Path
from typing import Any

Row = dict[str, Any]

_SCHEMA = Path(__file__).with_name("schema.sql")


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    conn.row_factory = lambda cursor, row: {col[0]: value for col, value in zip(cursor.description, row)}
    conn.execute("PRAGMA journal_mode=WAL")  # the poller writes while web requests read, concurrently
    conn.executescript(_SCHEMA.read_text())
    return conn


class _Repository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def _one(self, sql: str, *params: Any) -> Row | None:
        return self._conn.execute(sql, params).fetchone()

    def _all(self, sql: str, *params: Any) -> list[Row]:
        return self._conn.execute(sql, params).fetchall()

    def _write(self, sql: str, *params: Any) -> None:
        self._conn.execute(sql, params)


class TargetRepository(_Repository):
    def add(self, id: str, name: str, base_url: str, admin_key_enc: bytes, created_at: float) -> None:
        self._write(
            "INSERT INTO targets (id, name, base_url, admin_key_enc, created_at) VALUES (?, ?, ?, ?, ?)",
            id, name, base_url, admin_key_enc, created_at)

    def get(self, id: str) -> Row | None:
        return self._one("SELECT * FROM targets WHERE id = ?", id)

    def list_all(self) -> list[Row]:
        return self._all("SELECT * FROM targets ORDER BY created_at")

    def remove(self, id: str) -> None:
        self._write("DELETE FROM target_status WHERE target_id = ?", id)
        self._write("DELETE FROM targets WHERE id = ?", id)

    def record_poll_result(self, id: str, *, log_id: str | None, last_seq: int, status: str,
                           last_error: str | None, polled_at: float) -> None:
        self._write(
            "UPDATE targets SET log_id = ?, last_seq = ?, status = ?, last_error = ?, polled_at = ? WHERE id = ?",
            log_id, last_seq, status, last_error, polled_at, id)

    def set_status(self, target_id: str, *, size: int, safe_to_ship: bool | None, sealed_at: float | None,
                  breach_kinds_json: str, updated_at: float) -> None:
        self._write(
            """INSERT INTO target_status (target_id, size, safe_to_ship, sealed_at, breach_kinds_json, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(target_id) DO UPDATE SET
                   size = excluded.size, safe_to_ship = excluded.safe_to_ship, sealed_at = excluded.sealed_at,
                   breach_kinds_json = excluded.breach_kinds_json, updated_at = excluded.updated_at""",
            target_id, size, safe_to_ship, sealed_at, breach_kinds_json, updated_at)

    def get_status(self, target_id: str) -> Row | None:
        return self._one("SELECT * FROM target_status WHERE target_id = ?", target_id)


class UserRepository(_Repository):
    def add(self, id: str, email: str, password_hash: str, role: str, created_at: float) -> None:
        self._write("INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                    id, email, password_hash, role, created_at)

    def get(self, id: str) -> Row | None:
        return self._one("SELECT * FROM users WHERE id = ?", id)

    def get_by_email(self, email: str) -> Row | None:
        return self._one("SELECT * FROM users WHERE email = ? AND disabled = 0", email)

    def list_all(self) -> list[Row]:
        return self._all("SELECT * FROM users ORDER BY created_at")

    def count(self) -> int:
        return self._one("SELECT COUNT(*) AS n FROM users")["n"]


class SessionRepository(_Repository):
    def add(self, token_digest: str, user_id: str, expires_at: float, created_at: float) -> None:
        self._write("INSERT INTO sessions (token_digest, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
                    token_digest, user_id, expires_at, created_at)

    def get(self, token_digest: str) -> Row | None:
        return self._one("SELECT * FROM sessions WHERE token_digest = ?", token_digest)

    def delete(self, token_digest: str) -> None:
        self._write("DELETE FROM sessions WHERE token_digest = ?", token_digest)
