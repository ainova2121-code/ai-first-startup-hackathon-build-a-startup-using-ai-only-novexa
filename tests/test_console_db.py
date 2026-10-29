"""The console's own SQLite store: a fleet registry, console users, their sessions."""

from purpleteam.console.db.repositories import SessionRepository, TargetRepository, UserRepository, connect


def _conn(tmp_path):
    return connect(tmp_path / "console.db")


def test_a_target_can_be_added_fetched_and_removed(tmp_path):
    targets = TargetRepository(_conn(tmp_path))
    targets.add("t1", "demo", "https://gw.example", b"cipher-bytes", 1000.0)

    row = targets.get("t1")
    assert row["name"] == "demo" and row["admin_key_enc"] == b"cipher-bytes" and row["last_seq"] == -1

    targets.remove("t1")
    assert targets.get("t1") is None


def test_listing_is_oldest_first(tmp_path):
    targets = TargetRepository(_conn(tmp_path))
    targets.add("t2", "second", "https://b", b"x", 2000.0)
    targets.add("t1", "first", "https://a", b"x", 1000.0)
    assert [row["id"] for row in targets.list_all()] == ["t1", "t2"]


def test_poll_result_and_status_round_trip(tmp_path):
    targets = TargetRepository(_conn(tmp_path))
    targets.add("t1", "demo", "https://gw.example", b"x", 1000.0)

    targets.record_poll_result("t1", log_id="abc123", last_seq=4, status="ok", last_error=None, polled_at=1010.0)
    row = targets.get("t1")
    assert (row["log_id"], row["last_seq"], row["status"]) == ("abc123", 4, "ok")

    targets.set_status("t1", size=5, safe_to_ship=True, sealed_at=1005.0, breach_kinds_json="[]", updated_at=1010.0)
    status = targets.get_status("t1")
    assert status["size"] == 5 and status["safe_to_ship"] == 1

    # a second poll overwrites, not duplicates
    targets.set_status("t1", size=9, safe_to_ship=False, sealed_at=1020.0, breach_kinds_json='["injection_action"]',
                       updated_at=1020.0)
    status = targets.get_status("t1")
    assert status["size"] == 9 and status["safe_to_ship"] == 0


def test_removing_a_target_removes_its_status(tmp_path):
    targets = TargetRepository(_conn(tmp_path))
    targets.add("t1", "demo", "https://gw.example", b"x", 1000.0)
    targets.set_status("t1", size=1, safe_to_ship=True, sealed_at=None, breach_kinds_json="[]", updated_at=1000.0)

    targets.remove("t1")

    assert targets.get_status("t1") is None


def test_users_and_sessions(tmp_path):
    conn = _conn(tmp_path)
    users, sessions = UserRepository(conn), SessionRepository(conn)
    assert users.count() == 0

    users.add("u1", "a@example.com", "hash", "admin", 1000.0)
    assert users.count() == 1
    assert users.get_by_email("a@example.com")["role"] == "admin"
    assert users.get("u1")["email"] == "a@example.com"

    sessions.add("digest1", "u1", 2000.0, 1000.0)
    assert sessions.get("digest1")["user_id"] == "u1"
    sessions.delete("digest1")
    assert sessions.get("digest1") is None


def test_a_disabled_user_is_not_found_by_email(tmp_path):
    conn = _conn(tmp_path)
    users = UserRepository(conn)
    users.add("u1", "a@example.com", "hash", "admin", 1000.0)
    conn.execute("UPDATE users SET disabled = 1 WHERE id = 'u1'")
    assert users.get_by_email("a@example.com") is None
    assert users.get("u1")["disabled"] == 1  # still reachable by id, just not for login
