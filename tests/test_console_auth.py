"""Console user login/session auth: a role is looked up fresh on every request, not snapshotted
at login, so a demotion takes effect on the very next request rather than only after re-login."""

import pytest

from purpleteam.console.auth import ADMIN, ANALYST, ConsoleAuth, ConsoleAuthError, hash_password, verify_password
from purpleteam.console.db.repositories import SessionRepository, UserRepository, connect


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def _auth(tmp_path):
    conn = connect(tmp_path / "console.db")
    users, sessions = UserRepository(conn), SessionRepository(conn)
    clock = Clock()
    return ConsoleAuth(users, sessions, clock), users, clock


def _add_user(users, id="u1", email="a@example.com", password="correct horse", role=ADMIN) -> None:
    users.add(id, email, hash_password(password), role, 0.0)


def test_password_hashing_round_trips_and_rejects_wrong_password():
    stored = hash_password("correct horse")
    assert verify_password("correct horse", stored)
    assert not verify_password("wrong", stored)


def test_the_plaintext_password_never_appears_in_the_stored_hash():
    assert "correct horse" not in hash_password("correct horse")


def test_login_succeeds_with_the_right_password_and_the_session_authenticates(tmp_path):
    auth, users, _ = _auth(tmp_path)
    _add_user(users)
    token = auth.login("a@example.com", "correct horse")
    session = auth.authenticate(token)
    assert (session.email, session.role) == ("a@example.com", ADMIN)


def test_login_fails_with_the_wrong_password_or_unknown_email(tmp_path):
    auth, users, _ = _auth(tmp_path)
    _add_user(users)
    with pytest.raises(ConsoleAuthError) as error:
        auth.login("a@example.com", "wrong")
    assert error.value.status == 401
    with pytest.raises(ConsoleAuthError):
        auth.login("nobody@example.com", "correct horse")


def test_authenticate_rejects_missing_or_unknown_tokens(tmp_path):
    auth, _, _ = _auth(tmp_path)
    with pytest.raises(ConsoleAuthError):
        auth.authenticate(None)
    with pytest.raises(ConsoleAuthError):
        auth.authenticate("nonsense-token")


def test_a_session_expires(tmp_path):
    auth, users, clock = _auth(tmp_path)
    _add_user(users)
    token = auth.login("a@example.com", "correct horse")
    clock.now += 13 * 3600  # past the 12h session TTL
    with pytest.raises(ConsoleAuthError):
        auth.authenticate(token)


def test_logout_invalidates_the_session(tmp_path):
    auth, users, _ = _auth(tmp_path)
    _add_user(users)
    token = auth.login("a@example.com", "correct horse")
    auth.logout(token)
    with pytest.raises(ConsoleAuthError):
        auth.authenticate(token)


def test_a_role_change_takes_effect_on_the_very_next_request(tmp_path):
    auth, users, _ = _auth(tmp_path)
    _add_user(users, role=ADMIN)
    token = auth.login("a@example.com", "correct horse")
    assert auth.authenticate(token).role == ADMIN

    users._conn.execute("UPDATE users SET role = ? WHERE id = 'u1'", (ANALYST,))

    assert auth.authenticate(token).role == ANALYST  # same token, no re-login, role already updated


def test_a_disabled_users_existing_session_stops_working(tmp_path):
    auth, users, _ = _auth(tmp_path)
    _add_user(users)
    token = auth.login("a@example.com", "correct horse")

    users._conn.execute("UPDATE users SET disabled = 1 WHERE id = 'u1'")

    with pytest.raises(ConsoleAuthError):
        auth.authenticate(token)
