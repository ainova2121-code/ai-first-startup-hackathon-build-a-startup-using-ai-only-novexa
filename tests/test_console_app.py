"""The console's FastAPI app: login, RBAC boundaries, and main.py's refuse-to-start config."""

import re

import httpx
import pytest
from fastapi.testclient import TestClient

from purpleteam.console.app import create_console
from purpleteam.console.auth import ANALYST, AUDITOR, hash_password
from purpleteam.console.db.repositories import TargetRepository, UserRepository, connect
from purpleteam.console.main import build_app


def _unreachable_client() -> httpx.AsyncClient:
    """No real gateway exists in these tests -- fail fast and deterministically instead of
    letting a route's live fetch attempt real DNS against a fake base_url."""
    def handler(request):
        raise httpx.ConnectError("test: no real gateway")
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _app(tmp_path, client=None):
    return create_console(tmp_path / "console.db", secret_key="test-secret", client=client or _unreachable_client())


def _signed_in(app, email="admin@local", password=None) -> TestClient:
    web = TestClient(app)
    password = password or app.state.bootstrap_password
    response = web.post("/login", data={"email": email, "password": password})
    assert response.status_code in (200, 303)
    return web


def test_bootstrap_admin_is_created_once_and_can_log_in(tmp_path):
    app = _app(tmp_path)
    assert app.state.bootstrap_password
    web = _signed_in(app)
    assert web.get("/").status_code == 200


def test_a_second_build_against_the_same_db_does_not_rebootstrap(tmp_path):
    _app(tmp_path)  # the first build bootstraps the database
    app2 = _app(tmp_path)
    assert app2.state.bootstrap_password is None


def test_login_page_renders_and_wrong_password_is_refused(tmp_path):
    app = _app(tmp_path)
    web = TestClient(app)
    assert web.get("/login").status_code == 200
    response = web.post("/login", data={"email": "admin@local", "password": "wrong"})
    assert response.status_code == 401


def test_unauthenticated_requests_are_401_not_a_silent_redirect_loop(tmp_path):
    app = _app(tmp_path)
    web = TestClient(app)
    assert web.get("/").status_code == 401
    assert web.get("/targets").status_code == 401


def test_logout_actually_ends_the_session(tmp_path):
    app = _app(tmp_path)
    web = _signed_in(app)
    assert web.get("/").status_code == 200
    web.post("/logout")
    assert web.get("/").status_code == 401


def _add_user(db_path, id, email, password, role) -> None:
    """A second connection to the same on-disk SQLite file -- WAL mode lets this coexist with the
    app's own connection, exactly the concurrent-access pattern the console relies on in general."""
    UserRepository(connect(db_path)).add(id, email, hash_password(password), role, 0.0)


def test_an_analyst_cannot_manage_the_fleet_or_users(tmp_path):
    app = _app(tmp_path)
    _add_user(tmp_path / "console.db", "u1", "analyst@local", "analyst-pw", ANALYST)
    web = _signed_in(app, "analyst@local", "analyst-pw")

    assert web.get("/").status_code == 200  # the dashboard is fine for every role
    assert web.get("/targets").status_code == 403
    assert web.post("/targets", data={"name": "x", "base_url": "https://x", "admin_key": "k"}).status_code == 403
    assert web.get("/users").status_code == 403
    assert web.post("/users", data={"email": "y@x", "password": "pw", "role": "admin"}).status_code == 403


def test_an_auditor_sees_evidence_views_but_not_raw_activity(tmp_path):
    db_path = tmp_path / "console.db"
    app = _app(tmp_path)
    admin_web = _signed_in(app)
    target_id = _register_target(db_path, admin_web)
    _add_user(db_path, "u1", "auditor@local", "auditor-pw", AUDITOR)
    web = _signed_in(app, "auditor@local", "auditor-pw")

    assert web.get(f"/targets/{target_id}").status_code == 200       # evidence-shaped view: allowed
    assert web.get(f"/targets/{target_id}/activity").status_code == 403  # raw operational detail: not allowed
    assert web.get("/targets").status_code == 403  # fleet management stays admin-only


def test_an_admin_can_manage_the_fleet_and_users(tmp_path):
    app = _app(tmp_path)
    web = _signed_in(app)

    assert web.get("/targets").status_code == 200
    assert web.get("/users").status_code == 200
    response = web.post("/users", data={"email": "new@local", "password": "a-password", "role": "analyst"},
                        follow_redirects=False)
    assert response.status_code == 303


def test_a_quote_in_a_target_name_cannot_break_out_of_the_remove_buttons_inline_js(tmp_path):
    """A target name is operator-chosen, untrusted text (XSS, not SQL injection, is the relevant
    threat here: it ends up in rendered HTML). The old template interpolated it straight into a
    single-quoted JS string inside an onsubmit="" attribute -- HTML-escaping a `'` protects the
    attribute boundary but the browser decodes it back to a literal quote before running the JS,
    so it broke out of the string. The fix moves the name into a data-* attribute instead, which
    is never re-parsed as JS source."""
    app = _app(tmp_path)
    web = _signed_in(app)
    payload = "x');fetch('/users',{method:'POST'});//"
    web.post("/targets", data={"name": payload, "base_url": "https://gw.example", "admin_key": "k"})

    body = web.get("/targets").text

    assert "onsubmit=\"return confirm('Remove ' + this.dataset.targetName" in body
    assert f"data-target-name=\"{payload}\"" not in body  # must be HTML-escaped, not raw
    assert "fetch(&#39;/users&#39;" in body or "fetch('/users'" not in body  # never raw, executable JS


def _register_target(db_path, web: TestClient) -> str:
    response = web.post("/targets", data={"name": "demo", "base_url": "https://gw.example", "admin_key": "k"},
                        follow_redirects=False)
    assert response.status_code == 303
    return TargetRepository(connect(db_path)).list_all()[0]["id"]


def test_deploy_generates_a_script_and_registers_the_target_immediately(tmp_path):
    db_path = tmp_path / "console.db"
    app = _app(tmp_path)
    web = _signed_in(app)

    response = web.post("/targets/deploy", data={"name": "acme-ap", "domain": "gateway.acme.example"})
    assert response.status_code == 200
    assert "docker compose up -d gateway tls" in response.text
    assert "GATEWAY_BOOTSTRAP_ADMIN_KEY=" in response.text

    rows = TargetRepository(connect(db_path)).list_all()
    assert len(rows) == 1 and rows[0]["name"] == "acme-ap" and rows[0]["base_url"] == "https://gateway.acme.example"


def test_deploy_rejects_a_domain_with_a_scheme_or_path(tmp_path):
    app = _app(tmp_path)
    web = _signed_in(app)

    response = web.post("/targets/deploy", data={"name": "x", "domain": "https://gateway.acme.example"})
    assert response.status_code == 400 and "no scheme or path" in response.text
    assert TargetRepository(connect(tmp_path / "console.db")).list_all() == []


def test_deploy_is_admin_only(tmp_path):
    app = _app(tmp_path)
    _add_user(tmp_path / "console.db", "u1", "analyst@local", "analyst-pw", ANALYST)
    web = _signed_in(app, "analyst@local", "analyst-pw")
    assert web.post("/targets/deploy", data={"name": "x", "domain": "gw.example"}).status_code == 403


def test_build_app_refuses_without_console_secret_key(monkeypatch, tmp_path):
    monkeypatch.delenv("CONSOLE_SECRET_KEY", raising=False)
    monkeypatch.setenv("CONSOLE_DB_PATH", str(tmp_path / "console.db"))
    with pytest.raises(RuntimeError, match="CONSOLE_SECRET_KEY"):
        build_app()


def test_build_app_refuses_without_console_db_path(monkeypatch, tmp_path):
    monkeypatch.delenv("CONSOLE_DB_PATH", raising=False)
    monkeypatch.setenv("CONSOLE_SECRET_KEY", "test-secret")
    with pytest.raises(RuntimeError, match="CONSOLE_DB_PATH"):
        build_app()


def test_the_stream_route_requires_auth(tmp_path):
    """The detailed SSE formatting logic is covered directly in test_console_sse.py. The body here
    never completes (the generator runs forever), which neither TestClient nor ASGITransport can
    read from without hanging past their first chunk -- so this checks only the one thing that
    does not require reading the stream's body: an unauthenticated request is refused before the
    route ever gets to return it. The authenticated, live path is proven by the end-to-end manual
    check in the implementation plan (two real gateways, a dashboard row updating live)."""
    app = _app(tmp_path)
    assert TestClient(app).get("/stream").status_code == 401


def test_build_app_prints_the_bootstrap_password_once(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CONSOLE_DB_PATH", str(tmp_path / "console.db"))
    monkeypatch.setenv("CONSOLE_SECRET_KEY", "test-secret")
    build_app()
    err = capsys.readouterr().err
    assert re.search(r"admin@local.*password:\s+\S+", err)
