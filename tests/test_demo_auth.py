"""The live demo behind its access code: nothing but the login page answers without a valid session."""

from fastapi.testclient import TestClient
from pydantic import SecretStr

from purpleteam import demo_auth, live_demo
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.run_history import RunStore

CODE = "correct-horse-battery"


def _app(tmp_path):
    return live_demo.create_app(SourceSnapshots(tmp_path / "snapshots.json"), tmp_path / "ledgerpilot",
                                RunStore(tmp_path / "runs"), access_code=SecretStr(CODE))


def _client(tmp_path, app=None, address="203.0.113.7"):
    return TestClient(app or _app(tmp_path), base_url="https://demo.test", client=(address, 50000))


def test_without_a_session_pages_go_to_the_login_and_every_api_call_is_refused(tmp_path):
    client = _client(tmp_path)
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    for method, path in (("get", "/runs"), ("get", "/stream"), ("post", "/run"), ("post", "/restore"),
                         ("get", "/static/app.js"), ("get", "/source-status")):
        assert getattr(client, method)(path).status_code == 401, path
    assert client.get("/login").headers["x-frame-options"] == "DENY"


def test_a_wrong_code_is_refused_and_never_echoed(tmp_path):
    client = _client(tmp_path)
    page = client.post("/login", data={"code": "<script>guess</script>"})
    assert "That code is not right." in page.text and "guess" not in page.text
    assert demo_auth.COOKIE not in client.cookies and client.get("/runs").status_code == 401


def test_the_right_code_opens_every_route_with_a_locked_down_cookie(tmp_path):
    client = _client(tmp_path)
    response = client.post("/login", data={"code": CODE}, follow_redirects=False)
    cookie = response.headers["set-cookie"].lower()
    assert response.headers["location"] == "/" and all(flag in cookie for flag in ("httponly", "samesite=strict", "secure"))
    assert client.get("/runs").status_code == 200 and client.get("/").status_code == 200


def test_a_forged_or_expired_session_is_refused(tmp_path):
    client = _client(tmp_path)
    client.cookies.set(demo_auth.COOKIE, "9999999999.abcd.0000")
    assert client.get("/runs").status_code == 401
    client.cookies.set(demo_auth.COOKIE, "1.abcd.0000")
    assert client.get("/runs").status_code == 401


def test_too_many_wrong_codes_lock_out_that_client_only(tmp_path):
    app = _app(tmp_path)
    attacker, judge = _client(tmp_path, app, "198.51.100.9"), _client(tmp_path, app, "203.0.113.7")
    for _ in range(demo_auth.MAX_FAILURES):
        attacker.post("/login", data={"code": "nope"})
    assert "Too many wrong codes" in attacker.post("/login", data={"code": CODE}).text
    assert attacker.get("/runs").status_code == 401
    judge.post("/login", data={"code": CODE})  # someone else guessing never locks a real visitor out
    assert judge.get("/runs").status_code == 200


def test_the_server_refuses_to_start_without_a_strong_enough_code(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "test-token")
    monkeypatch.setenv("DEMO_ACCESS_CODE", "short")
    try:
        live_demo.app()
    except RuntimeError as error:
        assert "DEMO_ACCESS_CODE" in str(error)
    else:
        raise AssertionError("started without a real access code")
