"""The live demo behind its passwordless login: nothing but the login page answers without a session,
one click opens every route with a locked-down cookie, and logging out ends the session."""

from fastapi.testclient import TestClient

from purpleteam import demo_auth, live_demo
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.run_history import RunStore


def _app(tmp_path):
    return live_demo.create_app(SourceSnapshots(tmp_path / "snapshots.json"), tmp_path / "ledgerpilot",
                                RunStore(tmp_path / "runs"), login=True)


def _client(tmp_path, app=None, address="203.0.113.7"):
    return TestClient(app or _app(tmp_path), base_url="https://demo.test", client=(address, 50000))


def test_without_a_session_pages_go_to_the_login_and_every_api_call_is_refused(tmp_path):
    client = _client(tmp_path)
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    for method, path in (("get", "/runs"), ("get", "/stream"), ("post", "/run"), ("post", "/restore"),
                         ("get", "/static/app.js"), ("get", "/source-status")):
        assert getattr(client, method)(path).status_code == 401, path
    assert client.get("/login").headers["x-frame-options"] == "DENY"


def test_the_synthetic_corpus_json_is_public(tmp_path):
    assert _client(tmp_path).get("/custom-dataset.json").status_code == 200


def test_one_click_opens_every_route_with_a_locked_down_cookie(tmp_path):
    client = _client(tmp_path)
    response = client.post("/login", follow_redirects=False)  # no code to type
    cookie = response.headers["set-cookie"].lower()
    assert response.headers["location"] == "/target"  # the target overview first, then the console
    assert all(f in cookie for f in ("httponly", "samesite=strict", "secure"))
    assert client.get("/runs").status_code == 200 and client.get("/").status_code == 200


def test_a_forged_or_expired_session_is_refused(tmp_path):
    client = _client(tmp_path)
    client.cookies.set(demo_auth.COOKIE, "9999999999.abcd.0000")
    assert client.get("/runs").status_code == 401
    client.cookies.set(demo_auth.COOKIE, "1.abcd.0000")
    assert client.get("/runs").status_code == 401


def test_logout_clears_the_session_and_restores_the_target(tmp_path):
    repo = tmp_path / "ledgerpilot"
    repo.mkdir()
    (repo / "mod.py").write_bytes(b"patched\n")  # exact bytes, as the platform writes them (no newline translation)
    snapshots = SourceSnapshots(tmp_path / "snapshots.json")
    snapshots.record("mod.py", "original\n", "patched\n")  # the platform edited this file
    client = _client(tmp_path, live_demo.create_app(snapshots, repo, RunStore(tmp_path / "runs"), login=True))
    client.post("/login")

    response = client.post("/logout")

    assert response.status_code == 200 and "mod.py" in response.json()["restored"]
    assert (repo / "mod.py").read_bytes() == b"original\n"  # patches rolled back to the original state
    assert client.get("/runs").status_code == 401  # the session is over


def test_the_app_starts_on_the_login_page_by_default_however_it_is_created(tmp_path):
    app = live_demo.create_app(SourceSnapshots(tmp_path / "snapshots.json"), tmp_path / "ledgerpilot",
                               RunStore(tmp_path / "runs"))  # no login argument: the default must be the login page
    client = _client(tmp_path, app)
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/runs").status_code == 401
