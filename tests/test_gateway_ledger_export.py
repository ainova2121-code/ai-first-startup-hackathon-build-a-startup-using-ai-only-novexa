"""/ledger/export: the one HTTP read a fleet console needs -- BYOC means it has no filesystem
access to a customer's gateway host, only this paginated, admin-only, bounded read."""

from fastapi.testclient import TestClient
from pydantic import SecretStr

from purpleteam.audit.ledger import AuditLedger
from purpleteam.gateway import MAX_EXPORT, Provider, create_gateway
from purpleteam.gateway_keys import ADMIN, TARGET, GatewayKeys
from purpleteam.gateway_observer import GatewayObserver

_BIG = {"ttl_seconds": 3600, "max_requests": 10**6, "per_minute": 10**6}


def _app(tmp_path, ledger=None):
    keys = GatewayKeys()
    admin_token = keys.issue("admin", ADMIN, **_BIG)
    target_token = keys.issue("target", TARGET, **_BIG)
    app = create_gateway(
        GatewayObserver(), keys=keys, openai=Provider("https://provider.test/v1", SecretStr("sk-x")),
        ledger=ledger if ledger is not None else AuditLedger(tmp_path / "audit.jsonl"))
    return TestClient(app), admin_token, target_token


def _auth(token: str) -> dict:
    return {"authorization": f"Bearer {token}"}


def test_route_is_absent_without_a_ledger(tmp_path):
    keys = GatewayKeys()
    admin_token = keys.issue("admin", ADMIN, **_BIG)
    app = create_gateway(GatewayObserver(), keys=keys, openai=Provider("https://provider.test/v1", SecretStr("sk-x")))
    web = TestClient(app)
    assert web.get("/ledger/export", headers=_auth(admin_token)).status_code == 404


def test_a_target_key_is_refused(tmp_path):
    web, _, target_token = _app(tmp_path)
    response = web.get("/ledger/export", headers=_auth(target_token))
    assert response.status_code == 403


def test_bad_auth_is_a_plain_401(tmp_path):
    web, _, _ = _app(tmp_path)
    assert web.get("/ledger/export").status_code == 401
    assert web.get("/ledger/export", headers={"authorization": "Bearer nonsense"}).status_code == 401


def test_an_empty_ledger_has_no_log_id_and_no_events(tmp_path):
    web, admin_token, _ = _app(tmp_path)
    response = web.get("/ledger/export", headers=_auth(admin_token))
    assert response.status_code == 200
    body = response.json()
    assert body == {"log_id": None, "size": 0, "events": [], "next_seq": None}


def test_pagination_walks_the_log_in_order(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    for i in range(5):
        ledger.append("test", "event", {"n": i})
    web, admin_token, _ = _app(tmp_path, ledger=ledger)

    first = web.get("/ledger/export", headers=_auth(admin_token), params={"limit": 2}).json()
    assert [e["payload"]["n"] for e in first["events"]] == [0, 1]
    assert first["next_seq"] == 1 and first["size"] == 5 and first["log_id"] == ledger.log_id

    second = web.get("/ledger/export", headers=_auth(admin_token),
                     params={"after_seq": first["next_seq"], "limit": 2}).json()
    assert [e["payload"]["n"] for e in second["events"]] == [2, 3]

    last = web.get("/ledger/export", headers=_auth(admin_token),
                   params={"after_seq": second["next_seq"], "limit": 2}).json()
    assert [e["payload"]["n"] for e in last["events"]] == [4]
    assert last["next_seq"] is None  # a short page: the caller is caught up as of this call


def test_limit_outside_bounds_is_rejected(tmp_path):
    web, admin_token, _ = _app(tmp_path)
    for limit in (0, -1, MAX_EXPORT + 1):
        response = web.get("/ledger/export", headers=_auth(admin_token), params={"limit": limit})
        assert response.status_code == 400


def test_after_seq_below_the_starting_sentinel_is_rejected(tmp_path):
    web, admin_token, _ = _app(tmp_path)
    assert web.get("/ledger/export", headers=_auth(admin_token), params={"after_seq": -2}).status_code == 400


def test_after_seq_default_includes_the_very_first_event(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("test", "event", {"n": 0})
    web, admin_token, _ = _app(tmp_path, ledger=ledger)
    body = web.get("/ledger/export", headers=_auth(admin_token)).json()
    assert [e["payload"]["n"] for e in body["events"]] == [0]


def test_the_trust_endpoint_serves_only_public_keys_and_only_to_an_admin(tmp_path):
    from purpleteam.audit.ledger import AuditLedger
    from purpleteam.gateway import Provider, create_gateway
    from purpleteam.gateway_keys import ADMIN, TARGET, GatewayKeys
    from purpleteam.gateway_observer import GatewayObserver
    from fastapi.testclient import TestClient
    from pydantic import SecretStr

    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("gateway", "decision", {})
    keys = GatewayKeys()
    admin = keys.issue("a", ADMIN, ttl_seconds=60, max_requests=10)
    target = keys.issue("t", TARGET, ttl_seconds=60, max_requests=10)
    web = TestClient(create_gateway(GatewayObserver(), keys=keys, ledger=ledger,
                                    openai=Provider("https://provider.test/v1", SecretStr("x"))))

    assert web.get("/ledger/trust", headers={"authorization": f"Bearer {target}"}).status_code == 403
    body = web.get("/ledger/trust", headers={"authorization": f"Bearer {admin}"}).json()
    assert body["log_id"] == ledger.log_id and body["keys"] == ledger.public_keys()
    assert "PRIVATE" not in str(body) and "checkpoint" not in body
