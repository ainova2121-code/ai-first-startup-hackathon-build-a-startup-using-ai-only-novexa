"""Gateway keys: scoped, expiring, budgeted, rate-limited and audited; and the gateway's TLS rule."""

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from purpleteam.audit.ledger import AuditLedger
from purpleteam.gateway import Provider, check_binding, create_gateway
from purpleteam.gateway_keys import ADMIN, AUDIT_WINDOW, MAX_KEYS, MAX_TTL, TARGET, AuthError, GatewayKeys
from purpleteam.gateway_observer import GatewayObserver
from test_gateway import _request  # noqa: E402  (helper shared with the gateway tests)


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def _keys(audit=None):
    clock = Clock()
    return GatewayKeys(audit, clock), clock


def _bearer(token: str) -> str:
    return f"Bearer {token}"


def _refused(keys, header, role=TARGET):
    with pytest.raises(AuthError) as error:
        keys.authenticate(header, role)
    return error.value


def test_a_valid_key_is_accepted_and_only_its_digest_is_kept():
    keys, _ = _keys()
    token = keys.issue("assessment 7", TARGET, ttl_seconds=60, max_requests=5)
    grant = keys.authenticate(_bearer(token), TARGET)
    assert (grant.label, grant.role) == ("assessment 7", TARGET)
    secret = token.split("_", 2)[2]
    assert secret not in repr(vars(keys)) and secret not in str(keys._keys)


def test_anything_not_proven_is_a_plain_401_whatever_the_reason():
    keys, _ = _keys()
    token = keys.issue("k", TARGET, ttl_seconds=60, max_requests=5)
    _, key_id, secret = token.split("_", 2)
    for header in ("", "Bearer", "Basic " + token, "bearer " + token, _bearer("nonsense"), _bearer("ptgw__"),
                   _bearer(f"ptgw_{key_id}_"), _bearer(f"ptgw_{key_id}_{secret[:-1]}x"),
                   _bearer(f"ptgw_deadbeef_{secret}"), _bearer(token + "x"), _bearer("ptgw_" + "_" * 5)):
        assert _refused(keys, header).status == 401, header


def test_a_key_expires_and_can_be_revoked():
    keys, clock = _keys()
    token = keys.issue("k", TARGET, ttl_seconds=60, max_requests=100)
    keys.authenticate(_bearer(token), TARGET)
    clock.now += 61
    assert (_refused(keys, _bearer(token)).status, _refused(keys, _bearer(token)).reason) == (401, "expired")
    other = keys.issue("k2", TARGET, ttl_seconds=60, max_requests=100)
    keys.revoke(other.split("_")[1])
    assert _refused(keys, _bearer(other)).reason == "revoked"
    with pytest.raises(ValueError, match="no such key"):
        keys.revoke("00000000")


def test_the_request_budget_is_hard():
    keys, _ = _keys()
    token = keys.issue("k", TARGET, ttl_seconds=60, max_requests=3, per_minute=1000)
    for _ in range(3):
        keys.authenticate(_bearer(token), TARGET)
    refused = _refused(keys, _bearer(token))
    assert (refused.status, refused.reason) == (429, "budget")


def test_the_rate_limit_drains_and_refills():
    keys, clock = _keys()
    token = keys.issue("k", TARGET, ttl_seconds=3600, max_requests=1000, per_minute=6)
    for _ in range(6):
        keys.authenticate(_bearer(token), TARGET)
    assert _refused(keys, _bearer(token)).reason == "rate"
    clock.now += 10  # six a minute is one every ten seconds
    keys.authenticate(_bearer(token), TARGET)
    assert _refused(keys, _bearer(token)).reason == "rate"
    clock.now += 600  # the bucket never holds more than a minute's worth
    for _ in range(6):
        keys.authenticate(_bearer(token), TARGET)
    assert _refused(keys, _bearer(token)).reason == "rate"


def test_refused_requests_do_not_spend_the_budget_and_strangers_cannot_drain_a_key():
    keys, _ = _keys()
    token = keys.issue("k", TARGET, ttl_seconds=60, max_requests=2, per_minute=1000)
    key_id = token.split("_")[1]
    for _ in range(50):
        _refused(keys, _bearer(f"ptgw_{key_id}_wrongsecret"))
    keys.authenticate(_bearer(token), TARGET)
    keys.authenticate(_bearer(token), TARGET)


def test_roles_are_kept_apart():
    keys, _ = _keys()
    target = keys.issue("t", TARGET, ttl_seconds=60, max_requests=9)
    admin = keys.issue("a", ADMIN, ttl_seconds=60, max_requests=9)
    assert _refused(keys, _bearer(target), ADMIN).status == 403
    assert _refused(keys, _bearer(admin), TARGET).status == 403
    keys.authenticate(_bearer(admin), ADMIN)


def test_a_key_is_rotated_by_overlap():
    keys, _ = _keys()
    old = keys.issue("v1", TARGET, ttl_seconds=60, max_requests=9)
    new = keys.issue("v2", TARGET, ttl_seconds=60, max_requests=9)
    keys.authenticate(_bearer(old), TARGET)
    keys.authenticate(_bearer(new), TARGET)
    keys.revoke(old.split("_")[1])
    keys.authenticate(_bearer(new), TARGET)
    assert _refused(keys, _bearer(old)).reason == "revoked"


def test_keys_must_have_a_limited_life_and_budget():
    keys, _ = _keys()
    for bad in ({"ttl_seconds": 0}, {"ttl_seconds": MAX_TTL + 1}, {"max_requests": 0}, {"per_minute": 0},
                {"ttl_seconds": float("nan")}):
        args = {"ttl_seconds": 60, "max_requests": 5, **bad}
        with pytest.raises(ValueError, match="lifetime"):
            keys.issue("k", TARGET, **args)
    for label, role in (("", TARGET), ("bad\nlabel", TARGET), ("x" * 65, TARGET), ("ok", "root")):
        with pytest.raises(ValueError, match="role must be"):
            keys.issue(label, role, ttl_seconds=60, max_requests=5)


def test_dead_keys_are_forgotten_and_live_keys_are_capped():
    keys, clock = _keys()
    for _ in range(MAX_KEYS):
        keys.issue("k", TARGET, ttl_seconds=10, max_requests=1)
    with pytest.raises(ValueError, match="at most"):
        keys.issue("k", TARGET, ttl_seconds=10, max_requests=1)
    clock.now += 11
    keys.issue("k", TARGET, ttl_seconds=10, max_requests=1)  # the expired ones made room


def test_audit_records_issue_revoke_and_refusals_without_any_secret():
    events = []
    keys, clock = _keys(lambda kind, payload: events.append((kind, payload)))
    token = keys.issue("k", TARGET, ttl_seconds=60, max_requests=1)
    key_id = token.split("_")[1]
    keys.revoke(key_id)
    _refused(keys, _bearer(token))
    kinds = [kind for kind, _ in events]
    assert kinds == ["key_issued", "key_revoked", "auth_refused"]
    assert events[2][1] == {"reason": "revoked", "key_id": key_id, "held_back": 0}
    assert token.split("_", 2)[2] not in str(events)
    _refused(keys, _bearer("ptgw_0badc0de_guess"))
    assert events[-1][1]["key_id"] == "unknown"  # an unproven id is never echoed back into the log


def test_a_flood_of_bad_requests_writes_one_event_per_window_and_counts_the_rest():
    events = []
    keys, clock = _keys(lambda kind, payload: events.append((kind, payload)))
    for _ in range(500):
        _refused(keys, _bearer("junk"))
    refusals = [p for k, p in events if k == "auth_refused"]
    assert len(refusals) == 1
    clock.now += AUDIT_WINDOW + 1
    _refused(keys, _bearer("junk"))
    refusals = [p for k, p in events if k == "auth_refused"]
    assert len(refusals) == 2 and refusals[1]["held_back"] == 499


def test_a_broken_audit_sink_never_turns_a_refusal_into_an_approval():
    def broken(kind, payload):
        raise OSError("disk full")

    keys, _ = _keys(broken)
    token = keys.issue("k", TARGET, ttl_seconds=60, max_requests=5)
    assert _refused(keys, _bearer("junk")).status == 401
    keys.authenticate(_bearer(token), TARGET)


def test_audit_events_land_in_the_signed_ledger(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    keys = GatewayKeys(lambda kind, payload: ledger.append("gateway", kind, payload))
    token = keys.issue("assessment", TARGET, ttl_seconds=60, max_requests=1)
    _refused(keys, _bearer("junk"))
    keys.revoke(token.split("_")[1])
    assert [e["kind"] for e in ledger.events()] == ["key_issued", "auth_refused", "key_revoked"]
    assert ledger.verify().ok and token.split("_", 2)[2] not in (tmp_path / "audit.jsonl").read_text()


def _web(keys, upstream_key=SecretStr("sk-up")):
    seen = []

    def upstream(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        return httpx.Response(200, json={"choices": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    app = create_gateway(GatewayObserver(), openai=Provider("https://p.test/v1", upstream_key), keys=keys, client=client)
    return TestClient(app), seen


def test_the_gateway_answers_with_the_right_status_and_keeps_roles_apart():
    keys, _ = _keys()
    target = {"authorization": _bearer(keys.issue("t", TARGET, ttl_seconds=60, max_requests=2, per_minute=1000))}
    admin = {"authorization": _bearer(keys.issue("a", ADMIN, ttl_seconds=60, max_requests=9))}
    web, _ = _web(keys)
    assert web.post("/v1/chat/completions", json=_request(), headers={"authorization": "Bearer x"}).status_code == 401
    assert web.get("/profile", headers=target).status_code == 403  # a target key cannot read the inventory
    assert web.post("/v1/chat/completions", json=_request(), headers=admin).status_code == 403
    assert web.get("/profile", headers=admin).status_code == 200
    assert web.post("/v1/chat/completions", json=_request(), headers=target).status_code == 200
    assert web.get("/v1/models", headers=target).status_code == 200
    limited = web.post("/v1/chat/completions", json=_request(), headers=target)
    assert limited.status_code == 429 and limited.headers["retry-after"] == "60"
    assert "budget" not in limited.text and "key" not in limited.text  # the reason stays in the audit log


def test_the_upstream_key_can_come_from_a_secrets_manager_on_every_request():
    keys, _ = _keys()
    header = {"authorization": _bearer(keys.issue("t", TARGET, ttl_seconds=60, max_requests=9, per_minute=1000))}
    versions = iter(["sk-one", "sk-two"])
    web, seen = _web(keys, upstream_key=lambda: SecretStr(next(versions)))
    web.post("/v1/chat/completions", json=_request(), headers=header)
    web.post("/v1/chat/completions", json=_request(), headers=header)
    assert seen == ["Bearer sk-one", "Bearer sk-two"]


def test_plain_http_is_allowed_only_on_loopback():
    check_binding("127.0.0.1", None, None, None)
    check_binding("::1", None, None, None)
    check_binding("0.0.0.0", "cert.pem", "key.pem", None)
    check_binding("gateway.example.com", "cert.pem", "key.pem", "ca.pem")
    for host in ("0.0.0.0", "10.0.0.5", "gateway.example.com", "localhost", "::"):
        with pytest.raises(ValueError, match="without TLS"):
            check_binding(host, None, None, None)
    with pytest.raises(ValueError, match="go together"):
        check_binding("127.0.0.1", "cert.pem", None, None)
    with pytest.raises(ValueError, match="mutual TLS"):
        check_binding("127.0.0.1", None, None, "ca.pem")
