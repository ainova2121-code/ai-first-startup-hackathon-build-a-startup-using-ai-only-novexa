"""A key must still be valid when the answer is released: revoking it stops work already in flight."""

import httpx
from fastapi.testclient import TestClient
from pydantic import SecretStr

from purpleteam.audit.ledger import AuditLedger
from purpleteam.gateway import Provider, create_gateway
from purpleteam.gateway_keys import TARGET, GatewayKeys
from purpleteam.gateway_observer import GatewayObserver
from test_gateway import _call, _request  # noqa: E402  (helpers shared with the gateway tests)

BIG = {"ttl_seconds": 3600, "max_requests": 10**6, "per_minute": 10**6}
ANSWER = {"choices": [{"message": {"role": "assistant", "tool_calls": [_call()]}}]}


class Clock:
    now = 1_000_000.0

    def __call__(self):
        return self.now


def _bearer(token):
    return {"authorization": f"Bearer {token}"}


def _app(handler, keys, ledger=None):
    observer = GatewayObserver()
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app = create_gateway(observer, openai=Provider("https://p.test/v1", SecretStr("sk")), keys=keys, client=client,
                         ledger=ledger)
    return TestClient(app), observer


def test_is_active_tracks_revocation_and_expiry_and_costs_nothing():
    clock = Clock()
    keys = GatewayKeys(clock=clock)
    token = keys.issue("k", TARGET, ttl_seconds=60, max_requests=1)
    key_id = token.split("_")[1]
    for _ in range(50):  # asking never spends the budget
        assert keys.is_active(key_id)
    keys.authenticate(f"Bearer {token}", TARGET)  # the one request the budget allows is still there
    other = keys.issue("k2", TARGET, ttl_seconds=60, max_requests=5)
    keys.revoke(other.split("_")[1])
    assert not keys.is_active(other.split("_")[1])
    clock.now += 61
    assert not keys.is_active(key_id)
    assert not keys.is_active("00000000") and not keys.is_active(None) and not keys.is_active("")


def test_a_key_revoked_while_the_provider_is_thinking_gets_no_answer_and_no_call_is_recorded():
    keys = GatewayKeys()
    token = keys.issue("records key", TARGET, agent="records", **BIG)
    key_id = token.split("_")[1]

    def provider(request):
        keys.revoke(key_id)  # the stop arrives while the request is in flight
        return httpx.Response(200, json=ANSWER)

    web, observer = _app(provider, keys)
    reply = web.post("/v1/chat/completions", json=_request(), headers=_bearer(token))
    assert reply.status_code == 401 and "tool_calls" not in reply.text
    assert observer.timeline() == [] and observer.drain() == []  # a call inside a withheld answer never happened


def test_an_answer_is_released_while_the_key_is_valid():
    keys = GatewayKeys()
    token = keys.issue("records key", TARGET, agent="records", **BIG)
    web, observer = _app(lambda r: httpx.Response(200, json=ANSWER), keys)
    assert web.post("/v1/chat/completions", json=_request(), headers=_bearer(token)).status_code == 200
    assert [c.tool for c in observer.timeline()] == ["update_record"]


def test_a_key_that_expires_while_the_provider_is_thinking_gets_no_answer():
    clock = Clock()
    keys = GatewayKeys(clock=clock)
    token = keys.issue("short key", TARGET, ttl_seconds=60, max_requests=10)

    def provider(request):
        clock.now += 120
        return httpx.Response(200, json=ANSWER)

    web, observer = _app(provider, keys)
    assert web.post("/v1/chat/completions", json=_request(), headers=_bearer(token)).status_code == 401
    assert observer.timeline() == []


def test_revoking_one_agents_key_leaves_the_others_working():
    keys = GatewayKeys()
    records = keys.issue("records key", TARGET, agent="records", **BIG)
    billing = keys.issue("billing key", TARGET, agent="billing", **BIG)

    def provider(request):
        keys.revoke(records.split("_")[1])
        return httpx.Response(200, json=ANSWER)

    web, observer = _app(provider, keys)
    assert web.post("/v1/chat/completions", json=_request(), headers=_bearer(records)).status_code == 401
    assert web.post("/v1/chat/completions", json=_request(), headers=_bearer(billing)).status_code == 200
    assert {c.agent for c in observer.timeline()} == {"billing"}


def test_the_withheld_answer_is_on_the_signed_record_without_the_call(tmp_path):
    keys = GatewayKeys()
    token = keys.issue("records key", TARGET, agent="records", **BIG)
    ledger = AuditLedger(tmp_path / "audit.jsonl")

    def provider(request):
        keys.revoke(token.split("_")[1])
        return httpx.Response(200, json=ANSWER)

    web, _ = _app(provider, keys, ledger)
    web.post("/v1/chat/completions", json=_request(), headers=_bearer(token))
    (event,) = ledger.events()
    assert event["kind"] == "decision" and ledger.verify().ok
    assert (event["payload"]["verdict"], event["payload"]["policy"], event["payload"]["agent"]) == ("withheld", "key_inactive", "records")
    assert "update_record" not in str(event)


def test_a_stream_is_cut_when_its_key_is_revoked_part_way_through(tmp_path):
    keys = GatewayKeys()
    token = keys.issue("records key", TARGET, agent="records", **BIG)
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    closed = []

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
            keys.revoke(token.split("_")[1])  # the stop arrives mid-stream
            yield b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"update_record","arguments":"{}"}}]}}]}\n\n'

        async def aclose(self):
            closed.append(True)

    web, observer = _app(lambda r: httpx.Response(200, stream=Body(), headers={"content-type": "text/event-stream"}),
                         keys, ledger)
    with web.stream("POST", "/v1/chat/completions", json={**_request(), "stream": True}, headers=_bearer(token)) as reply:
        received = b"".join(reply.iter_raw())
    assert b"hello" in received and b"update_record" not in received  # the call after the stop never reached the client
    assert closed and observer.timeline() == []
    assert [e["payload"]["verdict"] for e in ledger.events()] == ["withheld"]


def test_a_stream_whose_key_is_revoked_before_it_starts_is_refused_and_released_upstream():
    keys = GatewayKeys()
    token = keys.issue("records key", TARGET, agent="records", **BIG)
    closed = []

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"data: {}\n\n"

        async def aclose(self):
            closed.append(True)

    def provider(request):
        keys.revoke(token.split("_")[1])
        return httpx.Response(200, stream=Body(), headers={"content-type": "text/event-stream"})

    web, observer = _app(provider, keys)
    reply = web.post("/v1/chat/completions", json={**_request(), "stream": True}, headers=_bearer(token))
    assert reply.status_code == 401 and closed and observer.timeline() == []
