"""Anthropic and Gemini requests through the gateway: forwarded with our key, models read, streams observed, odd input refused."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from purpleteam.gateway import Provider, create_gateway
from purpleteam.gateway_keys import TARGET, GatewayKeys
from purpleteam.gateway_observer import GatewayObserver
from test_gateway import KEYS, TOKEN  # noqa: E402  (a shared target key for the gateway tests)
from test_gateway_dialects import _anthropic, _function_call, _gemini, _tool_use


def _provider_app(handler, *, anthropic=True, gemini=True, openai=False, keys=KEYS):
    seen = []

    def upstream(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    observer = GatewayObserver()
    app = create_gateway(
        observer, keys=keys, client=client,
        openai=Provider("https://openai.test/v1", SecretStr("sk-openai")) if openai else None,
        anthropic=Provider("https://anthropic.test", SecretStr("sk-ant-upstream")) if anthropic else None,
        gemini=Provider("https://gemini.test", SecretStr("gem-upstream")) if gemini else None)
    return TestClient(app), observer, seen


def test_anthropic_requests_are_forwarded_with_our_key_and_only_the_version_headers():
    web, observer, seen = _provider_app(lambda r: httpx.Response(200, json=_tool_use()))
    reply = web.post("/v1/messages", json=_anthropic(), headers={
        "x-api-key": TOKEN, "anthropic-version": "2023-06-01", "anthropic-beta": "tools-2024-04-04",
        "cookie": "session=abc", "x-forwarded-for": "1.2.3.4"})
    assert reply.status_code == 200 and reply.json()["stop_reason"] == "tool_use"
    (upstream,) = seen
    assert str(upstream.url) == "https://anthropic.test/v1/messages"
    assert upstream.headers["x-api-key"] == "sk-ant-upstream" and TOKEN not in str(upstream.headers)
    assert upstream.headers["anthropic-beta"] == "tools-2024-04-04" and "cookie" not in upstream.headers
    assert upstream.headers["anthropic-version"] == "2023-06-01"
    assert [c.tool for c in observer.drain()] == ["update_record"]


def test_a_default_anthropic_version_is_supplied_and_odd_ones_are_refused():
    web, _, seen = _provider_app(lambda r: httpx.Response(200, json=_tool_use()))
    web.post("/v1/messages", json=_anthropic(), headers={"x-api-key": TOKEN})
    assert seen[0].headers["anthropic-version"] == "2023-06-01"
    assert web.post("/v1/messages", json=_anthropic(), headers={"x-api-key": TOKEN, "anthropic-version": "x\ty"}).status_code == 400


def test_gemini_requests_are_forwarded_with_our_key_and_the_client_key_never_leaves():
    web, observer, seen = _provider_app(lambda r: httpx.Response(200, json=_function_call()))
    reply = web.post("/v1beta/models/gemini-2.0-flash:generateContent", json=_gemini(), headers={"x-goog-api-key": TOKEN})
    assert reply.status_code == 200
    (upstream,) = seen
    assert str(upstream.url) == "https://gemini.test/v1beta/models/gemini-2.0-flash:generateContent"
    assert upstream.headers["x-goog-api-key"] == "gem-upstream" and TOKEN not in str(upstream.headers)
    assert [c.tool for c in observer.drain()] == ["update_record"]
    assert web.post("/v1/models/gemini-pro:generateContent", json=_gemini(), headers={"x-goog-api-key": TOKEN}).status_code == 200


def test_gemini_model_is_read_from_the_url_not_the_body():
    # the Gemini request body never carries a "model" field; the gateway resolves it from the URL path instead
    web, observer, _ = _provider_app(lambda r: httpx.Response(200, json=_function_call()))
    web.post("/v1beta/models/gemini-2.0-flash:generateContent", json=_gemini(), headers={"x-goog-api-key": TOKEN})
    (agent,) = observer.profile("p").agent_info
    assert agent.model == "gemini-2.0-flash"


def test_anthropic_model_is_read_from_the_request_body():
    web, observer, _ = _provider_app(lambda r: httpx.Response(200, json=_tool_use()))
    web.post("/v1/messages", json=_anthropic(), headers={"x-api-key": TOKEN, "anthropic-version": "2023-06-01"})
    (agent,) = observer.profile("p").agent_info
    assert agent.model == "m"  # _anthropic() sets {"model": "m", ...}


def test_gemini_keys_in_the_url_are_not_accepted_and_odd_paths_are_refused():
    web, _, seen = _provider_app(lambda r: httpx.Response(200, json=_function_call()))
    assert web.post(f"/v1beta/models/m:generateContent?key={TOKEN}", json=_gemini()).status_code == 401
    ok = {"x-goog-api-key": TOKEN}
    for path in ("/v1beta/models/m:deleteEverything", "/v1beta/models/..%2Fsecret:generateContent",
                 "/v1beta/models/m", "/v1beta/models/" + "a" * 101 + ":generateContent"):
        assert web.post(path, json=_gemini(), headers=ok).status_code == 404, path
    assert not seen


def test_gemini_streaming_is_observed_and_unreadable_streaming_is_refused():
    stream = f"data: {json.dumps(_function_call())}\r\n\r\n".encode()
    web, observer, seen = _provider_app(lambda r: httpx.Response(
        200, stream=httpx.ByteStream(stream), headers={"content-type": "text/event-stream"}))
    ok = {"x-goog-api-key": TOKEN}
    reply = web.post("/v1beta/models/m:streamGenerateContent?alt=sse", json=_gemini(), headers=ok)
    assert reply.content == stream and str(seen[0].url).endswith("m:streamGenerateContent?alt=sse")
    assert [c.tool for c in observer.drain()] == ["update_record"]
    refused = web.post("/v1beta/models/m:streamGenerateContent", json=_gemini(), headers=ok)
    assert refused.status_code == 400 and len(seen) == 1  # never passed on unobserved


def test_anthropic_streaming_is_passed_through_and_observed():
    events = [{"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "t1", "name": "update_record", "input": {}}},
              {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": '{"account": "Q"}'}}]
    body = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()
    web, observer, _ = _provider_app(lambda r: httpx.Response(200, stream=httpx.ByteStream(body),
                                                              headers={"content-type": "text/event-stream"}))
    reply = web.post("/v1/messages", json={**_anthropic(), "stream": True}, headers={"x-api-key": TOKEN})
    assert reply.content == body and observer.drain()[0].args == {"account": "Q"}


def test_only_configured_providers_have_routes_and_every_header_style_is_authenticated():
    web, _, _ = _provider_app(lambda r: httpx.Response(200, json={}), anthropic=False, gemini=False, openai=True)
    assert web.post("/v1/messages", json=_anthropic(), headers={"x-api-key": TOKEN}).status_code == 404
    assert web.post("/v1beta/models/m:generateContent", json=_gemini(), headers={"x-goog-api-key": TOKEN}).status_code == 404
    for headers in ({}, {"x-api-key": "wrong"}, {"x-goog-api-key": "wrong"}, {"authorization": "Bearer wrong"}):
        assert web.post("/v1/chat/completions", json={"messages": []}, headers=headers).status_code == 401
    for headers in ({"x-api-key": TOKEN}, {"x-goog-api-key": TOKEN}, {"authorization": f"Bearer {TOKEN}"}):
        assert web.post("/v1/chat/completions", json={"messages": []}, headers=headers).status_code == 200


def test_a_target_key_cannot_read_the_inventory_through_any_header_style():
    web, _, _ = _provider_app(lambda r: httpx.Response(200, json={}))
    for headers in ({"x-api-key": TOKEN}, {"x-goog-api-key": TOKEN}):
        assert web.get("/profile", headers=headers).status_code == 403


def test_provider_failures_are_generic_for_every_format():
    def down(request):
        raise httpx.ConnectError("secret internal host db.internal:5432")

    web, _, _ = _provider_app(down)
    for path, headers, body in (("/v1/messages", {"x-api-key": TOKEN}, _anthropic()),
                                ("/v1beta/models/m:generateContent", {"x-goog-api-key": TOKEN}, _gemini())):
        failed = web.post(path, json=body, headers=headers)
        assert failed.status_code == 502 and "internal" not in failed.text


def test_provider_bases_are_validated():
    with pytest.raises(ValueError, match="http"):
        Provider("file:///etc", SecretStr("k"))
    assert GatewayKeys().issue("t", TARGET, ttl_seconds=60, max_requests=1)  # keys are independent of providers
