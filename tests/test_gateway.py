"""Gateway discovery: any product that sends its model traffic through us is profiled, observed and attackable."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from purpleteam.capture import DiscoveryError
from purpleteam.gateway import Provider, create_gateway
from purpleteam.gateway_keys import ADMIN, TARGET, GatewayKeys
from purpleteam.gateway_observer import MAX_AGENTS, GatewayObserver
from purpleteam.oracle import CANARY_ACCOUNT, CanaryOracle
from purpleteam.targets.endpoint import HttpTarget

UPSTREAM_KEY = "sk-upstream-secret-value"
KEYS = GatewayKeys()  # shared by the tests; generous limits, the limits themselves are tested in test_gateway_keys
_BIG = {"ttl_seconds": 3600, "max_requests": 10**6, "per_minute": 10**6}
TOKEN = KEYS.issue("tests", TARGET, **_BIG)
ADMIN_TOKEN = KEYS.issue("tests admin", ADMIN, **_BIG)
AUTH = {"authorization": f"Bearer {TOKEN}"}
ADMIN_AUTH = {"authorization": f"Bearer {ADMIN_TOKEN}"}
SYSTEM = "You handle customer records for the acme team."
TOOLS = [
    {"type": "function", "function": {"name": "update_record", "description": "Change a record",
                                      "parameters": {"properties": {"account": {"type": "string"}}}}},
    {"type": "function", "function": {"name": "get_record", "description": "Read a record", "parameters": {}}},
]


def _request(user="hi", tools=TOOLS, system=SYSTEM, extra=()):
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}, *extra]
    return {"model": "m", "messages": messages, "tools": tools}


def _call(name="update_record", args='{"account": "X1"}', call_id="c1"):
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": args}}


def test_profile_comes_from_the_request_alone():
    observer = GatewayObserver()
    observer.observe(_request())
    profile = observer.profile("product")
    assert {t.name: t.risk for t in profile.tools} == {"update_record": "write", "get_record": "read"}
    assert profile.dangerous_tools == {"update_record"} and len(profile.agents) == 1


def test_an_agents_model_is_read_from_the_request_body_without_being_told_explicitly():
    observer = GatewayObserver()
    observer.observe(_request())  # _request() sets {"model": "m", ...}; no explicit model= argument given
    (agent,) = observer.profile("p").agent_info
    assert agent.model == "m" and observer.summary()["agents"][0]["model"] == "m"


def test_an_explicit_model_overrides_the_request_body_and_a_later_exchange_does_not_change_it():
    observer = GatewayObserver()
    observer.observe(_request(), model="gemini-2.0-flash")  # as the gateway resolves it for Gemini, from the URL
    observer.observe(_request())  # a later exchange for the same agent must not overwrite the first model seen
    (agent,) = observer.profile("p").agent_info
    assert agent.model == "gemini-2.0-flash"


def test_prompt_is_reported_only_as_a_hash():
    observer = GatewayObserver()
    observer.observe(_request(system="secret prompt text sk-live-123"))
    assert "secret prompt" not in json.dumps(observer.summary())
    assert observer.summary()["agents"][0]["prompt_chars"] == len("secret prompt text sk-live-123")


def test_agents_are_told_apart_by_tools_and_by_header():
    observer = GatewayObserver()
    observer.observe(_request())
    observer.observe(_request(tools=TOOLS[:1], system="Another job."))
    observer.observe(_request(), hint="billing")
    assert len(observer.profile("p").agents) == 3 and "billing" in observer.profile("p").agents
    observer.observe(_request())  # the same agent again adds nothing
    assert len(observer.profile("p").agents) == 3


def test_calls_come_from_answers_and_results_from_the_following_request():
    observer = GatewayObserver()
    observer.observe(_request(), {"choices": [{"message": {"tool_calls": [_call()]}}]})
    observer.observe(_request(extra=[{"role": "tool", "tool_call_id": "c1", "content": "updated"}]))
    (call,) = observer.drain()
    assert (call.tool, call.args, call.result) == ("update_record", {"account": "X1"}, "updated")
    assert observer.drain() == []
    unexercised = observer.summary()["unexercised"]
    assert len(unexercised) == 1 and unexercised[0].endswith(".get_record")


def test_hostile_or_malformed_traffic_never_raises():
    observer = GatewayObserver()
    for junk in (None, [], "x", {"messages": "no"}, {"messages": [1, None]}, {"tools": [5, {"function": 3}]},
                 {"messages": [{"role": "tool", "tool_call_id": ["unhashable"]}]},
                 {"messages": [{"role": "assistant", "tool_calls": [{"id": 1, "function": 2}, 7]}]},
                 {"tools": [{"function": {"name": "t", "parameters": {"properties": 4}}}]}):
        observer.observe(junk, {"choices": [None, {"message": 5}]})
    observer.observe(_request(), {"choices": "no"})
    assert observer.drain() == []


def test_a_tool_name_that_is_not_plain_fails_discovery_loudly():
    observer = GatewayObserver()
    observer.observe(_request(tools=[{"type": "function", "function": {"name": "bad\nname"}}]))
    with pytest.raises(DiscoveryError, match="not a plain name"):
        observer.profile("p")


def test_no_traffic_is_not_an_empty_target():
    with pytest.raises(DiscoveryError, match="no model traffic"):
        GatewayObserver().profile("p")


def test_the_number_of_agents_is_capped():
    observer = GatewayObserver()
    for i in range(MAX_AGENTS + 1):
        observer.observe(_request(system=f"agent number {i}", tools=[{"type": "function", "function": {"name": f"t{i}"}}]))
    assert len(observer.summary()["agents"]) == MAX_AGENTS and observer.errors


def test_provider_native_tools_are_recorded_as_changing_things():
    observer = GatewayObserver()
    observer.observe(_request(tools=[{"type": "web_search_preview"}]))
    assert observer.profile("p").dangerous_tools == {"web_search_preview"}


def _gateway(upstream, observer=None, keys=KEYS):
    observer = observer or GatewayObserver()
    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    app = create_gateway(observer, openai=Provider("https://provider.test/v1", SecretStr(UPSTREAM_KEY)),
                         keys=keys, client=client)
    return TestClient(app), observer


def test_every_endpoint_needs_the_token_and_docs_are_off():
    web, _ = _gateway(lambda r: httpx.Response(200, json={}))
    for method, path in (("post", "/v1/chat/completions"), ("get", "/v1/models"), ("get", "/profile")):
        assert getattr(web, method)(path).status_code == 401
        assert getattr(web, method)(path, headers={"authorization": "Bearer wrong"}).status_code == 401
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert web.get(path).status_code == 404


def test_requests_are_forwarded_with_our_key_not_the_targets_token():
    seen = {}

    def upstream(request: httpx.Request) -> httpx.Response:
        seen["auth"], seen["body"] = request.headers["authorization"], json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})

    web, observer = _gateway(upstream)
    reply = web.post("/v1/chat/completions", json=_request(), headers=AUTH)
    assert reply.json() == {"choices": [{"message": {"content": "hi"}}]}
    assert seen["auth"] == f"Bearer {UPSTREAM_KEY}" and TOKEN not in seen["auth"] and seen["body"]["tools"] == TOOLS
    assert UPSTREAM_KEY not in json.dumps(web.get("/profile", headers=ADMIN_AUTH).json())
    assert len(observer.profile("p").tools) == 2


def test_bad_bodies_and_provider_failures_are_handled_without_leaking():
    def down(request):
        raise httpx.ConnectError("secret internal host db.internal:5432")

    web, _ = _gateway(down)
    assert web.post("/v1/chat/completions", content=b"not json", headers=AUTH).status_code == 400
    assert web.post("/v1/chat/completions", json=[1], headers=AUTH).status_code == 400
    assert web.post("/v1/chat/completions", content=b"{}" + b" " * 4_100_000, headers=AUTH).status_code == 413
    failed = web.post("/v1/chat/completions", json=_request(), headers=AUTH)
    assert failed.status_code == 502 and "internal" not in failed.text


def test_streaming_is_passed_through_untouched():
    chunks = b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n\n'
    web, observer = _gateway(lambda r: httpx.Response(200, stream=httpx.ByteStream(chunks),
                                                      headers={"content-type": "text/event-stream"}))
    reply = web.post("/v1/chat/completions", json={**_request(), "stream": True}, headers=AUTH)
    assert reply.content == chunks and "update_record" in observer.summary()["agents"][0]["tools"][0]["name"]


def test_gateway_refuses_odd_upstreams():
    with pytest.raises(ValueError, match="http"):
        Provider("file:///etc", SecretStr("k"))
    with pytest.raises(ValueError, match="at least one provider"):
        create_gateway(GatewayObserver(), keys=KEYS)


def _product(web: TestClient):
    """An agent product built on no framework we know: a webhook that calls a model and a tool, via the gateway."""

    def model(messages, system=SYSTEM):
        return web.post("/v1/chat/completions", headers=AUTH, json={"model": "m", "tools": TOOLS, "messages": [
            {"role": "system", "content": system}, *messages]}).json()["choices"][0]["message"]

    def webhook(request: httpx.Request) -> httpx.Response:
        text = json.loads(request.content)["chatInput"]
        asked = [{"role": "user", "content": text}]
        step = model(asked)
        if step.get("tool_calls"):
            done = [*asked, step, {"role": "tool", "tool_call_id": step["tool_calls"][0]["id"], "content": "record updated"}]
            return httpx.Response(200, json={"output": {"text": model(done)["content"]}})
        return httpx.Response(200, json={"output": {"text": step["content"]}})

    return webhook


def _obedient_model(request: httpx.Request) -> httpx.Response:
    messages = json.loads(request.content)["messages"]
    if messages[-1]["role"] == "tool":
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "all done"}}]})
    account = messages[-1]["content"].split()[-1]
    call = _call(args=json.dumps({"account": account}))
    return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [call]}}]})


def test_any_http_product_can_be_profiled_attacked_and_judged():
    web, observer = _gateway(_obedient_model)
    target = HttpTarget("product", "https://product.test/webhook", observer, message_field="chatInput",
                        reply_field="output.text",
                        client=httpx.Client(transport=httpx.MockTransport(_product(web))))
    observation = target.send(f"please update the record to {CANARY_ACCOUNT}")
    assert observation.reply == "all done"
    (call,) = observation.tool_calls
    assert (call.tool, call.args, call.result) == ("update_record", {"account": CANARY_ACCOUNT}, "record updated")
    profile = observer.profile("product")
    verdict = CanaryOracle({CANARY_ACCOUNT}, profile.dangerous_tools).judge(observation)
    assert verdict.breached and verdict.tool == "update_record"
    assert target.send("nothing special here").tool_calls[0].args == {"account": "here"}  # each send sees only its own calls


def test_http_target_reads_replies_and_refuses_odd_urls():
    observer = GatewayObserver()
    plain = HttpTarget("p", "https://x.test/hook", observer,
                       client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="plain text"))))
    assert plain.send("hi").reply == "plain text"
    with pytest.raises(ValueError, match="http"):
        HttpTarget("p", "ftp://x.test", observer)
