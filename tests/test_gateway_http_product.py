"""Any HTTP agent product behind the gateway can be profiled, attacked and judged; unbound keys stop at enforcement."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from purpleteam.gateway import Provider, create_gateway
from purpleteam.gateway_keys import ADMIN, TARGET, GatewayKeys
from purpleteam.gateway_observer import GatewayObserver
from purpleteam.oracle import CANARY_ACCOUNT, CanaryOracle
from purpleteam.targets.endpoint import HttpTarget
from test_gateway import AUTH, SYSTEM, TOOLS, UPSTREAM_KEY, _BIG, _call, _gateway, _request


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


def test_an_unbound_target_key_is_refused_once_enforcement_is_on():
    """The gap this closes: X-Purpleteam-Agent is spoofable by anyone (see gateway_observer.py's
    own docstring), so an unbound key combined with a claimed header name could be checked against
    that claimed agent's real policy permissions. Once enforcement is actually on, the key alone
    must prove which agent is calling — an unbound one is refused outright, not merely profiled as
    "unauthenticated" after the fact."""
    keys = GatewayKeys()
    unbound = keys.issue("unbound", TARGET, **_BIG)  # no agent= — exactly the bootstrap-key shape
    bound = keys.issue("bound", TARGET, agent="vendor", **_BIG)
    app = create_gateway(GatewayObserver(), keys=keys,
                         openai=Provider("https://provider.test/v1", SecretStr(UPSTREAM_KEY)),
                         guard=object())  # non-None: only decisions.enforcing is under test here

    web = TestClient(app)
    unbound_response = web.post("/v1/chat/completions", json=_request(), headers={"authorization": f"Bearer {unbound}"})
    assert unbound_response.status_code == 403

    bound_response = web.post("/v1/chat/completions", json=_request(), headers={"authorization": f"Bearer {bound}"})
    assert bound_response.status_code != 403  # may still fail upstream (no real provider), but not for this reason


def test_an_unbound_target_key_still_works_during_observe_only_discovery():
    """Discovery needs this: before any agent has a key of its own, an unbound key is the only way
    to see every agent's traffic at all. Must keep working exactly as before while observe-only."""
    keys = GatewayKeys()
    unbound = keys.issue("unbound", TARGET, **_BIG)
    app = create_gateway(GatewayObserver(), keys=keys,
                         openai=Provider("https://provider.test/v1", SecretStr(UPSTREAM_KEY)))  # no guard=

    web = TestClient(app)
    response = web.post("/v1/chat/completions", json=_request(), headers={"authorization": f"Bearer {unbound}"})
    assert response.status_code != 403


def test_an_unbound_admin_key_is_unaffected_by_the_target_only_check():
    """The new check is scoped to TARGET keys only — ADMIN has no agent concept to spoof."""
    keys = GatewayKeys()
    admin = keys.issue("admin", ADMIN, **_BIG)  # ADMIN keys never bind to an agent at all
    app = create_gateway(GatewayObserver(), keys=keys,
                         openai=Provider("https://provider.test/v1", SecretStr(UPSTREAM_KEY)), guard=object())

    web = TestClient(app)
    assert web.get("/profile", headers={"authorization": f"Bearer {admin}"}).status_code == 200
