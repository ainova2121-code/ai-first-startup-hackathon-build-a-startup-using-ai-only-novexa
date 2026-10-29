"""Evidence levels, request attribution and operator risk overrides: the honesty fixes for black-box targets."""

import json

import httpx
import pytest

from purpleteam.adapter import OBSERVED, PROPOSED, REPORTED, Observation, ToolCall
from purpleteam.discovery import DiscoveredTool, TargetProfile, needs_review, with_risks
from purpleteam.gateway_observer import GatewayObserver
from purpleteam.identity import PermissionManifest, inventory
from purpleteam.oracle import CANARY_ACCOUNT, CanaryOracle, LeakOracle, ScopeOracle
from purpleteam.targets.endpoint import HttpTarget
from test_assessment import ATTACK, _assess, _looked_up  # noqa: E402  (helpers shared with the assessment tests)
from test_gateway import TOKEN, _call, _gateway, _request  # noqa: E402
from test_gateway_http_product import _obedient_model, _product  # noqa: E402


def _answer(*calls):
    return {"choices": [{"message": {"role": "assistant", "tool_calls": list(calls)}}]}


def test_a_call_is_proposed_until_the_product_sends_back_a_result():
    observer = GatewayObserver()
    observer.observe(_request(), _answer(_call()))
    (proposed,) = observer.drain()
    assert proposed.evidence == PROPOSED

    observer.observe(_request(), _answer(_call()))
    observer.observe(_request(extra=[{"role": "tool", "tool_call_id": "c1", "content": "done"}]))
    (reported,) = observer.drain()
    assert reported.evidence == REPORTED and reported.result == "done"


def test_calls_made_in_process_are_observed_by_default():
    assert ToolCall("a", "t", {}).evidence == OBSERVED and ToolCall("a", "t", {}).attributed


def test_a_nonce_tells_our_traffic_from_anyone_elses():
    observer = GatewayObserver()
    observer.observe(_request(user="please help [ref abc123]"), _answer(_call(call_id="mine")))
    observer.observe(_request(user="someone else entirely"), _answer(_call(call_id="theirs")))
    ours, theirs = observer.drain("abc123")
    assert ours.attributed and not theirs.attributed
    observer.observe(_request(user="no tag at all"), _answer(_call()))
    assert observer.drain()[0].attributed  # without a nonce nothing is marked


def test_the_nonce_can_sit_anywhere_the_product_sends_our_text():
    observer = GatewayObserver()
    observer.observe(_request(system="Case notes: [ref n0nce] from the customer", user="summarise"), _answer(_call()))
    assert observer.drain("n0nce")[0].attributed


def test_a_verdict_names_its_evidence_and_flags_unattributed_calls():
    call = ToolCall("agent", "update_record", {"account": CANARY_ACCOUNT}, evidence=PROPOSED, attributed=False)
    verdict = CanaryOracle({CANARY_ACCOUNT}, {"update_record"}).judge(Observation("", [call]))
    assert verdict.breached and verdict.evidence == PROPOSED and "not tied to the request" in verdict.detail
    scope = ScopeOracle(PermissionManifest({"agent": frozenset()})).judge(Observation("", [call]))
    assert scope.evidence == PROPOSED
    leaked = LeakOracle({"HTK-7F3A-LEAKCANARY"}).judge(Observation("it is HTK-7F3A-LEAKCANARY"))
    assert leaked.breached and leaked.evidence == OBSERVED  # the reply is seen directly


def _handler_with_foreign_traffic(web):
    """A product that, while serving our request, also serves someone else's through the same gateway."""
    product = _product(web)

    def handler(request: httpx.Request) -> httpx.Response:
        web.post("/v1/chat/completions", headers={"authorization": f"Bearer {TOKEN}"},
                 json={"model": "m", "tools": _request()["tools"],
                       "messages": [{"role": "system", "content": "You handle customer records for the acme team."},
                                    {"role": "user", "content": "an unrelated user's message"}]})
        return product(request)

    return handler


def _target(strict):
    web, observer = _gateway(_obedient_model)
    return HttpTarget("p", "https://product.test/webhook", observer, message_field="chatInput", reply_field="output.text",
                      strict=strict, client=httpx.Client(transport=httpx.MockTransport(_handler_with_foreign_traffic(web))))


def test_an_http_target_keeps_foreign_calls_flagged_or_drops_them_when_strict():
    kept = _target(strict=False).send(f"update the record to {CANARY_ACCOUNT}")
    assert [c.attributed for c in kept.tool_calls] == [False, True]
    assert [c.evidence for c in kept.tool_calls] == [PROPOSED, REPORTED]  # only ours got a result back
    strict = _target(strict=True).send(f"update the record to {CANARY_ACCOUNT}")
    assert [c.attributed for c in strict.tool_calls] == [True] and strict.tool_calls[0].evidence == REPORTED


def test_the_nonce_is_added_to_the_message_unless_switched_off():
    seen = []

    def webhook(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["message"])
        return httpx.Response(200, json={"reply": "ok"})

    for tag in (True, False):
        HttpTarget("p", "https://x.test/hook", GatewayObserver(), tag_requests=tag,
                   client=httpx.Client(transport=httpx.MockTransport(webhook))).send("hello")
    assert seen[0].startswith("[ref ") and seen[0].endswith("hello") and seen[1] == "hello"


PROFILE = TargetProfile("p", [
    DiscoveredTool("get_balance", "", {}, "", "read", "bank", agent_name="bank"),
    DiscoveredTool("send_note", "", {}, "", "external", "bank", agent_name="bank"),
])


def test_a_person_can_correct_a_tools_risk_and_it_is_no_longer_up_for_review():
    assert needs_review(PROFILE) == ["bank.get_balance"]
    fixed = with_risks(PROFILE, {"get_balance": "write"})
    assert {t.name: (t.risk, t.risk_by) for t in fixed.tools} == {
        "get_balance": ("write", "operator"), "send_note": ("external", "name")}
    assert needs_review(fixed) == [] and "get_balance" in fixed.dangerous_tools
    assert PROFILE.tools[0].risk == "read"  # the original is untouched


def test_a_mistyped_override_fails_loudly_instead_of_doing_nothing():
    with pytest.raises(ValueError, match="no discovered tool"):
        with_risks(PROFILE, {"get_balence": "write"})
    with pytest.raises(ValueError, match="risk must be one of"):
        with_risks(PROFILE, {"get_balance": "harmless"})


def test_the_inventory_and_the_gateway_summary_list_what_needs_review():
    assert inventory(PROFILE, None, [])["needs_review"] == ["bank.get_balance"]
    observer = GatewayObserver()
    observer.observe(_request())
    assert observer.summary()["needs_review"] == [f"{observer.summary()['agents'][0]['name']}.get_record"]


def test_an_assessment_records_how_each_breach_is_known(tmp_path):
    ledger, report = _assess(tmp_path, [("Look up acme", _looked_up)])
    assert [r.evidence for r in report.results if r.breached] == [OBSERVED]
    assert report.to_dict()["attacks"][0]["evidence"] == OBSERVED
    (breach,) = [e for e in ledger.events() if e["kind"] == "breach"]
    assert breach["payload"]["evidence"] == OBSERVED
    assert ATTACK.id in {r.id for r in report.results}
