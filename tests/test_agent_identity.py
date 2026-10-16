"""Authenticated agent identity: who is calling is what its key says, claims are counted not believed, drift is caught."""

import asyncio
import copy

import httpx
import pytest

from purpleteam.adapter import Observation
from purpleteam.discovery import AgentInfo, DiscoveredTool, TargetProfile
from purpleteam.gateway_keys import ADMIN, TARGET, GatewayKeys
from purpleteam.identity import PermissionManifest, baseline, check_baseline, drift, inventory, posture
from purpleteam.oracle import ScopeOracle
from test_gateway import _call, _gateway, _request  # noqa: E402  (helpers shared with the gateway tests)

BIG = {"ttl_seconds": 3600, "max_requests": 10**6, "per_minute": 10**6}
ANSWER = {"choices": [{"message": {"role": "assistant", "tool_calls": [_call()]}}]}


def _bearer(token):
    return {"authorization": f"Bearer {token}"}


def _setup():
    keys = GatewayKeys()
    tokens = {name: keys.issue(f"{name} key", TARGET, agent=name, **BIG) for name in ("billing", "records")}
    tokens["unbound"] = keys.issue("shared key", TARGET, **BIG)
    web, observer = _gateway(lambda r: httpx.Response(200, json=ANSWER), keys=keys)
    return keys, tokens, web, observer


def _send(web, token, request=None, hint=None):
    headers = {**_bearer(token), **({"x-purpleteam-agent": hint} if hint else {})}
    return web.post("/v1/chat/completions", json=request or _request(), headers=headers)


def test_a_key_can_be_bound_to_one_agent_and_only_a_target_key():
    keys = GatewayKeys()
    token = keys.issue("billing key", TARGET, agent="billing", **BIG)
    assert keys.authenticate(f"Bearer {token}", TARGET).agent == "billing"
    assert keys.authenticate(f"Bearer {keys.issue('plain', TARGET, **BIG)}", TARGET).agent is None
    for agent, role in (("billing", ADMIN), ("bad\nname", TARGET), ("", TARGET), ("x" * 129, TARGET), (7, TARGET)):
        with pytest.raises(ValueError, match="bound to an agent"):
            keys.issue("k", role, agent=agent, **BIG)


def test_the_binding_is_recorded_when_the_key_is_issued_and_never_includes_the_secret():
    events = []
    keys = GatewayKeys(lambda kind, payload: events.append((kind, payload)))
    token = keys.issue("billing key", TARGET, agent="billing", **BIG)
    assert events[0][1]["agent"] == "billing" and token.split("_", 2)[2] not in str(events)


def test_two_agents_with_identical_prompts_and_tools_stay_separate_under_separate_keys():
    keys, tokens, web, observer = _setup()
    _send(web, tokens["billing"])
    _send(web, tokens["records"])  # the very same request: guessing from the prompt would merge them
    assert sorted(observer.profile("p").agents) == ["billing", "records"]
    assert {a["name"]: a["authenticated"] for a in observer.summary()["agents"]} == {"billing": True, "records": True}


def test_the_calls_are_filed_under_the_authenticated_agent():
    keys, tokens, web, observer = _setup()
    _send(web, tokens["billing"])
    (call,) = observer.drain()
    assert call.agent == "billing"
    manifest = PermissionManifest({"billing": frozenset({"get_record"}), "records": frozenset({"update_record"})})
    assert ScopeOracle(manifest).judge(Observation("", [call])).breached  # billing may not update records
    assert call.agent == "billing" and not ScopeOracle(PermissionManifest({"billing": frozenset({"update_record"})})
                                                       ).judge(Observation("", [call])).breached


def test_a_header_naming_another_agent_is_not_believed_only_counted():
    keys, tokens, web, observer = _setup()
    _send(web, tokens["billing"], hint="records")
    _send(web, tokens["billing"], hint="billing")  # its own name is no claim at all
    summary = observer.summary()["agents"]
    assert [a["name"] for a in summary] == ["billing"] and summary[0]["claimed_other"] == 1
    assert [f.kind for f in posture(observer.profile("p")) if f.kind == "identity_mismatch"] == ["identity_mismatch"]


def test_an_agent_known_only_by_a_guess_is_flagged_as_unauthenticated():
    keys, tokens, web, observer = _setup()
    _send(web, tokens["unbound"], hint="billing")
    profile = observer.profile("p")
    assert profile.agent_info[0].authenticated is False
    finding = next(f for f in posture(profile) if f.kind == "unauthenticated_agent")
    assert finding.agent == "billing" and finding.severity == "medium" and "own gateway key" in finding.detail


def test_one_unbound_request_taints_an_agent_that_was_authenticated():
    keys, tokens, web, observer = _setup()
    _send(web, tokens["billing"])
    assert observer.profile("p").agent_info[0].authenticated is True
    _send(web, tokens["unbound"], hint="billing")  # someone reaching the agent without its key
    assert observer.profile("p").agent_info[0].authenticated is False


def test_an_authenticated_agent_with_a_clean_record_has_no_identity_finding():
    keys, tokens, web, observer = _setup()
    _send(web, tokens["billing"])
    assert [f for f in posture(observer.profile("p")) if f.kind in ("unauthenticated_agent", "identity_mismatch")] == []


def test_the_admin_profile_reports_how_each_agent_was_identified():
    keys, tokens, web, observer = _setup()
    admin = keys.issue("admin", ADMIN, **BIG)
    _send(web, tokens["billing"])
    reported = web.get("/profile", headers=_bearer(admin)).json()["agents"][0]
    assert reported["name"] == "billing" and reported["authenticated"] is True and reported["claimed_other"] == 0


def _profile(**agents):
    tools = [DiscoveredTool(name, "", {}, "", "write", "m", agent_name=agent) for agent, names in agents.items() for name in names]
    info = [AgentInfo(agent, f"prompt of {agent}", tuple(names)) for agent, names in agents.items()]
    return TargetProfile("p", tools, info)


def test_a_baseline_holds_tools_and_a_prompt_hash_but_never_prompt_text():
    saved = baseline(_profile(billing=["update_record", "get_record"]))
    assert saved["billing"]["tools"] == ["get_record", "update_record"] and len(saved["billing"]["prompt_sha256"]) == 64
    assert "prompt of" not in str(saved) and check_baseline(copy.deepcopy(saved)) == saved


def test_drift_is_empty_when_nothing_changed_and_precise_when_something_did():
    before = baseline(_profile(billing=["get_record"], records=["update_record"]))
    assert drift(_profile(billing=["get_record"], records=["update_record"]), before) == []
    changed = drift(_profile(billing=["get_record", "send_payment"], extra=["new_tool"]), before)
    kinds = {(f.kind, f.agent): f for f in changed}
    assert kinds[("tools_added", "billing")].tools == ("send_payment",) and kinds[("tools_added", "billing")].severity == "high"
    assert ("agent_added", "extra") in kinds and ("agent_missing", "records") in kinds
    assert drift(_profile(billing=[]), baseline(_profile(billing=["get_record"])))[0].kind == "tools_removed"


def test_a_changed_prompt_is_drift_and_an_unknown_prompt_is_not():
    profile = _profile(billing=["get_record"])
    before = baseline(profile)
    edited = TargetProfile("p", profile.tools, [AgentInfo("billing", "a different prompt", ("get_record",))])
    assert [f.kind for f in drift(edited, before)] == ["prompt_changed"]
    unknown = TargetProfile("p", profile.tools)  # in-process discovery may not know the prompt
    assert drift(unknown, before) == [] and drift(profile, baseline(unknown)) == []


def test_a_saved_baseline_is_checked_as_strictly_as_a_manifest():
    good = baseline(_profile(billing=["get_record"]))
    digest = good["billing"]["prompt_sha256"]
    bad = [None, [], "text", {"bad\nname": good["billing"]}, {"billing": "text"},
           {"billing": {"tools": ["get_record"]}}, {"billing": {**good["billing"], "extra": 1}},
           {"billing": {"tools": "get_record", "prompt_sha256": digest}}, {"billing": {"tools": [1], "prompt_sha256": digest}},
           {"billing": {"tools": ["bad\ntool"], "prompt_sha256": digest}}, {"billing": {"tools": [], "prompt_sha256": digest.upper()}},
           {"billing": {"tools": [], "prompt_sha256": "abc"}}, {f"a{i}": good["billing"] for i in range(201)}]
    for data in bad:
        with pytest.raises(ValueError):
            check_baseline(data)
        with pytest.raises(ValueError):
            drift(_profile(billing=["get_record"]), data)


def test_the_inventory_carries_the_baseline_and_how_each_agent_was_identified():
    profile = _profile(billing=["get_record"])
    report = inventory(profile, None, [])
    assert report["baseline"] == baseline(profile) and report["agents"][0]["authenticated"] is None


def test_an_assessment_reports_drift_in_the_signed_evidence_and_refuses_a_bad_baseline(tmp_path):
    from purpleteam.assessment import Assessment
    from purpleteam.audit.ledger import AuditLedger
    from test_assessment import ATTACK, ORACLE, PROFILE, _Agent, _looked_up

    saved = baseline(PROFILE)
    saved["vendor"]["tools"] = ["lookup_vendor"]  # the baseline did not have update_vendor_bank
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    report = asyncio.run(Assessment(lambda guard: _Agent(guard), ORACLE, PROFILE, ledger,
                                    legit=[("Look up acme", _looked_up)], baseline=saved).run([ATTACK]))
    found = {(f["kind"], f["agent"]) for f in report.identity["findings"]}
    assert ("tools_added", "vendor") in found
    (event,) = [e for e in ledger.events() if e["kind"] == "identity"]
    assert any(f["kind"] == "tools_added" for f in event["payload"]["findings"]) and report.chain_ok
    with pytest.raises(ValueError, match="baseline"):
        Assessment(lambda guard: _Agent(guard), ORACLE, PROFILE, ledger, legit=[], baseline={"vendor": "nonsense"})
