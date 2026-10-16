"""Blast radius: the chains an attacker can string together, who they reach, and how sure we are."""

import json

import pytest

from purpleteam.blast import SEVERITY, blast_radius
from purpleteam.discovery import DiscoveredTool, TargetProfile
from purpleteam.identity import PermissionManifest


def _profile(**agents):
    """_profile(billing={"read_email": "read", "update_record": "write"}) -> a profile of those agents and tools."""
    return TargetProfile("p", [DiscoveredTool(name, "", {}, "", risk, "m", agent_name=agent)
                               for agent, tools in agents.items() for name, risk in tools.items()])


def _kinds(report, agent=None):
    return {c.kind for c in report.chains if agent is None or agent in c.agents}


def _score(report, agent, *, reach=False):
    radius = next(r for r in report.agents if r.agent == agent)
    return radius.reach if reach else radius.score


def test_a_tool_that_runs_what_the_model_writes_is_a_critical_chain():
    report = blast_radius(_profile(reports={"run_query": "execute"}))
    assert _kinds(report) == {"unbounded_execution"} and report.chains[0].severity == "critical"
    assert _score(report, "reports") >= SEVERITY["critical"]


def test_private_data_untrusted_input_and_an_outward_channel_make_the_lethal_trifecta():
    report = blast_radius(_profile(helper={"read_records": "read", "read_email": "read", "send_note": "external"}))
    assert {"lethal_trifecta", "injection_to_action", "exfiltration_path"} <= _kinds(report)
    assert _score(report, "helper") >= SEVERITY["critical"]


def test_untrusted_input_plus_an_action_is_injection_to_action_and_neither_alone_is():
    assert "injection_to_action" in _kinds(blast_radius(_profile(a={"read_email": "read", "update_record": "write"})))
    assert "injection_to_action" not in _kinds(blast_radius(_profile(a={"read_email": "read"})))
    assert "injection_to_action" not in _kinds(blast_radius(_profile(a={"update_record": "write"})))


def test_reading_plus_sending_is_an_exfiltration_path_and_deleting_is_destructive():
    report = blast_radius(_profile(a={"get_record": "read", "send_note": "external"}, b={"drop_table": "delete"}))
    assert "exfiltration_path" in _kinds(report, "a") and "destructive_action" in _kinds(report, "b")
    assert "exfiltration_path" not in _kinds(report, "b")


def test_a_write_alone_is_only_the_low_baseline_and_undeclared_permissions_raise_the_score():
    undeclared = blast_radius(_profile(a={"update_record": "write"}))
    declared = blast_radius(_profile(a={"update_record": "write"}), manifest=PermissionManifest({"a": frozenset({"update_record"})}))
    assert _kinds(undeclared) == {"state_change"} and undeclared.chains[0].severity == "low"
    assert _score(undeclared, "a") == _score(declared, "a") == 15  # amplifiers are listed, not scored
    assert "no declared permissions" in undeclared.agents[0].amplifiers and declared.agents[0].amplifiers == []


def test_an_agent_with_nothing_dangerous_scores_zero():
    report = blast_radius(_profile(a={"get_record": "read"}))
    assert report.chains == [] and _score(report, "a") == 0


def test_a_shared_credential_lets_one_compromised_agent_reach_the_others_tools():
    profile = _profile(inbox={"read_email": "read"}, sender={"send_note": "external", "get_record": "read"})
    alone = blast_radius(profile, credentials={"inbox": "inbox-key", "sender": "sender-key"})
    shared = blast_radius(profile, credentials={"inbox": "one-key", "sender": "one-key"})
    assert "lethal_trifecta" not in _kinds(alone)
    chain = next(c for c in shared.chains if c.kind == "lethal_trifecta")
    assert chain.agents == ("inbox", "sender") and chain.via == "a shared credential" and "one-key" in chain.detail
    assert "shares a credential with another agent" in shared.agents[0].amplifiers and chain.severity == "high"
    assert _score(shared, "inbox") == 0 and _score(shared, "inbox", reach=True) > _score(alone, "inbox", reach=True) == 0


def test_a_declared_hand_off_carries_untrusted_content_to_the_next_agents_tools():
    profile = _profile(intake={"read_email": "read"}, middle={"get_record": "read"}, payer={"send_payment": "external"})
    report = blast_radius(profile, handoffs=[("intake", "middle"), ("middle", "payer")])
    chain = next(c for c in report.chains if c.kind == "cross_agent_propagation")
    assert chain.agents == ("intake", "payer") and chain.via == "a declared hand-off"  # reached through the middle agent
    assert "propagation between agents was not assessed" in " ".join(blast_radius(profile).assumptions)
    assert not any(c.kind == "cross_agent_propagation" for c in blast_radius(profile).chains)


def test_bad_inputs_are_refused_not_ignored():
    profile = _profile(a={"read_email": "read"}, b={"update_record": "write"})
    with pytest.raises(ValueError, match="not found"):
        blast_radius(profile, handoffs=[("a", "nobody")])
    with pytest.raises(ValueError, match="not found"):
        blast_radius(profile, untrusted={"read_emial"})  # a typo must not silently assess nothing
    with pytest.raises(ValueError, match="credential"):
        blast_radius(profile, credentials={"a": "Zx9Qm2Lp7Vk4Rt8Wn3Yb6Hc1"})  # a bare random token is a secret, not a label


def test_proven_breaches_turn_a_prediction_into_a_demonstration():
    profile = _profile(a={"read_email": "read", "update_record": "write"})
    predicted = blast_radius(profile)
    demonstrated = blast_radius(profile, proven=[("a", "update_record")])
    assert {c.status for c in predicted.chains} == {"predicted"}
    assert {c.kind: c.status for c in demonstrated.chains} == {"injection_to_action": "demonstrated", "state_change": "demonstrated"}
    other = blast_radius(profile, proven=[("a", "something_else"), ("zzz", "update_record")])
    assert {c.status for c in other.chains} == {"predicted"}


def test_tools_never_used_legitimately_are_listed_as_removable_only_when_usage_is_known():
    profile = _profile(a={"get_record": "read", "update_record": "write", "drop_table": "delete"})
    report = blast_radius(profile, used={"get_record", "update_record"})
    assert report.agents[0].removable == ["drop_table"]
    unknown = blast_radius(profile)
    assert unknown.agents[0].removable == [] and "no tool is suggested for removal" in " ".join(unknown.assumptions)


def test_assumptions_say_what_was_guessed_and_what_was_not_assessed():
    profile = _profile(a={"read_email": "read"})
    guessed = blast_radius(profile).assumptions
    assert any("guessed from channel words" in a for a in guessed) and any("no credentials" in a for a in guessed)
    explicit = blast_radius(profile, untrusted={"read_email"}, credentials={"a": "key"}, used={"read_email"},
                            handoffs=[("a", "a")]).assumptions
    assert explicit == []


def test_the_ranking_is_deterministic_bounded_and_serialisable():
    profile = _profile(a={"read_email": "read", "get_x": "read", "send_x": "external", "run_code": "execute",
                          "drop_x": "delete", "set_x": "write"}, b={"set_y": "write"}, c={"get_z": "read"})
    first, second = blast_radius(profile), blast_radius(profile)
    assert json.dumps(first.to_dict()) == json.dumps(second.to_dict())
    scores = [r.score for r in first.agents]
    assert scores == sorted(scores, reverse=True) and max(scores) <= 100 and scores[0] > scores[1] > scores[2] == 0
    assert all(r.reach >= r.score for r in first.agents)
    assert all(c["fix"] and c["severity"] in SEVERITY for c in first.to_dict()["chains"])


def test_the_real_ledgerpilot_profile_has_an_unbounded_tool_and_shared_credential_reach():
    from purpleteam.targets.ledgerpilot import SHARED_CREDENTIAL, credentials, discover_profile

    profile = discover_profile()
    alone = blast_radius(profile, untrusted={"read_email"})
    shared = blast_radius(profile, untrusted={"read_email"}, credentials=credentials(profile))
    assert "unbounded_execution" in _kinds(alone)
    assert any(c.via == "a shared credential" and SHARED_CREDENTIAL in c.detail for c in shared.chains)
    assert len({a for c in shared.chains if c.via == "a shared credential" for a in c.agents}) == len(profile.agents)
    assert [r.score for r in shared.agents] == [r.score for r in alone.agents]  # sharing changes reach, not what an agent does alone
    assert max(r.reach for r in shared.agents) >= max(r.reach for r in alone.agents)


def _assessed(tmp_path, blast):
    import asyncio

    from purpleteam.assessment import Assessment
    from purpleteam.audit.ledger import AuditLedger
    from test_assessment import ATTACK, ORACLE, PROFILE, _Agent, _looked_up

    ledger = AuditLedger(tmp_path / "audit.jsonl")
    assessment = Assessment(lambda guard: _Agent(guard), ORACLE, PROFILE, ledger, legit=[("Look up acme", _looked_up)],
                            blast=blast)
    return ledger, asyncio.run(assessment.run([ATTACK]))


def test_an_assessment_that_asks_for_it_signs_the_blast_radius_and_marks_what_its_breaches_proved(tmp_path):
    ledger, report = _assessed(tmp_path, blast={"used": {"lookup_vendor", "update_vendor_bank"}})
    chains = {c["kind"]: c["status"] for c in report.blast["chains"]}
    assert chains == {"state_change": "demonstrated"}  # the breach went through update_vendor_bank
    assert report.to_dict()["blast_radius"] == report.blast and report.blast["agents"][0]["agent"] == "vendor"
    (event,) = [e for e in ledger.events() if e["kind"] == "blast_radius"]
    assert event["payload"]["chains"][0]["status"] == "demonstrated"
    assert "EU AI Act · Art. 9" in report.coverage and report.chain_ok


def test_without_the_option_an_assessment_is_exactly_as_before(tmp_path):
    ledger, report = _assessed(tmp_path, blast=None)
    assert report.blast == {} and not [e for e in ledger.events() if e["kind"] == "blast_radius"]
