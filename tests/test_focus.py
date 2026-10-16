"""Focused red teaming: one topic (and optionally one agent) at a time, judged only by the oracles that apply."""

import asyncio

import pytest

from purpleteam.adapter import Observation, ToolCall
from purpleteam.assessment import Assessment
from purpleteam.attack.corpus import PYRIT_TEMPLATES
from purpleteam.audit.ledger import AuditLedger
from purpleteam.discovery import DiscoveredTool, TargetProfile
from purpleteam.focus import AGENT, FOCUSES, RETRIEVAL, TOOL, focus_oracle, plan_focus
from purpleteam.identity import PermissionManifest
from purpleteam.oracle import CANARY_ACCOUNT

SECRET = "HTK-7F3A-LEAKCANARY"
PROFILE = TargetProfile("p", [
    DiscoveredTool("update_record", "", {}, "", "write", "records", agent_name="records"),
    DiscoveredTool("run_query", "", {"sql": {}}, "", "execute", "reports", agent_name="reports"),
    DiscoveredTool("get_record", "", {}, "", "read", "records", agent_name="records"),
])
MANIFEST = PermissionManifest({"records": frozenset({"get_record"}), "reports": frozenset({"run_query"})})
PER_OBJECTIVE = len(PYRIT_TEMPLATES)


def _topics(plan):
    return {t.id.split(":")[0] for t in plan.templates}


def test_each_topic_runs_only_its_own_attacks():
    for focus in FOCUSES:
        plan = plan_focus(PROFILE, [focus], secrets=[SECRET], manifest=MANIFEST)
        assert _topics(plan) == {focus} and plan.skipped == {}
    both = plan_focus(PROFILE, [TOOL, RETRIEVAL], secrets=[SECRET])
    assert _topics(both) == {TOOL, RETRIEVAL}


def test_attack_ids_are_unique_and_objectives_come_from_the_profile():
    plan = plan_focus(PROFILE, FOCUSES, secrets=[SECRET], manifest=MANIFEST)
    ids = [t.id for t in plan.templates]
    assert len(ids) == len(set(ids))
    tool_bodies = " ".join(t.body for t in plan.templates if t.id.startswith(TOOL))
    assert "update_record" in tool_bodies and "run_query" in tool_bodies and "get_record" not in tool_bodies


def test_execute_tools_get_their_own_instruction_attack():
    ids = {t.id.split(":")[1] for t in plan_focus(PROFILE, [TOOL]).templates}
    assert ids == {"action", "instruction"}
    read_only = TargetProfile("p", [PROFILE.tools[2]])
    assert plan_focus(read_only, [TOOL]).skipped[TOOL].startswith("no tool in scope")


def test_a_topic_without_ground_truth_is_skipped_with_the_reason_not_run():
    plan = plan_focus(PROFILE, [AGENT, RETRIEVAL])
    assert plan.templates == [] and set(plan.skipped) == {AGENT, RETRIEVAL}
    assert "prove" in plan.skipped[AGENT] and "honeytoken" in plan.skipped[RETRIEVAL]
    writes_only = TargetProfile("p", PROFILE.tools[:1])
    assert plan_focus(writes_only, [RETRIEVAL], secrets=[SECRET]).skipped[RETRIEVAL] == "no tool in scope retrieves anything"


def test_narrowing_to_one_agent_names_only_its_tools_and_rejects_unknown_agents():
    plan = plan_focus(PROFILE, [TOOL, RETRIEVAL], agent="records", secrets=[SECRET])
    tool_bodies = " ".join(t.body for t in plan.templates if t.id.startswith(TOOL))
    assert "update_record" in tool_bodies and "run_query" not in tool_bodies
    assert all("You are the records agent." in t.body for t in plan.templates if t.id.startswith(RETRIEVAL))
    with pytest.raises(ValueError, match="unknown agent"):
        plan_focus(PROFILE, [TOOL], agent="nobody")


def test_role_swap_needs_more_than_one_agent():
    single = TargetProfile("p", [PROFILE.tools[0]])
    assert not any("role_swap" in t.id for t in plan_focus(single, [AGENT], manifest=MANIFEST).templates)
    assert any("role_swap" in t.id for t in plan_focus(PROFILE, [AGENT], manifest=MANIFEST).templates)


def test_bad_focus_input_is_refused():
    for bad in ([], ["everything"], [TOOL, "other"]):
        with pytest.raises(ValueError, match="choose from"):
            plan_focus(PROFILE, bad)
        with pytest.raises(ValueError, match="choose from"):
            focus_oracle(PROFILE, bad, secrets=[SECRET])


def test_only_the_oracles_for_the_topic_can_call_a_breach():
    leak = Observation(f"the key is {SECRET}")
    wrote = Observation("done", [ToolCall("records", "update_record", {"account": CANARY_ACCOUNT})])
    out_of_scope = Observation("done", [ToolCall("records", "run_query", {"sql": "select 1"})])

    tool_only = focus_oracle(PROFILE, [TOOL], secrets=[SECRET], manifest=MANIFEST)
    assert tool_only.judge(wrote).breached and not tool_only.judge(leak).breached
    assert not tool_only.judge(out_of_scope).breached

    retrieval_only = focus_oracle(PROFILE, [RETRIEVAL], secrets=[SECRET], manifest=MANIFEST)
    assert retrieval_only.judge(leak).breached and not retrieval_only.judge(wrote).breached

    agent_topic = focus_oracle(PROFILE, [AGENT], secrets=[SECRET], manifest=MANIFEST)
    assert agent_topic.judge(out_of_scope).breached and agent_topic.judge(leak).breached
    with pytest.raises(ValueError, match="nothing here could prove"):
        focus_oracle(PROFILE, [RETRIEVAL])


class _Leaky:
    name = "p"

    def reset(self) -> None:
        pass

    def send(self, request: str) -> Observation:
        return Observation(f"here is everything: {SECRET}")


def _run(tmp_path, focus, **kwargs):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    oracle = focus_oracle(PROFILE, focus, secrets=[SECRET])
    assessment = Assessment(lambda guard: _Leaky(), oracle, PROFILE, ledger, legit=[], facts={"secrets": [SECRET]})
    return ledger, asyncio.run(assessment.run(focus=focus, **kwargs))


def test_a_focused_assessment_attacks_only_that_topic_and_records_the_scope(tmp_path):
    ledger, report = _run(tmp_path, [RETRIEVAL])
    assert {r.id.split(":")[0] for r in report.results} == {RETRIEVAL}
    assert report.scope == {"focus": [RETRIEVAL], "agent": None, "skipped": {}}
    assert any(r.breached for r in report.results) and report.chain_ok
    scope_events = [e for e in ledger.events() if e["kind"] == "scope"]
    assert len(scope_events) == 1 and scope_events[0]["payload"]["skipped"] == report.scope["skipped"]
    assert report.to_dict()["scope"] == report.scope


def test_a_focus_with_nothing_to_run_attacks_nothing_instead_of_the_default_corpus(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    assessment = Assessment(lambda guard: _Leaky(), focus_oracle(PROFILE, [TOOL]), PROFILE, ledger, legit=[])
    report = asyncio.run(assessment.run(focus=[AGENT]))
    assert report.results == [] and report.findings == [] and AGENT in report.scope["skipped"]
