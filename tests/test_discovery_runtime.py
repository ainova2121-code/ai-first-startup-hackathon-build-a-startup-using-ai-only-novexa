"""Runtime discovery sees what a target is built from: agents, system prompts and tools,
including tools that only exist inside functions, and puts everything back afterwards."""

import copy
import importlib

import pytest
from langchain.agents import create_agent
from langchain_core.messages import SystemMessage

import langchain.agents
from fixtures import supportbot
from purpleteam.capture import DiscoveryError, UnbuiltAgent, _tools_of, capture_agents, profile_runtime
from purpleteam.targets.ledgerpilot import discover_profile

AGENTS = {"intake", "vendor", "matching", "approval", "payment", "inquiry"}


def _lookup_thing(name: str) -> str:
    """Find a thing by name."""
    return name


def _update_thing(name: str) -> str:
    """Change a thing."""
    return name


def test_ledgerpilots_six_agents_and_their_tools_are_discovered():
    profile = discover_profile()
    assert profile.agents == AGENTS
    by_agent = {a.name: set(a.tool_names) for a in profile.agent_info}
    assert by_agent["vendor"] == {"lookup_vendor", "update_vendor_bank", "confirm_vendor"}
    assert by_agent["payment"] == {"schedule_payment"}
    assert by_agent["inquiry"] == {"query_ledger"}
    assert {t.agent for t in profile.tools if t.name == "update_vendor_bank"} == {"vendor"}


def test_tools_are_classified_by_what_they_do_with_unknown_actions_treated_as_writes():
    risk = {t.name: t.risk for t in discover_profile().tools}
    assert risk["lookup_vendor"] == risk["get_po"] == risk["extract_invoice"] == "read"
    assert risk["query_ledger"] == "execute"              # a raw SQL argument
    assert risk["request_approval"] == "external"
    for written in ("update_vendor_bank", "schedule_payment", "record_invoice", "mark_matched", "record_approval"):
        assert risk[written] == "write", written
    assert {"schedule_payment", "update_vendor_bank", "record_invoice"} <= discover_profile().dangerous_tools


def test_prompts_are_kept_but_never_shown_in_reprs_or_reports():
    profile = discover_profile()
    assert all(a.prompt and a.prompt_chars == len(a.prompt) for a in profile.agent_info)
    assert len({a.prompt_sha256 for a in profile.agent_info}) == len(profile.agent_info)
    assert not any(a.prompt[:40] in repr(a) for a in profile.agent_info)


def test_a_reference_imported_before_capture_is_wrapped_and_then_restored():
    original = langchain.agents.create_agent
    assert create_agent is original
    with capture_agents() as capture:
        assert create_agent is not original                     # this module imported the name earlier
        create_agent(object(), [_lookup_thing, _update_thing], system_prompt="be careful", name="helper")
    assert create_agent is original and langchain.agents.create_agent is original
    assert [(a.name, a.prompt, a.tool_names) for a in capture.agents] == [
        ("helper", "be careful", ("_lookup_thing", "_update_thing"))]
    assert {t.name: t.risk for t in capture.tools}["_update_thing"] == "write"


def test_everything_is_restored_even_if_the_target_raises():
    original = langchain.agents.create_agent
    with pytest.raises(RuntimeError, match="boom"):
        with capture_agents():
            raise RuntimeError("boom")
    assert langchain.agents.create_agent is original and create_agent is original


def test_agents_are_placeholders_by_default_and_real_when_asked():
    with capture_agents() as stubbed:
        agent = supportbot._build()
    assert isinstance(agent, UnbuiltAgent)
    with pytest.raises(RuntimeError, match="discovery only"):
        agent.invoke({})
    with capture_agents(build_graphs=True) as real:
        graph = supportbot._build()
    assert hasattr(graph, "invoke") and not isinstance(graph, UnbuiltAgent)
    for capture in (stubbed, real):  # a plain @tool function and an unnamed agent
        assert [(a.name, a.prompt, set(a.tool_names)) for a in capture.agents] == [
            ("agent1", "You are a wallet assistant.", {"get_balance", "transfer"})]


def test_a_system_message_prompt_is_read_as_text():
    with capture_agents() as capture:
        create_agent(object(), [], system_prompt=SystemMessage("only as a message"), name="m")
    assert capture.agents[0].prompt == "only as a message"


def test_a_failure_to_record_never_stops_the_target_but_is_reported():
    with capture_agents() as capture:
        result = create_agent(object(), 42, system_prompt="x", name="odd")  # tools is not iterable
    assert isinstance(result, UnbuiltAgent) and "odd" in capture.errors[0]
    with pytest.raises(DiscoveryError, match="odd"):
        profile_runtime("t", lambda: create_agent(object(), 42, system_prompt="x", name="odd"))


def test_discovery_that_sees_no_agents_is_an_error_not_an_empty_profile():
    with pytest.raises(DiscoveryError, match="no agent construction"):
        profile_runtime("nothing", lambda: None)


def test_a_module_first_imported_during_capture_is_restored_too(tmp_path, monkeypatch):
    (tmp_path / "late_target.py").write_text("from langchain.agents import create_agent\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    original = langchain.agents.create_agent
    try:
        with capture_agents():
            late = importlib.import_module("late_target")
            assert late.create_agent is not original  # it bound the wrapper while the block was open
        assert late.create_agent is original
    finally:
        import sys

        sys.modules.pop("late_target", None)


class _Middleware:
    tools = [_update_thing]


def test_opaque_provider_tools_and_middleware_tools_are_recorded_and_never_read_only():
    with capture_agents() as capture:
        create_agent(object(), [_lookup_thing, {"type": "code_interpreter"}, {"type": "get_weather"}],
                     system_prompt="p", name="ops", middleware=[_Middleware()])
    risk = {t.name: t.risk for t in capture.tools}
    assert set(risk) == {"_lookup_thing", "code_interpreter", "get_weather", "_update_thing"}
    assert risk["code_interpreter"] == "write" and risk["get_weather"] == "write"  # unknown behaviour is dangerous
    assert risk["_update_thing"] == "write" and risk["_lookup_thing"] == "read"
    assert "unknown" in next(t for t in capture.tools if t.name == "code_interpreter").description


def test_a_generator_of_tools_is_not_spent_by_discovery():
    tools, args, kwargs = _tools_of((object(), (t for t in [_lookup_thing, _update_thing])), {})
    assert [t.__name__ for t in tools] == ["_lookup_thing", "_update_thing"] and args[1] is not None and not kwargs
    assert [t.__name__ for t in args[1]] == ["_lookup_thing", "_update_thing"]  # the real call gets the list
    tools, args, kwargs = _tools_of((object(),), {"tools": iter([_lookup_thing])})
    assert [t.__name__ for t in kwargs["tools"]] == ["_lookup_thing"]


@pytest.mark.parametrize("name", ["bad\nname", "x" * 200, 123, "weird!name", "two  spaces"])
def test_odd_agent_names_fail_discovery_loudly_instead_of_reaching_later_checks(name):
    with pytest.raises(DiscoveryError, match="plain name"):
        profile_runtime("t", lambda: create_agent(object(), [], system_prompt="x", name=name))


def test_a_tool_with_an_odd_name_fails_discovery():
    def build():
        create_agent(object(), [{"type": "bad\nname"}], system_prompt="x", name="ok")  # falls back to its class name
        create_agent(object(), [_lookup_thing], system_prompt="x", name="ok too")

    assert profile_runtime("t", build).agents == {"ok", "ok too"}  # a plain agent name with a space is fine


def test_the_placeholder_behaves_for_copy_and_attribute_probes_but_refuses_to_run():
    agent = UnbuiltAgent("a")
    assert copy.copy(agent) is not agent and not hasattr(agent, "__wrapped__")
    with pytest.raises(RuntimeError):
        agent.invoke({})
