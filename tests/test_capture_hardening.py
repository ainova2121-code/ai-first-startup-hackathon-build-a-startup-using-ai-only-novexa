"""Discovery must not outlive its block, change what the target is built with, or miss how tools arrive."""

from langchain.agents import create_agent
from langchain_core.tools import StructuredTool
from langgraph.prebuilt import ToolNode

import langchain.agents
from fixtures import supportbot
from purpleteam.capture import UnbuiltAgent, _tools_of, capture_agents


def _lookup_thing(name: str) -> str:
    """Find a thing by name."""
    return name


class _Middleware:
    tools = [_lookup_thing]


def test_a_wrapper_held_outside_any_module_namespace_goes_inert_when_the_block_closes():
    with capture_agents() as capture:
        def build(factory=create_agent):  # a default argument binds the wrapper where no sweep can reach it
            return factory

        stale = build()
    assert stale is not langchain.agents.create_agent  # it is still the wrapper object...
    graph = stale(supportbot._ScriptedModel(messages=iter([])), [_lookup_thing], system_prompt="x", name="late")
    assert hasattr(graph, "invoke") and not isinstance(graph, UnbuiltAgent)  # ...but it now builds the real agent
    assert capture.agents == [] and capture.closed


def test_a_generator_of_middleware_is_not_spent_and_its_tools_are_recorded():
    tools, args, kwargs = _tools_of((object(), []), {"middleware": (m for m in [_Middleware()])})
    assert [t.__name__ for t in tools] == ["_lookup_thing"]
    assert isinstance(kwargs["middleware"], list) and len(kwargs["middleware"]) == 1  # the real call still gets it


def test_a_tool_node_is_read_through_its_tools_and_passed_on_untouched():
    node = ToolNode([StructuredTool.from_function(_lookup_thing)])
    tools, args, kwargs = _tools_of((object(), node), {})
    assert [t.name for t in tools] == ["_lookup_thing"] and args[1] is node
    with capture_agents() as capture:
        create_agent(object(), node, system_prompt="x", name="nodes")
    assert capture.errors == [] and capture.agents[0].tool_names == ("_lookup_thing",)
