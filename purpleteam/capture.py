"""Runtime discovery: watch a target build its agents, with no change to the target.

Agent frameworks funnel construction through one function (LangChain's ``create_agent``,
LangGraph's ``create_react_agent``). While ``capture_agents`` is active those functions are
wrapped everywhere they have been imported, so building the target reveals each agent's name,
system prompt and tools — including tools made inside functions, which a scan of module globals
can never see, tools contributed by middleware, and opaque provider-native tools (recorded, and
treated as dangerous, because their behaviour cannot be inspected).

When the block ends every module is swept again and each wrapper put back, including in modules
imported while the target was being built, and even if the target's own code raised.

By default the wrapped function returns a placeholder instead of compiling the agent, so a target
can be inspected without a model, credentials or network. Pass ``build_graphs=True`` when the
target needs real agents while it is being constructed.

This runs the target's construction code in this process, like the rest of the in-process MVP:
use it on targets you already trust, and sandbox it for anything else. It is not thread-safe.
Agent and tool names must be plain names; anything else fails discovery loudly rather than
reaching the checks that compare them with a manifest.
"""

from __future__ import annotations

import functools
import importlib
import sys
import threading
import warnings
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from purpleteam.discovery import READ, WRITE, AgentInfo, DiscoveredTool, TargetProfile, classify_risk, describe_tool
from purpleteam.identity import valid_name

_FACTORIES = (("langchain.agents", "create_agent"), ("langgraph.prebuilt", "create_react_agent"))
_LOCK = threading.Lock()


class DiscoveryError(RuntimeError):
    """The target was built but no agents could be seen (or recording failed)."""


class UnbuiltAgent:
    """Stands in for a compiled agent while a target is built only to be inspected."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, attribute: str) -> Any:
        if attribute.startswith("__"):  # let hasattr, copy and pickle see an ordinary object
            raise AttributeError(attribute)
        raise RuntimeError(f"agent '{self._name}' was built for discovery only and cannot run")


OnFound = Callable[[AgentInfo, list[DiscoveredTool]], None]


class AgentCapture:
    def __init__(self, on_found: OnFound | None = None) -> None:
        self.agents: list[AgentInfo] = []
        self.tools: list[DiscoveredTool] = []
        self.errors: list[str] = []
        self.closed = False  # once set, a wrapper that survived the block just calls the real function
        self._on_found = on_found  # told about each agent the moment the target constructs it

    def record(self, name: Any, prompt: str, tools: list[Any]) -> None:
        if not valid_name(name):
            raise ValueError(f"agent name {str(name)[:40]!r} is not a plain name")
        described = [self._describe(tool, name) for tool in tools]
        for tool in described:
            if not valid_name(tool.name):
                raise ValueError(f"tool name {str(tool.name)[:40]!r} of agent {name!r} is not a plain name")
        agent = AgentInfo(name, prompt, tuple(t.name for t in described))
        self.agents.append(agent)
        self.tools.extend(described)
        if self._on_found is not None:
            try:
                self._on_found(agent, described)
            except Exception as error:  # a listener must never change what was discovered
                self.errors.append(f"discovery listener failed: {type(error).__name__}")

    def profile(self, name: str) -> TargetProfile:
        return TargetProfile(name, list(self.tools), list(self.agents))

    @staticmethod
    def _describe(tool: Any, agent: str) -> DiscoveredTool:
        from langchain_core.tools import BaseTool, StructuredTool

        if isinstance(tool, BaseTool):
            return describe_tool(tool, agent_name=agent)
        if callable(tool):
            try:
                return describe_tool(StructuredTool.from_function(tool), agent_name=agent)
            except Exception:  # not introspectable as a function: fall through to the opaque record
                pass
        return _opaque(tool, agent)


def _opaque(tool: Any, agent: str) -> DiscoveredTool:
    """A tool whose behaviour cannot be seen (a provider-native dict, a custom object): never read-only."""
    label = tool.get("type") or tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None)
    name = label if valid_name(label) else type(tool).__name__
    risk = classify_risk(name, "", {})
    return DiscoveredTool(
        name=name, description="an opaque or provider-native tool: its behaviour is unknown, so it is treated as "
        "dangerous", args={}, source="?", risk=WRITE if risk == READ else risk, module="", tool=None,
        agent_name=agent)


def _prompt_text(value: Any) -> str:
    """The system prompt when it is plain text; a callable or template is not statically known."""
    if isinstance(value, str):
        return value
    content = getattr(value, "content", None)  # a SystemMessage
    return content if isinstance(content, str) else ""


def _factories() -> list[Any]:
    found: list[Any] = []
    for module_name, attribute in _FACTORIES:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                function = getattr(importlib.import_module(module_name), attribute, None)
        except Exception:  # an absent or broken framework is simply not one this target uses
            continue
        if callable(function) and all(function is not other for other in found):
            found.append(function)
    return found


def _namespaces() -> Iterator[dict]:
    for module in list(sys.modules.values()):
        namespace = getattr(module, "__dict__", None)
        if isinstance(namespace, dict):
            yield namespace


def _tools_of(args: tuple, kwargs: dict) -> tuple[list[Any], tuple, dict]:
    """The agent's tools (``create_agent``'s second argument, or ``tools=``), plus middleware tools.

    A generator would be spent by reading it, so it is turned into a list that the real call gets too.
    A ToolNode is read through ``tools_by_name`` and passed on untouched.
    """
    tools = args[1] if len(args) > 1 else kwargs.get("tools")
    by_name = getattr(tools, "tools_by_name", None)
    if isinstance(by_name, dict):
        listed = list(by_name.values())
    elif tools is not None and not isinstance(tools, (list, tuple)):
        listed = tools = list(tools)
        args, kwargs = (args[:1] + (tools,) + args[2:], kwargs) if len(args) > 1 else (args, {**kwargs, "tools": tools})
    else:
        listed = list(tools or [])
    middleware = kwargs.get("middleware")
    if middleware is not None and not isinstance(middleware, (list, tuple)):
        middleware = list(middleware)
        kwargs = {**kwargs, "middleware": middleware}
    from_middleware = [t for m in (middleware or ()) for t in (getattr(m, "tools", None) or ())]
    return [*listed, *from_middleware], args, kwargs


def _wrap(original: Any, capture: AgentCapture, build_graphs: bool) -> Any:
    @functools.wraps(original)
    def create(*args: Any, **kwargs: Any) -> Any:
        if capture.closed:
            return original(*args, **kwargs)
        name = kwargs.get("name") or f"agent{len(capture.agents) + 1}"
        try:  # observing must never stop the target from being built
            tools, args, kwargs = _tools_of(args, kwargs)
            capture.record(name, _prompt_text(kwargs.get("system_prompt", kwargs.get("prompt"))), tools)
        except Exception as error:
            capture.errors.append(f"{str(name)[:40]}: {type(error).__name__}: {error}")
        return original(*args, **kwargs) if build_graphs else UnbuiltAgent(str(name))

    return create


@contextmanager
def capture_agents(*, build_graphs: bool = False, on_found: OnFound | None = None) -> Iterator[AgentCapture]:
    capture = AgentCapture(on_found)
    wrappers: dict[int, tuple[Any, Any]] = {}  # id(wrapper) -> (wrapper, original)
    with _LOCK:
        try:
            for original in _factories():
                wrapper = _wrap(original, capture, build_graphs)
                wrappers[id(wrapper)] = (wrapper, original)
                for namespace in _namespaces():
                    for attribute, value in list(namespace.items()):
                        if value is original:
                            namespace[attribute] = wrapper
            yield capture
        finally:  # sweep again: modules imported during the block bound the wrapper too
            capture.closed = True  # and make any wrapper the sweep cannot reach (a default argument, a partial) inert
            for namespace in _namespaces():
                for attribute, value in list(namespace.items()):
                    entry = wrappers.get(id(value))
                    if entry is not None and entry[0] is value:
                        namespace[attribute] = entry[1]


def profile_runtime(name: str, build: Callable[[], Any], *, build_graphs: bool = False,
                    on_found: OnFound | None = None) -> TargetProfile:
    """Build the target once under observation and return what it was seen to contain; ``on_found`` hears about
    each agent (with its tools) the moment it is constructed, for a caller showing discovery as it happens."""
    with capture_agents(build_graphs=build_graphs, on_found=on_found) as capture:
        build()
    if capture.errors or not capture.agents:
        detail = "; ".join(capture.errors) or "no agent construction was observed"
        raise DiscoveryError(f"discovery of '{name}' failed: {detail}")
    return capture.profile(name)
