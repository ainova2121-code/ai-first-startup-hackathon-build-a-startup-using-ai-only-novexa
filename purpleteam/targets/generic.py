"""A Target for any LangChain / LangGraph multi-agent, with no changes to its code.

You supply only how to call it and how to reset it. Discovery finds its tools; this adapter
wraps each one in place so every call is recorded as a ToolCall. The target never imports
the platform and needs no EventSink. Observation only — enforcement (the defender's Guard) is
a separate concern.

NOTE: the MVP runs the target in this process. Trusted targets and the demo are fine; the
production story is to run each target in its own sandbox (subprocess/container).
"""

from __future__ import annotations

import functools
import inspect
from typing import Any

from purpleteam.adapter import Observation, ToolCall
from purpleteam.discovery import DiscoveredTool, discover_tools, load_callable


def _bind(fn: Any, args: tuple, kwargs: dict) -> dict:
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs).arguments
    except TypeError:
        bound = dict(kwargs)
    bound.pop("run_manager", None)
    bound.pop("callbacks", None)
    return dict(bound)


class GenericAgentTarget:
    """Wraps a discovered multi-agent so the platform can attack and observe it."""

    def __init__(self, name: str, entry: Any, reset: Any, tools: list[DiscoveredTool]) -> None:
        self.name = name
        self.tools = tools
        self._entry = entry
        self._reset = reset
        self._calls: list[ToolCall] = []
        for discovered in tools:
            self._wrap(discovered)

    @classmethod
    def from_config(cls, config: dict[str, str]) -> "GenericAgentTarget":
        entry_ref = config["entry"]
        name = config.get("name", entry_ref.split(":")[0].split(".")[0])
        reset = load_callable(config["reset"]) if config.get("reset") else None
        return cls(name, load_callable(entry_ref), reset, discover_tools(entry_ref))

    def reset(self) -> None:
        if self._reset:
            self._reset()
        self._calls.clear()

    def send(self, request: str) -> Observation:
        self._calls.clear()
        reply = str(self._entry(request))
        return Observation(reply, list(self._calls))

    def _record(self, discovered: DiscoveredTool, fn: Any, args: tuple, kwargs: dict, result: Any) -> None:
        self._calls.append(
            ToolCall(discovered.agent, discovered.name, _bind(fn, args, kwargs), str(result)[:2000])
        )

    def _wrap(self, discovered: DiscoveredTool) -> None:
        tool = discovered.tool
        if getattr(tool, "func", None) is not None:
            tool.func = self._recorder(discovered, tool.func)
            if getattr(tool, "coroutine", None) is not None:
                tool.coroutine = self._async_recorder(discovered, tool.coroutine)
        else:
            object.__setattr__(tool, "_run", self._recorder(discovered, tool._run))

    def _recorder(self, discovered: DiscoveredTool, fn: Any):
        @functools.wraps(fn)
        def recorder(*args: Any, **kwargs: Any) -> Any:
            result = fn(*args, **kwargs)
            self._record(discovered, fn, args, kwargs, result)
            return result

        return recorder

    def _async_recorder(self, discovered: DiscoveredTool, fn: Any):
        @functools.wraps(fn)
        async def recorder(*args: Any, **kwargs: Any) -> Any:
            result = await fn(*args, **kwargs)
            self._record(discovered, fn, args, kwargs, result)
            return result

        return recorder
