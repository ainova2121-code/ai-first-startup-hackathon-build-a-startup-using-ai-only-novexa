import json
from collections.abc import Callable
from typing import Any

from langchain.agents import create_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langchain_core.tools import BaseTool, StructuredTool
from langgraph.graph.state import CompiledStateGraph

from ledgerpilot.ports import Blocked, EventSink, Guard, ReviewRequired


class Agent:
    """A tool-calling agent whose input and output pass through the guard."""

    def __init__(self, name: str, graph: CompiledStateGraph, guard: Guard, sink: EventSink) -> None:
        self.name = name
        self._graph = graph
        self._guard = guard
        self._sink = sink

    def run(self, task: str) -> str:
        try:
            task = self._guard.screen(self.name, task, "input")
            self._sink.emit(self.name, "task", {"text": task})
            messages = self._graph.invoke({"messages": [HumanMessage(task)]})["messages"]
            output = self._guard.screen(self.name, messages[-1].text, "output")
        except Blocked as exc:
            self._sink.emit(self.name, "blocked", {"reason": str(exc)})
            return f"Blocked: {exc}"
        self._sink.emit(self.name, "output", {"text": output})
        return output


class AgentFactory:
    """Builds agents whose every tool call is authorized, screened and recorded."""

    def __init__(self, llm: BaseChatModel, guard: Guard, sink: EventSink) -> None:
        self._llm = llm
        self._guard = guard
        self._sink = sink

    def create(self, name: str, prompt: str, tools: list[Callable[..., Any]]) -> Agent:
        guarded = [self._guarded_tool(name, tool) for tool in tools]
        graph = create_agent(self._llm, guarded, system_prompt=prompt, name=name)
        return Agent(name, graph, self._guard, self._sink)

    def _guarded_tool(self, agent: str, func: Callable[..., Any]) -> BaseTool:
        spec = StructuredTool.from_function(func)

        def call(**args: Any) -> str:
            try:
                self._guard.authorize(agent, spec.name, args)
                self._sink.emit(agent, "tool_call", {"tool": spec.name, "args": args})
                result = self._guard.screen(agent, json.dumps(func(**args), default=str), "tool_result")
            except ReviewRequired as exc:
                self._sink.emit(agent, "review_required", {
                    "tool": spec.name, "args": args, "reason": str(exc),
                })
                hold_for_review = getattr(self._sink, "hold_for_review", None)
                if hold_for_review is None:
                    return f"Held for human review: {spec.name}"
                return hold_for_review(agent, spec.name, args, str(exc))
            except Blocked as exc:
                self._sink.emit(agent, "blocked", {"tool": spec.name, "reason": str(exc)})
                return f"Blocked: {exc}"
            except Exception as exc:  # Tool failures go back to the model, as in production agents.
                self._sink.emit(agent, "tool_error", {"tool": spec.name, "error": str(exc)})
                return f"Error: {exc}"
            self._sink.emit(agent, "tool_result", {"tool": spec.name, "result": result})
            return result

        return StructuredTool.from_function(
            call, name=spec.name, description=spec.description, args_schema=spec.args_schema
        )
