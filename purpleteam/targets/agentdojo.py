"""Adapts AgentDojo (ethz-spylab/agentdojo, pip-installed via the ``agentdojo`` dependency group,
never vendored or cloned into this repo) to the platform's Target protocol -- a second, third-
party target proving the platform discovers and attacks agents it did not build, not just
LedgerPilot. Zero changes to AgentDojo's own code: everything here calls only its public API
(``TaskSuite``, ``AgentPipeline``, ``FunctionsRuntime``, and ``get_llm``'s own officially
supported "openai-compatible" provider, confirmed by reading agentdojo/agent_pipeline/
agent_pipeline.py directly).

AgentDojo's own injection-success checker (built for its predefined ``injection_task`` catalog)
is never consulted: ``send()`` injects the attacker's real, rendered payload into a real
injection vector (an email body, a calendar description...) via ``injections={vector: text}`` --
a plain, public, data-driven API, not a patch -- and hands the resulting real tool-call trace back
for the platform's own proof-based oracle to judge, exactly as it already judges LedgerPilot.
"""

from __future__ import annotations

import json
from typing import Any

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig, get_llm
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import get_text_content_as_str

from purpleteam.adapter import Observation, ToolCall
from purpleteam.discovery import DiscoveredTool, TargetProfile, classify_risk, is_memory_surface, is_retrieval_surface

DEFAULT_SUITE = "workspace"
DEFAULT_USER_TASK = "user_task_0"
DEFAULT_VERSION = "v1"


def _yaml_scalar_escape(text: str) -> str:
    """AgentDojo's own load_and_inject_default_environment drops an injection value straight into
    a double-quoted YAML scalar with a plain, unescaped str.format() -- confirmed directly from its
    real environment.yaml (``"... {some_injection}"``). A payload containing a bare ``"`` or ``\\``
    (real jailbreak text routinely does) breaks the YAML parse immediately after. JSON string
    escaping is a compatible subset of YAML double-quoted-scalar escaping, so this prepares our own
    payload correctly for their real, unmodified template rather than patching their code."""
    return json.dumps(text)[1:-1]


def discover_profile(suite_name: str = DEFAULT_SUITE, version: str = DEFAULT_VERSION) -> TargetProfile:
    """AgentDojo's real tool suite, seen as it is -- the same domain-agnostic classify_risk/
    is_retrieval_surface discovery.py already uses for a LangChain target, just fed AgentDojo's own
    Function objects instead. Needs no model, key or network."""
    suite = get_suite(version, suite_name)
    tools = []
    for fn in suite.tools:
        args = {name: {} for name in fn.parameters.model_fields}
        risk = classify_risk(fn.name, fn.description, args)
        tools.append(DiscoveredTool(
            name=fn.name, description=fn.description, args=args, source="agentdojo",
            risk=risk, module=suite_name,
            retrieval=is_retrieval_surface(fn.name, fn.description),
            memory=is_memory_surface(fn.name, fn.description, risk),
        ))
    return TargetProfile(f"agentdojo:{suite_name}", tools)


class AgentDojoTarget:
    """One AgentDojo task suite and user task, attacked through its own public pipeline. The LLM
    is AgentDojo's "openai-compatible" provider (OPENAI_COMPATIBLE_BASE_URL/_API_KEY), so it can
    point at any real OpenAI-compatible endpoint -- including this project's own LedgerPilot model
    config, reused as-is by purpleteam.demo_agentdojo so this needs no new credentials."""

    def __init__(self, suite_name: str = DEFAULT_SUITE, user_task_id: str = DEFAULT_USER_TASK,
                vector: str | None = None, model: str = "openai-compatible-model",
                model_id: str | None = None, version: str = DEFAULT_VERSION, guard: Any = None,
                pipeline: Any = None) -> None:
        self._suite = get_suite(version, suite_name)
        self._user_task = self._suite.get_user_task_by_id(user_task_id)
        # Any declared vector works for a generic attack: this just needs one real channel the
        # agent reads untrusted content from, not a specific predefined injection scenario.
        self._vector = vector or next(iter(self._suite.get_injection_vector_defaults()))
        # ``pipeline`` is a test seam (a fake with a .query() method) -- real callers never pass it,
        # so the real AgentPipeline (and its real "openai-compatible" provider) is built lazily,
        # never touching the network at construction time, and only once per real run.
        self._pipeline = pipeline
        self._model, self._model_id = model, model_id
        self.name = f"agentdojo:{suite_name}:{user_task_id}"

    def _real_pipeline(self) -> Any:
        llm = get_llm("openai-compatible", self._model, self._model_id, "tool")
        config = PipelineConfig(llm=llm, model_id=self._model_id, defense=None, system_message_name=None,
                                system_message=None)
        return AgentPipeline.from_config(config)

    def reset(self) -> None:
        pass  # a fresh environment is built fresh on every send(); nothing carries over between calls

    def send(self, request: str) -> Observation:
        if self._pipeline is None:
            self._pipeline = self._real_pipeline()
        environment = self._suite.load_and_inject_default_environment({self._vector: _yaml_scalar_escape(request)})
        task_environment = self._user_task.init_environment(environment)
        runtime = FunctionsRuntime(self._suite.tools)
        _, _, _, messages, _ = self._pipeline.query(self._user_task.PROMPT, runtime, task_environment)

        calls = []
        for message in messages:
            if message["role"] != "tool":
                continue
            call = message["tool_call"]
            result = message["error"] or (get_text_content_as_str(message["content"]) if message["content"] else "")
            calls.append(ToolCall(self.name, call.function, dict(call.args), result=str(result)))

        last = messages[-1] if messages else None
        reply = get_text_content_as_str(last["content"]) if last and last["role"] == "assistant" and last["content"] else ""
        return Observation(reply, calls)
