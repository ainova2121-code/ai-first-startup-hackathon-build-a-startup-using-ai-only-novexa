"""Learn a target's agents, tools and tool calls from the model traffic it sends, whatever it is built with.

A product (n8n, CrewAI, a hand-rolled Python service, TypeScript...) only has to point its model base URL at
our gateway. Every chat request already carries the agent's system prompt and the tools it may call, and every
answer carries the calls the model made. So the traffic alone gives a ``TargetProfile`` and the ``ToolCall``
list of each attack, with no SDK, no code change and no knowledge of the framework. Provider formats (OpenAI,
Anthropic, Gemini) are read by ``gateway_dialects``, which hands this module one common ``Exchange``.

Everything here is untrusted target data, and the rules follow from that:
- A tool call exists only if the *model's answer* contained it. The request history is client-supplied
  (a chat product forwards what its user typed), so a call found there proves nothing; it is used only to
  attach the tool's reported result to a call we already saw.
- Nothing that an oracle reads is ever truncated or dropped: padding must not push a secret out of view,
  and an argument that is not valid JSON (or nests absurdly deep) is kept as raw text, not lost.
- Parsing is bounded and never raises into the proxied request. Names that are not plain are recorded as
  errors, and ``profile`` then fails loudly rather than hide a tool from the checks that compare names.
- Prompts are kept only as hashes in reports.

An agent is *authenticated* when the request came under a key bound to it (see ``gateway_keys``): the key says
who it is. Otherwise it is guessed, from its tool set plus the start of its system prompt or from the name a product
sends in the ``X-Purpleteam-Agent`` header, which anything can fake, and the profile says it is not authenticated.
A header that names a different agent than the key is bound to is never believed, only counted. A prompt that
changes at its very start on every request looks like many agents; the cap on agents turns that into a clear error
instead of unbounded growth.

We never see a tool run, so every call carries an evidence level: ``proposed`` (the model's answer held it)
or ``reported`` (the product then sent back a result). A request can carry a nonce; ``drain(nonce)`` marks
a call ``attributed`` only if its conversation held that nonce, so traffic that is not ours (other users, a
scheduled job) is visible as such instead of being mistaken for the attack.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from purpleteam.adapter import PROPOSED, REPORTED, ToolCall
from purpleteam.capture import DiscoveryError
from purpleteam.discovery import AgentInfo, DiscoveredTool, TargetProfile, classify_risk
from purpleteam.gateway_dialects import OPENAI, Dialect, Exchange
from purpleteam.identity import valid_name

MAX_AGENTS, MAX_TOOLS, MAX_ERRORS, MAX_CALLS = 64, 256, 20, 10_000
MAX_PROMPT, KEY_PROMPT_CHARS = 65_536, 256


def _arguments(raw: Any) -> dict[str, Any]:
    """The call's arguments as a dict; anything else (bad JSON, a list, a nesting bomb) is kept whole as raw text."""
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, RecursionError):
        parsed = None
    return parsed if isinstance(parsed, dict) else {"_raw": raw if isinstance(raw, str) else str(raw)}


@dataclass
class Observed:
    """What one exchange showed, for whoever acts on it (the gateway's decision point)."""

    agent: str | None = None  # None when the exchange could not be attributed to an agent (a cap was hit, or it was unreadable)
    calls: list[ToolCall] = field(default_factory=list)    # the model's calls in this answer, in order
    results: list[ToolCall] = field(default_factory=list)  # calls whose result arrived with this request, first time seen
    exchange: Exchange = field(default_factory=Exchange)

    @property
    def complete(self) -> bool:
        """Every call in the answer was recorded against a known agent. Anything less must not be trusted."""
        return self.agent is not None and len(self.calls) == len(self.exchange.calls)


class _Agent:
    def __init__(self, name: str, prompt: str, authenticated: bool) -> None:
        self.name, self.prompt, self.authenticated, self.claimed_other = name, prompt, authenticated, 0
        self.tools: dict[str, DiscoveredTool] = {}


class GatewayObserver:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._agents: dict[str, _Agent] = {}
        self._calls: list[ToolCall] = []  # since the last drain
        self._origins: list[str] = []  # the text the product sent in with each call, to check a nonce against
        self._by_id: dict[tuple[str, str], ToolCall] = {}  # (conversation, call key) -> call, to attach results
        self._completed: set[int] = set()  # calls whose result has been reported once already
        self._called: set[tuple[str, str]] = set()
        self._timeline: list[ToolCall] = []  # every call seen, never drained: for readers that must not lose any
        self.errors: list[str] = []

    def observe(self, request: Any, response: Any = None, hint: str | None = None, dialect: Dialect = OPENAI,
                identity: str | None = None) -> Observed:
        """Record one exchange (``identity``: the agent its key is bound to, if any). Never raises: a malformed
        one is noted and the traffic carries on."""
        try:
            with self._lock:
                if isinstance(request, dict):
                    return self._observe(dialect.parse(request, response if isinstance(response, dict) else {}), hint,
                                         identity)
        except Exception as error:  # untrusted input on a proxy path must not break the target
            self.note(f"unreadable exchange ({type(error).__name__})")
        return Observed()

    def timeline(self) -> list[ToolCall]:
        """All calls seen so far, oldest first, with the time each was first seen (``drain`` does not remove them)."""
        with self._lock:
            return list(self._timeline)

    def note(self, message: str) -> None:
        with self._lock:
            self._error(message)

    def drain(self, nonce: str | None = None) -> list[ToolCall]:
        """Tool calls seen since the last drain, in the order the model made them. Each drain starts a new
        window, so a model that reuses call ids across requests cannot hide a later call behind an earlier one.
        With a ``nonce``, calls whose conversation never held it are marked as not attributed (and kept)."""
        with self._lock:
            fresh, origins = self._calls, self._origins
            self._calls, self._origins, self._by_id, self._completed = [], [], {}, set()
            if nonce:
                for call, origin in zip(fresh, origins):
                    call.attributed = nonce in origin
            return fresh

    def profile(self, name: str) -> TargetProfile:
        with self._lock:
            if self.errors:
                raise DiscoveryError("; ".join(self.errors[:3]))
            if not self._agents:
                raise DiscoveryError("no model traffic has been seen yet; point the target's base URL at the gateway")
            agents = list(self._agents.values())
            return TargetProfile(name, [t for a in agents for t in a.tools.values()],
                                 [AgentInfo(a.name, a.prompt, tuple(a.tools), a.authenticated, a.claimed_other)
                                  for a in agents])

    def summary(self) -> dict:
        """What was learned, safe to show: prompts appear only as hash and length."""
        with self._lock:
            agents = [{"name": a.name, "prompt_sha256": AgentInfo(a.name, a.prompt).prompt_sha256,
                       "prompt_chars": len(a.prompt), "authenticated": a.authenticated,
                       "claimed_other": a.claimed_other,
                       "tools": [{"name": t.name, "risk": t.risk, "called": (a.name, t.name) in self._called}
                                 for t in a.tools.values()]} for a in self._agents.values()]
            return {"agents": agents, "errors": list(self.errors),
                    "unexercised": [f"{a['name']}.{t['name']}" for a in agents for t in a["tools"] if not t["called"]],
                    "needs_review": [f"{a['name']}.{t['name']}" for a in agents for t in a["tools"] if t["risk"] == "read"]}

    def _error(self, message: str) -> None:
        if len(self.errors) < MAX_ERRORS and message not in self.errors:
            self.errors.append(message)

    def _observe(self, exchange: Exchange, hint: str | None, identity: str | None = None) -> Observed:
        agent = self._agent_for(hint, exchange.system[:MAX_PROMPT], exchange.tools, identity)
        if agent is None:
            return Observed(exchange=exchange)
        for name, description, schema in exchange.tools:
            self._add_tool(agent, name, description, schema)
        conversation = hashlib.sha256(f"{agent.name}\x00{exchange.first_user}".encode()).hexdigest()
        arrived: list[ToolCall] = []
        for key, content in exchange.results:  # the history can only complete a call we already saw, never create one
            call = self._by_id.get((conversation, key))
            if call is not None:
                call.result, call.evidence = content, REPORTED
                if id(call) not in self._completed:
                    self._completed.add(id(call))
                    arrived.append(call)
        recorded = [self._record_call(agent, conversation, exchange.users, *call) for call in exchange.calls]
        return Observed(agent.name, [c for c in recorded if c is not None], arrived, exchange)

    def peek_agent(self, exchange: Exchange, hint: str | None, identity: str | None = None) -> str:
        """The name this exchange would be filed under, without recording anything."""
        if identity is not None:
            return identity
        names = sorted(str(n) for n, _, _ in exchange.tools)
        key = hashlib.sha256((",".join(names) + "\x00" + exchange.system[:KEY_PROMPT_CHARS]).encode()).hexdigest()
        return hint if valid_name(hint) else f"agent-{key[:8]}"

    def _agent_for(self, hint: str | None, prompt: str, declared: list, identity: str | None = None) -> _Agent | None:
        name = self.peek_agent(Exchange(system=prompt, tools=declared), hint, identity)
        agent = self._agents.get(name)
        if agent is None:
            if len(self._agents) >= MAX_AGENTS:
                self._error(f"more than {MAX_AGENTS} distinct agents; send X-Purpleteam-Agent to name them")
                return None
            agent = self._agents[name] = _Agent(name, prompt, identity is not None)
        agent.authenticated = agent.authenticated and identity is not None  # one unbound request taints the identity
        if identity is not None and valid_name(hint) and hint != identity:
            agent.claimed_other += 1  # a header naming another agent is never believed, only counted
        return agent

    def _add_tool(self, agent: _Agent, name: Any, description: str, schema: dict) -> None:
        if not valid_name(name):
            self._error(f"tool name {str(name)[:40]!r} of agent {agent.name!r} is not a plain name")
        elif name not in agent.tools and len(agent.tools) < MAX_TOOLS:
            agent.tools[name] = DiscoveredTool(name, description, schema, "gateway",
                                               classify_risk(name, description, schema), "gateway",
                                               agent_name=agent.name)

    def _record_call(self, agent: _Agent, conversation: str, origin: str, key: str | None, name: Any,
                     raw: Any) -> ToolCall | None:
        if len(self._calls) >= MAX_CALLS:
            self._error(f"more than {MAX_CALLS} tool calls seen; later calls are not recorded")
            return None
        call = ToolCall(agent.name, str(name), _arguments(raw), evidence=PROPOSED, at=time.monotonic())
        self._calls.append(call)
        if len(self._timeline) < MAX_CALLS:
            self._timeline.append(call)
        self._origins.append(origin)
        self._called.add((agent.name, call.tool))
        if key is not None:
            self._by_id[(conversation, key)] = call
        return call
