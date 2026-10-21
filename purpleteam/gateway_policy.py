"""The gateway's decision point: record every model decision in the signed ledger, and enforce policy on it if asked.

Each model answer is a decision: a tool call, several, or a final reply. Here each is (1) checked by a ``Guard``,
the same patches the defender selects (tool gate, argument allowlist, per-agent scope, egress guard, SQL
firewall), and (2) written to the audit ledger, so the production trail says which agent, on which model, did
what, and whether it was allowed. Enforcement works on what the model *proposes*, before the product acts:

- A call that fails the guard is withdrawn from the answer, and the product receives a plain refusal instead.
- If any call in an answer is withdrawn, all of them are (``withheld`` in the log), so a product never runs half
  of a decision.
- A provider-executed tool (a hosted shell, code execution, web search) runs before the gateway sees the answer
  and cannot be held back, and a streamed answer cannot be rewritten in flight, so while enforcement is on both
  are refused up front rather than let through unchecked. This stops the model's decision, not an action a
  product takes without asking the model.
- Anything that cannot be attributed to an agent, or was only partly recorded, is treated as blocked.
- Any exception from a guard counts as a block. A guard that fails never opens the gate.

The log holds no raw data. Arguments go through the ledger's redactor (sensitive values become keyed
commitments), results and reply text appear only as a length and, when a redactor is given, a keyed commitment,
and oversized or unreadable arguments are summarised instead of stored. By default a decision that cannot be
written to the log is not released (HTTP 503): no unlogged decisions. A model's own reasoning/thinking text
(see ``gateway_dialects.Exchange.reasoning``) follows a different rule, not this one: it never reaches this
log at all, not even summarised — see ``gateway_debug.ReasoningDebugLog`` for the separate, explicit,
operator-opted-in place full reasoning text can go instead.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from purpleteam.gateway_containment import ContainmentEvent, LiveContainment
from purpleteam.gateway_debug import ReasoningDebugLog
from purpleteam.gateway_dialects import Dialect
from purpleteam.gateway_observer import GatewayObserver, Observed

REFUSAL = "This action was blocked by the security gateway."
ACTOR = "gateway"
MAX_LOGGED_ARGS = 4000  # characters of arguments written to the log before they are summarised


class Refusal(Exception):
    """The gateway declines to pass a request or an answer on; ``status`` and ``message`` go to the caller."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status, self.message = status, message


class Guard(Protocol):
    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        """Raise if the tool call must not run."""
        ...


class DecisionPoint:
    def __init__(self, observer: GatewayObserver, *, guard: Guard | None = None, ledger: Any = None,
                 redactor: Any = None, allow_native_tools: bool = False, fail_closed: bool = True,
                 containment: LiveContainment | None = None,
                 reasoning_debug: ReasoningDebugLog | None = None) -> None:
        self._observer, self._guard, self._ledger = observer, guard, ledger
        self._redactor, self._allow_native, self._fail_closed = redactor, allow_native_tools, fail_closed
        self._containment, self._reasoning_debug = containment, reasoning_debug

    @property
    def enforcing(self) -> bool:
        return self._guard is not None

    def check_request(self, dialect: Dialect, payload: dict, streaming: bool) -> None:
        """Refuse, before anything is sent upstream, what enforcement could not control."""
        if not self.enforcing:
            return
        if streaming:
            raise Refusal(400, "streaming is not supported while enforcement is on")
        native = dialect.parse(payload, {}).native
        if native and not self._allow_native:
            names = ", ".join(sorted({name[:64] for name in native})[:5])
            raise Refusal(400, f"provider-executed tools cannot be enforced: {names}")

    def process(self, dialect: Dialect, payload: dict, response: dict, hint: str | None, model: str,
                identity: str | None = None, key_id: str | None = None) -> dict | None:
        """Observe the answer, enforce on it, log it. Returns the answer to send instead, or None to send it as is.
        ``key_id`` is the authenticated bearer key, if any — only needed so containment can revoke it outright."""
        observed = self._observer.observe(payload, response, hint, dialect, identity, model)
        if self._reasoning_debug is not None:
            self._debug_reasoning(observed, model)
        verdicts, containment_events = self._verdicts(observed, key_id)
        withhold = any(policy for _, policy in verdicts)
        self._record(observed, dialect, model, verdicts, withhold, containment_events)
        return dialect.block(response, REFUSAL) if withhold else None

    def _debug_reasoning(self, observed: Observed, model: str) -> None:
        """Best-effort, and outside the signed ledger entirely — see ``gateway_debug``."""
        try:
            self._reasoning_debug.record(agent=observed.agent, model=model,
                                         reasoning=observed.exchange.reasoning,
                                         redacted=observed.exchange.redacted_reasoning)
        except Exception:
            self._observer.note("the reasoning debug log could not be written")

    def log_withheld(self, dialect: Dialect, hint: str | None, model: str, identity: str | None, policy: str) -> None:
        """Record that an answer was held back whole (its key stopped being valid while it was in flight). The answer
        is never observed, so calls inside it are not counted as calls that happened."""
        if self._ledger is None:
            return
        try:
            self._ledger.append(ACTOR, "decision", {
                "mode": "enforce" if self.enforcing else "observe", "agent": identity or "", "model": model,
                "dialect": dialect.name, "action": "answer", "verdict": "withheld", "policy": policy, "chars": 0})
        except Exception:  # the answer is withheld either way; the failure is surfaced, not hidden
            self._observer.note("a withheld answer could not be written to the audit log")

    def _verdicts(self, observed: Observed, key_id: str | None) -> tuple[list[tuple[Any, str]], list[ContainmentEvent]]:
        """(call, policy that stopped it) for each call, plus any containment events those blocks
        triggered. An empty policy means allowed."""
        if self._guard is None or not observed.exchange.calls:
            return [(call, "") for call in observed.calls], []
        if not observed.complete:  # an answer we could not fully attribute is never waved through
            return [(None, "unobserved")], []
        verdicts: list[tuple[Any, str]] = []
        events: list[ContainmentEvent] = []
        for call in observed.calls:
            policy, kind = self._stopped_by(call)
            verdicts.append((call, policy))
            if policy and self._containment is not None:
                event = self._containment.observe_block(kind, call.agent, call.tool, key_id)
                if event is not None:
                    events.append(event)
        return verdicts, events

    def _stopped_by(self, call: Any) -> tuple[str, str]:
        """(policy id that blocked the call, the finding kind it answers for) — kind feeds
        containment's escalation decision; both are "" when nothing blocked it."""
        if self._containment is not None and not self._containment.permits(call.agent, call.tool, call.args):
            return "containment", "containment"
        for patch in getattr(self._guard, "patches", None) or [self._guard]:
            try:
                patch.authorize(call.agent, call.tool, call.args)
            except Exception:  # a block, or a guard that failed: either way the call does not go ahead
                policy = str(getattr(patch, "id", "") or type(patch).__name__)
                kind = (getattr(patch, "answers", None) or ("",))[0]
                return policy, kind
        return "", ""

    def _record(self, observed: Observed, dialect: Dialect, model: str, verdicts: list, withhold: bool,
               containment_events: list[ContainmentEvent] = ()) -> None:
        if self._ledger is None:
            return
        base = {"mode": "enforce" if self.enforcing else "observe", "agent": observed.agent or "",
                "model": model, "dialect": dialect.name}
        events = [("decision", {**base, "action": "tool_call", "tool": call.tool if call else "",
                                "args": self._loggable(call.args) if call else {}, "policy": policy,
                                "verdict": "blocked" if policy else ("withheld" if withhold else "allowed")})
                  for call, policy in verdicts]
        if not observed.exchange.calls:
            events.append(("decision", {**base, "action": "answer", **self._summary(observed.exchange.answer)}))
        events += [("tool_result", {"agent": call.agent, "tool": call.tool, **self._summary(call.result)})
                   for call in observed.results]
        events += [("containment", {"level": e.level, "agent": e.agent, "tool": e.tool, "kind": e.kind,
                                    "reason": e.reason}) for e in containment_events]
        try:
            for kind, payload in events:
                self._ledger.append(ACTOR, kind, payload)
        except Exception:
            if self._fail_closed:
                raise Refusal(503, "the audit log is unavailable") from None
            self._observer.note("a decision could not be written to the audit log")

    def _summary(self, text: str) -> dict:
        """Length, and a keyed commitment if there is a redactor: enough to prove later, nothing to read now."""
        summary: dict[str, Any] = {"chars": len(text)}
        if self._redactor is not None:
            summary["commitment"] = self._redactor.commit(text)
        return summary

    def _loggable(self, args: dict) -> dict:
        try:
            text = json.dumps(args, default=str)
        except (ValueError, TypeError, RecursionError):  # a nesting bomb: say so rather than store or crash
            return {"unreadable": True}
        return args if len(text) <= MAX_LOGGED_ARGS else self._summary(text)
