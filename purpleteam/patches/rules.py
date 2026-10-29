"""Deterministic patches: tool gates, argument invariants, a SQL firewall and an egress guard.

These are plain, reviewed code. The defender only chooses which to switch on; it never
writes them. Each targets a tool by name or risk, so they are domain-agnostic.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import defaultdict, deque
from typing import Any, Callable

import sqlglot
from sqlglot import exp

from purpleteam.identity import PermissionManifest
from purpleteam.patches.base import Blocked, Patch
from purpleteam.secrets import ScanTooLarge, SecretFinder


class ArgumentAllowlist(Patch):
    """A tool argument may only take a value the business has verified (e.g. the record on file)."""

    id, layer, answers = "P5", "invariant", ("injection_action",)

    def __init__(self, tool: str, arg: str, allowed: set[str]) -> None:
        self._tool, self._arg = tool, arg
        self._allowed = {str(a).strip().upper() for a in allowed}

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        if tool == self._tool and str(args.get(self._arg, "")).strip().upper() not in self._allowed:
            raise Blocked(f"{self._arg}={args.get(self._arg)} is not a verified value for {tool}")


class SqlFirewall(Patch):
    """Allow a query tool to run only a single read-only SELECT over allowlisted tables."""

    id, layer, answers = "P8", "sql", ("sql_injection", "exfiltration", "destructive")

    def __init__(self, tools: set[str], arg: str = "sql", tables: set[str] | None = None) -> None:
        self._tools, self._arg = set(tools), arg
        self._tables = {t.lower() for t in tables} if tables else None

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        if tool not in self._tools:
            return
        reason = self._unsafe(str(args.get(self._arg, "")))
        if reason:
            raise Blocked(f"blocked SQL: {reason}")

    def _unsafe(self, sql: str) -> str | None:
        try:
            statements = [s for s in sqlglot.parse(sql, read="sqlite") if s]
        except Exception:
            return "could not be parsed"
        if len(statements) != 1:
            return "only a single statement is allowed"
        statement = statements[0]
        if not isinstance(statement, exp.Select):
            return "only SELECT is allowed"
        if self._tables is not None:
            for table in statement.find_all(exp.Table):
                if table.name.lower() not in self._tables:
                    return f"table '{table.name}' is not allowed"
        return None


class EgressGuard(Patch):
    """Block a tool call whose arguments carry a secret (known value, credential format, encoded copy).

    ``tools=None`` guards every tool, which is how the defender uses it: a secret can leave through
    any tool that takes text (a page fetch with a query string, a note), not only outbound-looking ones.
    """

    id, layer, answers = "P10", "egress", ("egress_leak", "exfiltration")

    def __init__(self, tools: set[str] | None, finder: SecretFinder) -> None:
        self._tools = None if tools is None else set(tools)  # None guards every tool
        self._finder = finder

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        if self._tools is not None and tool not in self._tools:
            return
        try:
            found = self._finder.find_in(args)
        except ScanTooLarge as error:
            raise Blocked(f"arguments to {tool} are too large to scan for secrets") from error
        except Exception as error:  # fail closed: a call whose arguments cannot be inspected does not run
            raise Blocked(f"could not scan the arguments to {tool} for secrets") from error
        if found:  # name the kind, never the value
            raise Blocked(f"arguments to {tool} carry a secret ({found[0].kind}); egress blocked")


_INSTRUCTION_MARKERS = re.compile(
    r"ignore (all |any )?(previous|prior|above) (instructions|rules)|disregard (all |the )?(previous|prior|above)"
    r"|you are now\b|new instructions?:|system prompt|<\|im_start\|>|<\|system\|>|###\s*instruction",
    re.IGNORECASE)


class MemoryWriteGuard(Patch):
    """Quarantine a write to a memory tool whose content carries an instruction or a secret.

    Whatever lands in memory is read back by every later recall, so a planted instruction outlives
    the conversation that planted it. This refuses the write itself. It does not give stored items
    provenance or isolate sessions: the Guard port carries no session channel to bind them to.
    """

    id, layer, answers = "P12", "memory", ("memory_write_surface",)

    def __init__(self, tools: set[str], finder: SecretFinder, scanner: Patch | None = None) -> None:
        self._tools, self._finder, self._scanner = set(tools), finder, scanner

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        if tool not in self._tools:
            return
        text = json.dumps(args, default=str)
        if _INSTRUCTION_MARKERS.search(text):
            raise Blocked(f"memory write to {tool} quarantined: it carries an instruction")
        try:
            if self._finder.find_in(args):
                raise Blocked(f"memory write to {tool} quarantined: it carries a secret")
        except ScanTooLarge as error:
            raise Blocked(f"memory write to {tool} is too large to inspect") from error
        if self._scanner is not None:
            self._scanner.screen(agent, text, "memory_write")  # raises Blocked on an injection


class LoopGuard(Patch):
    """Stop an agent that is looping: a per-agent step budget over a sliding window, and a cap on the
    same tool call (same arguments) repeating within it."""

    id, layer, answers = "P13", "loop", ("agent_loop",)

    def __init__(self, max_calls: int = 30, window: float = 60.0, max_repeats: int = 3,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._max_calls, self._window, self._max_repeats, self._clock = max_calls, window, max_repeats, clock
        self._seen: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._lock = threading.Lock()

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        key = f"{tool}:{json.dumps(args, sort_keys=True, default=str)}"
        now = self._clock()
        with self._lock:
            seen = self._seen[agent]
            while seen and now - seen[0][0] > self._window:
                seen.popleft()
            if len(seen) >= self._max_calls:
                raise Blocked(f"{agent} exceeded {self._max_calls} tool calls in {self._window:.0f}s")
            if sum(1 for _, k in seen if k == key) >= self._max_repeats:
                raise Blocked(f"{agent} repeated the same {tool} call {self._max_repeats} times: a loop")
            seen.append((now, key))


class AgentScopeGuard(Patch):
    """Deny by default: an agent may call only the tools its permission manifest lists for it."""

    id, layer, answers = "P11", "identity", ("privilege_escalation", "excessive_agency")

    def __init__(self, manifest: PermissionManifest) -> None:
        self._manifest = manifest

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        reason = self._manifest.reason_denied(agent, tool, args)
        if reason is not None:
            raise Blocked(reason)
