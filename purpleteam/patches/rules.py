"""Deterministic patches: tool gates, argument invariants, a SQL firewall and an egress guard.

These are plain, reviewed code. The defender only chooses which to switch on; it never
writes them. Each targets a tool by name or risk, so they are domain-agnostic.
"""

from __future__ import annotations

from typing import Any

import sqlglot
from sqlglot import exp

from purpleteam.identity import PermissionManifest
from purpleteam.patches.base import Blocked, Patch
from purpleteam.secrets import ScanTooLarge, SecretFinder


class ToolGate(Patch):
    """Hold a dangerous tool for human verification before it runs (EU AI Act Art. 14)."""

    id, layer, answers = "P4", "tool-gate", ("injection_action", "excessive_agency", "jailbreak")

    def __init__(self, tools: set[str]) -> None:
        self._tools = set(tools)

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        if tool in self._tools:
            raise Blocked(f"{tool} needs out-of-band human verification; routed to the review queue")


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


class AgentScopeGuard(Patch):
    """Deny by default: an agent may call only the tools its permission manifest lists for it."""

    id, layer, answers = "P11", "identity", ("privilege_escalation", "excessive_agency")

    def __init__(self, manifest: PermissionManifest) -> None:
        self._manifest = manifest

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        if not self._manifest.permits(agent, tool):
            raise Blocked(f"agent '{agent}' is not permitted to call {tool}")
