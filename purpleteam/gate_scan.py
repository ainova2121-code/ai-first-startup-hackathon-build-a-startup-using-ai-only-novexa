"""Static check: a dangerous tool whose body performs its side effect with no human-approval gate.

Driven entirely by discovery: a tool is pinned by the exact definition discovery saw (its file name and
the line its ``def`` starts on), never by name alone -- a same-named helper elsewhere (a repository method
called by the tool, say) is not the tool and is never flagged. A finding names the tool's first statement,
which the deterministic codemod (``codemods.gate``) replaces with a marked "held for human approval" return.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path

from purpleteam.discovery import TargetProfile
from purpleteam.sast import EXCLUDED_DIRS, StaticFinding

GATE_KIND = "unguarded_action"
GATE_TAG = "[AIQ-GATE]"

Location = tuple[str, str, int]  # (tool name, file name, line its definition starts on)


def parse_location(name: str, source: str) -> Location | None:
    """``("update_vendor_bank", "vendor.py:11")`` -> ``("update_vendor_bank", "vendor.py", 11)``, or None
    when discovery could not tell where the tool is defined -- then it is not pinned rather than guessed."""
    file_name, _, line = source.rpartition(":")
    if not file_name or not line.isdigit():
        return None
    return name, file_name, int(line)


def is_gated(body: list[ast.stmt]) -> bool:
    """True when the first statement after any docstring is a return of a gate-marked string."""
    first = _first_statement(body)
    value = first.value if isinstance(first, ast.Return) else None
    return isinstance(value, ast.Constant) and isinstance(value.value, str) and GATE_TAG in value.value


def _first_statement(body: list[ast.stmt]) -> ast.stmt | None:
    statements = body[1:] if body and _is_docstring(body[0]) else body
    return statements[0] if statements else None


def _is_docstring(node: ast.stmt) -> bool:
    return isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)


def _starts_at(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """The line ``inspect.getsourcelines`` reports for a function: its first decorator, else its ``def``."""
    return min([node.lineno, *(decorator.lineno for decorator in node.decorator_list)])


class UnguardedActionScanner:
    """Flags each pinned dangerous-tool definition whose first statement is not a human-approval gate."""

    languages = frozenset({".py"})

    def __init__(self, locations: Iterable[Location]) -> None:
        self._locations = frozenset(locations)

    @classmethod
    def from_profile(cls, profile: TargetProfile) -> UnguardedActionScanner:
        """Every dangerous tool discovery could locate; one it could not is skipped, never matched by name."""
        return cls(location for tool in profile.tools if tool.dangerous
                   if (location := parse_location(tool.name, tool.source)) is not None)

    def scan(self, repo: Path) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        for path in self._python_files(repo):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue  # an unreadable file is not evidence either way; the code scanner reports it
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if (node.name, path.name, _starts_at(node)) not in self._locations or is_gated(node.body):
                    continue
                first = _first_statement(node.body)
                if first is not None:
                    detail = f"dangerous tool '{node.name}' performs its action with no human-approval gate"
                    findings.append(StaticFinding(GATE_KIND, str(path), first.lineno, detail, severity="low",
                                                  subject=node.name))
        return findings

    @staticmethod
    def _python_files(repo: Path):
        root = repo.resolve()
        for path in repo.rglob("*.py"):
            if any(part in EXCLUDED_DIRS for part in path.relative_to(repo).parts):
                continue
            if path.resolve().is_relative_to(root):  # never follow a link out of the project
                yield path
