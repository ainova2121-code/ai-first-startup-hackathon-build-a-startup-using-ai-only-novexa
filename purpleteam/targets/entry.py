"""Find how to run an unknown agent project by reading its source -- nothing is imported or run.

Candidates, strongest first: a CrewAI ``@CrewBase`` class; a module-level app built by a framework call
(a LangGraph ``.compile()``, ``create_react_agent``, ``AgentExecutor``, a ``Crew``); a no-argument
function that builds one; a function that takes one request-shaped argument. The shim
(``purpleteam.targets.shim``) knows how to call each kind.
"""

from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass
from pathlib import Path

from purpleteam.sast import EXCLUDED_DIRS

_BUILDERS = {"compile": "graph", "create_react_agent": "agent", "create_agent": "agent", "AgentExecutor": "agent",
             "initialize_agent": "agent", "Crew": "crew"}
_REQUEST_PARAMS = {"query", "question", "request", "message", "prompt", "input", "task", "topic", "text", "user_input"}
_SKIP_DIRS = {"tests", "test", "docs", "scripts"}


@dataclass(frozen=True)
class Candidate:
    ref: str  # "module:attribute", importable from the project root (or its src/)
    kind: str
    file: str
    line: int
    score: int


def find_entries(repo: Path) -> list[Candidate]:
    found = []
    for path in sorted(repo.rglob("*.py")):
        parts = path.relative_to(repo).parts
        if any(p in EXCLUDED_DIRS or p in _SKIP_DIRS for p in parts) or path.name in ("setup.py", "conftest.py"):
            continue
        module = _module(repo, path)
        if module is None:
            continue
        try:
            with warnings.catch_warnings():  # third-party code: its own escape-sequence warnings are noise here
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        for node in tree.body:
            hit = _candidate(node)
            if hit:
                kind, score = hit
                found.append(Candidate(f"{module}:{node.name if hasattr(node, 'name') else _target(node)}", kind,
                                       path.relative_to(repo).as_posix(), node.lineno, score))
    return sorted(found, key=lambda c: (-c.score, c.file.count("/"), c.ref))


def _module(repo: Path, path: Path) -> str | None:
    root = repo / "src" if (repo / "src") in path.parents else repo
    parts = path.relative_to(root).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts and all(p.isidentifier() for p in parts) else None


def _callee(node: ast.AST) -> str:
    if not isinstance(node, ast.Call):
        return ""
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    # A graph's .compile() is a method taking keywords only; re.compile(pattern) is not an app.
    if name == "compile" and (node.args or not isinstance(func, ast.Attribute)
                              or getattr(func.value, "id", "") in {"re", "regex"}):
        return ""
    return name


def _target(node: ast.AST) -> str:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return targets[0].id


def _candidate(node: ast.AST) -> tuple[str, int] | None:
    if isinstance(node, ast.ClassDef):
        names = {_callee(d) or getattr(d, "id", "") or getattr(d, "attr", "") for d in node.decorator_list}
        return ("crew", 5) if "CrewBase" in names else None
    if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) == 1 and isinstance(targets[0], ast.Name) and _callee(node.value) in _BUILDERS:
            return _BUILDERS[_callee(node.value)], 4
        return None
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
        params = [a.arg for a in node.args.args]
        if not params:
            returned = [_callee(n.value) for n in ast.walk(node) if isinstance(n, ast.Return) and n.value is not None]
            kinds = [_BUILDERS[c] for c in returned if c in _BUILDERS]
            return (kinds[0], 3) if kinds else None
        if len(params) == 1 and params[0] in _REQUEST_PARAMS and not isinstance(node, ast.AsyncFunctionDef):
            return "function", 1
    return None
