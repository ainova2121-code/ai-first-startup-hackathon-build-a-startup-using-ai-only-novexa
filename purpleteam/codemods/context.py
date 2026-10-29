"""What a fix author needs to see beyond the flagged line, read from the target's own AST.

A scanner names one line, but the line is often part of a longer statement, and the right fix often
depends on what the code around it does: a table or column name cannot be bound as a query
parameter, so the only sound fix is to accept just the identifiers the code really uses -- and those
are visible at its call sites. Everything here is derived structurally from source text, never from
names or domain knowledge, and is handed to the author as untrusted data.
"""

from __future__ import annotations

import ast
from pathlib import Path

from purpleteam.sast import EXCLUDED_DIRS

_MAX_FUNCTION_LINES = 60
_MAX_VALUES = 25


def statement(text: str, line: int) -> tuple[int, int]:
    """(first, last) line of the innermost simple statement containing ``line``, so a fix replaces a
    whole statement rather than one physical line of a call that spans several. A line that is not
    inside a simple statement (a compound statement's header, say) stays just that line."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return line, line
    best: tuple[int, int] | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt) and not hasattr(node, "body") and node.lineno <= line <= node.end_lineno:
            if best is None or node.end_lineno - node.lineno < best[1] - best[0]:
                best = (node.lineno, node.end_lineno)
    return best or (line, line)


def occurrence(text: str, original: str, line: int) -> int:
    """Where ``original`` sits in ``text`` as the statement at ``line`` -- the exact copy the finding
    names, even when the same text appears elsewhere in the file -- or -1 if it is not there."""
    first, _ = statement(text, line)
    offset = sum(len(row) for row in text.splitlines(keepends=True)[:first - 1])
    return offset if text.startswith(original, offset) else -1


def source_statement(file_path: Path, line: int) -> str:
    """The exact text of the statement a finding points at (see ``statement``)."""
    text = file_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not 1 <= line <= len(lines):
        raise ValueError(f"{file_path}:{line} is out of range")
    first, last = statement(text, line)
    return "\n".join(lines[first - 1:last])


def _enclosing_function(tree: ast.AST, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    found = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= node.end_lineno:
            if found is None or node.lineno > found.lineno:
                found = node
    return found


def _interpolated_names(node: ast.AST) -> set[str]:
    return {sub.id for part in ast.walk(node) if isinstance(part, ast.FormattedValue)
            for sub in ast.walk(part.value) if isinstance(sub, ast.Name)}


def _python_files(repo: Path):
    root = repo.resolve()
    for path in repo.rglob("*.py"):
        if any(part in EXCLUDED_DIRS for part in path.relative_to(repo).parts):
            continue
        if path.resolve().is_relative_to(root):  # never follow a link out of the project
            yield path


def call_site_values(repo: Path, function: str, index: int, keyword: str) -> list[str] | None:
    """Every literal string passed for one parameter at every call of ``function`` in the project;
    None when any call passes something other than a literal (then the full set is not known)."""
    values: set[str] = set()
    for path in _python_files(repo):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError, OSError):
            return None  # unreadable code could hold a call we cannot see
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name != function:
                continue
            arg = next((k.value for k in node.keywords if k.arg == keyword), None)
            if arg is None and 0 <= index < len(node.args):
                arg = node.args[index]
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                return None
            values.add(arg.value)
    return sorted(values)[:_MAX_VALUES] if values else None


def fix_context(repo: Path, file_path: Path, line: int) -> dict:
    """The enclosing function's source (read-only context, not to be rewritten) and, for each of its
    parameters interpolated into the flagged statement, the literal values its callers pass."""
    text = file_path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    function = _enclosing_function(tree, line)
    if function is None:
        return {}
    lines = text.splitlines()[function.lineno - 1:function.end_lineno][:_MAX_FUNCTION_LINES]
    first, last = statement(text, line)
    flagged = [node for node in ast.walk(function) if isinstance(node, ast.stmt)
               and node.lineno == first and node.end_lineno == last]
    names = _interpolated_names(flagged[0]) if flagged else set()
    params = [a.arg for a in function.args.args]
    offset = 1 if params and params[0] in ("self", "cls") else 0
    values = {}
    for position, param in enumerate(params):
        if param in names and position >= offset:  # never self/cls: callers do not pass it
            found = call_site_values(repo, function.name, position - offset, param)
            if found:
                values[param] = found
    context = {"enclosing_function": "\n".join(lines)}
    if values:
        context["call_site_values"] = values
    return context
