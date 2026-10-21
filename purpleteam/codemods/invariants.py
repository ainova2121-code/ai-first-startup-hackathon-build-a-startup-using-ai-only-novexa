"""Independent security invariants for a patched file — a hand-written AST check, distinct from
whatever scanner found the original finding. Re-running the same scanner on the same text is
weaker evidence than it looks: a clean re-scan proves only that one tool's rules are satisfied, not
that the underlying property actually holds. A second, independently-implemented check of that
same property is real, additional proof.

Only kinds the codemod system is actually wired for (see ``purpleteam.sast.BANDIT_KINDS`` and
``SONARQUBE_KINDS``) get a checker here; a kind with none is not independently confirmed, and
``codemods.verify`` records that honestly rather than silently skipping it.
"""

from __future__ import annotations

import ast
import re

_SQL_CALLS = {"execute", "executemany", "executescript"}
_SHELL_CALLS = {"Popen", "call", "run", "check_call", "check_output"}
_SECRET_NAME = re.compile(r"(password|passwd|secret|token|api_key|apikey)", re.IGNORECASE)


def _is_dynamic_string(node: ast.AST) -> bool:
    """True for an f-string, %-format, ``.format()`` call or ``+`` concatenation — anything that
    builds a string from parts at runtime, which a parameterized query must never pass as itself."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"


def _parse(source: str) -> ast.AST | str:
    """The parsed tree, or an error message naming the line — never raises, so a source that
    cannot even be parsed is its own, clearly-named failure, not an exception escaping verification."""
    try:
        return ast.parse(source)
    except SyntaxError as error:
        return f"could not parse the patched source to check it ({error})"


def no_dynamic_sql(source: str) -> str | None:
    """None if no ``execute``/``executemany``/``executescript`` call takes a dynamically-built
    string as its first argument; otherwise a message naming the line."""
    tree = _parse(source)
    if isinstance(tree, str):
        return tree
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _SQL_CALLS and node.args and _is_dynamic_string(node.args[0])):
            return f"line {node.lineno}: a dynamically-built string still reaches {node.func.attr}()"
    return None


def no_shell_injection(source: str) -> str | None:
    """None if no ``subprocess`` call still passes ``shell=True`` with a dynamically-built command
    — the exact shape Bandit's B602 flags. A fixed, literal command with ``shell=True`` is still a
    smell but a different finding; only a dynamic (f-string, ``%``, ``+``, ``.format()``) command
    is what this fix is actually supposed to have removed."""
    tree = _parse(source)
    if isinstance(tree, str):
        return tree
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _SHELL_CALLS):
            continue
        shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                         for k in node.keywords)
        if shell_true and node.args and _is_dynamic_string(node.args[0]):
            return f"line {node.lineno}: {node.func.attr}() still runs a dynamically-built command with shell=True"
    return None


def _is_str_literal(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value != ""


def no_hardcoded_secret(source: str) -> str | None:
    """None if no string literal is assigned to, or passed as the default or keyword value for, a
    password/secret/token-named variable, parameter or call argument — the shape Bandit's
    hardcoded-password checks (B105/B106/B107) flag. A value read from an environment variable, a
    config object or a function call is never flagged; only a literal baked into the source is."""
    tree = _parse(source)
    if isinstance(tree, str):
        return tree
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Name) and _SECRET_NAME.search(target.id)
                        and _is_str_literal(node.value)):
                    return f"line {node.lineno}: {target.id!r} is still assigned a literal string"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg, default in zip(reversed(node.args.args), reversed(node.args.defaults)):
                if _SECRET_NAME.search(arg.arg) and _is_str_literal(default):
                    return f"line {node.lineno}: parameter {arg.arg!r} still defaults to a literal string"
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg and _SECRET_NAME.search(keyword.arg) and _is_str_literal(keyword.value):
                    return f"line {node.lineno}: argument {keyword.arg!r} is still a literal string"
    return None


# finding kind -> an independent checker; a kind absent here has no independent invariant yet.
INVARIANTS = {"sql_injection": no_dynamic_sql, "shell_injection": no_shell_injection,
             "hardcoded_secret": no_hardcoded_secret}
