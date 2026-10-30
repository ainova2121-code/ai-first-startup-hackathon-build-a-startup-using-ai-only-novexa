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
# A statement starts with its keyword. Matching the words anywhere (as scanners do) would also flag a log
# line like "select 5 tools from 40" and let a "fix" of that prose read as independently verified.
_SQL_SHAPE = re.compile(r"\s*\(?\s*(select\b.*\bfrom|insert\s+into|update\b.*\bset|delete\s+from|replace\s+into|"
                        r"with\b.*\bselect|(create|drop|alter)\s+(table|index|view))\b", re.IGNORECASE | re.DOTALL)
_WEAK_HASHES = {"md5", "sha1", "md4", "md2"}
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}


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


def _is_string(node: ast.AST) -> bool:
    return (isinstance(node, ast.Constant) and isinstance(node.value, str)) or _is_dynamic_string(node)


def _literal_text(node: ast.AST) -> str:
    """The string as written, in order, with every runtime-filled part shown as ``{}``."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else "{}"
    if isinstance(node, ast.JoinedStr):
        return "".join(_literal_text(part) for part in node.values)
    if isinstance(node, ast.BinOp):
        return _literal_text(node.left) + ("{}" if isinstance(node.op, ast.Mod) else _literal_text(node.right))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _literal_text(node.func.value)
    return "{}"


def no_dynamic_sql(source: str) -> str | None:
    """None if no SQL statement is built from parts at runtime -- wherever it goes, including a
    project's own query helper, not only a direct ``execute`` -- and no ``execute``-family call takes a
    dynamic string or gets its parameters as a string; otherwise a message naming the line. The last
    check catches a "parameterized" fix like ``(f"%{x}%,")`` -- a parenthesised string, not a tuple --
    which every driver binds character by character."""
    tree = _parse(source)
    if isinstance(tree, str):
        return tree
    for node in ast.walk(tree):
        if _is_dynamic_string(node) and _SQL_SHAPE.match(_literal_text(node)):
            return f"line {node.lineno}: an SQL statement is still built from parts at runtime"
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_CALLS):
            continue
        if node.args and _is_dynamic_string(node.args[0]):
            return f"line {node.lineno}: a dynamically-built string still reaches {node.func.attr}()"
        if len(node.args) > 1 and _is_string(node.args[1]):
            return f"line {node.lineno}: {node.func.attr}() gets its parameters as a string, not a sequence"
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
    for node in _calls(tree, {"system", "popen"}):  # os.system / os.popen always go through a shell
        if node.args and _is_dynamic_string(node.args[0]):
            return f"line {node.lineno}: {_name(node)}() still runs a dynamically-built command through a shell"
    return None


def _name(call: ast.Call) -> str:
    func = call.func
    return func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""


def _calls(tree: ast.AST, names: set[str]) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call) and _name(node) in names]


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def no_code_execution(source: str) -> str | None:
    """None if nothing is passed to ``eval``/``exec`` at all (``ast.literal_eval`` is the safe
    parser and is allowed): running text as code cannot be made safe by any check around it."""
    tree = _parse(source)
    if isinstance(tree, str):
        return tree
    for node in _calls(tree, {"eval", "exec"}):
        if isinstance(node.func, ast.Name):
            return f"line {node.lineno}: {node.func.id}() still runs text as code"
    return None


def no_unsafe_deserialization(source: str) -> str | None:
    """None if no ``pickle``/``marshal``/``dill`` load remains and every ``yaml.load`` names a safe
    loader: these formats can run code while being read, so untrusted bytes must never reach them."""
    tree = _parse(source)
    if isinstance(tree, str):
        return tree
    for node in _calls(tree, {"load", "loads", "load_all", "unsafe_load"}):
        owner = node.func.value.id if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) else ""
        if owner in {"pickle", "cPickle", "marshal", "dill", "shelve"}:
            return f"line {node.lineno}: {owner}.{_name(node)}() still deserializes arbitrary objects"
        if owner == "yaml":
            loader = _keyword(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            loader_name = loader.attr if isinstance(loader, ast.Attribute) else getattr(loader, "id", "")
            if _name(node) == "unsafe_load" or "Safe" not in loader_name:
                return f"line {node.lineno}: yaml.{_name(node)}() is not restricted to a safe loader"
    return None


def tls_verification_on(source: str) -> str | None:
    """None if no call turns certificate verification off (``verify=False``)."""
    tree = _parse(source)
    if isinstance(tree, str):
        return tree
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            value = _keyword(node, "verify")
            if isinstance(value, ast.Constant) and value.value is False:
                return f"line {node.lineno}: {_name(node)}() still disables TLS certificate verification"
    return None


def requests_have_timeout(source: str) -> str | None:
    """None if every ``requests``/``httpx`` call names a ``timeout`` that is not None: without one, a slow or
    hostile server holds the agent's worker forever."""
    tree = _parse(source)
    if isinstance(tree, str):
        return tree
    for node in _calls(tree, _HTTP_METHODS):
        owner = node.func.value.id if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) else ""
        timeout = _keyword(node, "timeout")
        if owner in {"requests", "httpx"} and (timeout is None or (isinstance(timeout, ast.Constant) and timeout.value is None)):
            return f"line {node.lineno}: {owner}.{_name(node)}() still has no timeout"
    return None


def no_weak_hash(source: str) -> str | None:
    """None if every MD5/SHA-1 use is either replaced or explicitly marked ``usedforsecurity=False``."""
    tree = _parse(source)
    if isinstance(tree, str):
        return tree
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _name(node)
        algorithm = name if name in _WEAK_HASHES else ""
        if name == "new" and node.args and isinstance(node.args[0], ast.Constant):
            requested = str(node.args[0].value).lower()
            algorithm = requested if requested in _WEAK_HASHES else ""
        flag = _keyword(node, "usedforsecurity")
        if algorithm and not (isinstance(flag, ast.Constant) and flag.value is False):
            return f"line {node.lineno}: {algorithm} is still used as a security hash"
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


def prompt_is_hardened(source: str) -> str | None:
    """None if some string literal in the snippet carries the injection-hardening marker; else a message.
    The independent check for the prompt / tool-description hardening codemods (``codemods.hardening``)."""
    from purpleteam.hardening_scan import MARKER_TAG  # lazy: this low-level module stays import-cycle free
    tree = _parse(source)
    if isinstance(tree, str):
        return tree
    for node in ast.walk(tree):
        if _is_string(node) and MARKER_TAG in _literal_text(node):
            return None
    return "the injection-hardening clause is not present in the text"


def action_is_gated(source: str) -> str | None:
    """None if the snippet is only a return of a gate-marked string literal -- no call, so nothing can still
    act -- else a message. The independent check for the unguarded-action codemod (``codemods.gate``)."""
    from purpleteam.gate_scan import GATE_TAG  # lazy: this low-level module stays import-cycle free
    tree = _parse(source)
    if isinstance(tree, str):
        return tree
    if any(isinstance(node, ast.Call) for node in ast.walk(tree)):
        return "the action still makes a call instead of holding for approval"
    first = tree.body[0] if len(tree.body) == 1 else None
    value = first.value if isinstance(first, ast.Return) else None
    if not (isinstance(value, ast.Constant) and isinstance(value.value, str) and GATE_TAG in value.value):
        return "the action does not return the human-approval hold"
    return None


# finding kind -> an independent checker; a kind absent here has no independent invariant yet.
INVARIANTS = {"sql_injection": no_dynamic_sql, "shell_injection": no_shell_injection,
              "hardcoded_secret": no_hardcoded_secret, "code_execution": no_code_execution,
              "insecure_deserialization": no_unsafe_deserialization,
              "tls_verification_disabled": tls_verification_on, "weak_hash": no_weak_hash,
              "request_without_timeout": requests_have_timeout,
              "unhardened_prompt": prompt_is_hardened, "unhardened_tool": prompt_is_hardened,
              "unguarded_action": action_is_gated}
