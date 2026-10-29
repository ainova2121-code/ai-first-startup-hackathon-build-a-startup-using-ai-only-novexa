"""Static analysis of n8n workflows: the node configuration (JSON) and the JavaScript inside Code nodes.

Most n8n weaknesses are configuration, not code: a SQL node whose query is assembled from an expression, a
shell command built from one, an API key typed into an HTTP header, a URL the model chooses. Those are read
straight from the workflow's node parameters. JavaScript in Code nodes is parsed with a real grammar
(tree-sitter) -- never run, never matched with regular expressions over the source.

An n8n expression is a parameter value starting with ``=`` (``={{ $json.name }}``), or any ``{{ ... }}`` or
``$fromAI(...)`` inside one: data that arrives at run time, often from the model or the webhook caller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

import tree_sitter
import tree_sitter_javascript

from purpleteam.codemods.invariants import _SQL_SHAPE
from purpleteam.sast import StaticFinding

SQL_NODES = {"n8n-nodes-base.postgres", "n8n-nodes-base.mySql", "n8n-nodes-base.microsoftSql",
             "n8n-nodes-base.postgresTool", "n8n-nodes-base.mySqlTool", "n8n-nodes-base.microsoftSqlTool"}
HTTP_NODES = {"n8n-nodes-base.httpRequest", "n8n-nodes-base.httpRequestTool", "@n8n/n8n-nodes-langchain.toolHttpRequest"}
COMMAND_NODES = {"n8n-nodes-base.executeCommand"}
CODE_FIELDS = {"n8n-nodes-base.code": "jsCode", "@n8n/n8n-nodes-langchain.toolCode": "jsCode",
               "n8n-nodes-base.function": "functionCode", "n8n-nodes-base.functionItem": "functionCode"}
SECRET_NAME = re.compile(r"(authorization|api[-_ ]?key|token|secret|password|passwd|bearer)", re.IGNORECASE)
_SQL_CALLS = {"query", "execute", "raw", "unsafe", "run", "all", "get"}
_SHELL_CALLS = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"}
_PARSER = tree_sitter.Parser(tree_sitter.Language(tree_sitter_javascript.language()))
_WRAP = "async function __n8n__() {\n"  # a Code node's body runs inside an async function


@dataclass(frozen=True)
class WorkflowFinding:
    kind: str
    workflow: str  # the workflow's id
    node: str      # the node's name, unique within a workflow
    path: str      # where in the node: a parameter path, or "jsCode:<line>"
    detail: str
    severity: str = "medium"

    def as_static(self, workflow_name: str) -> StaticFinding:
        line = int(self.path.rsplit(":", 1)[1]) if ":" in self.path else 0
        return StaticFinding(self.kind, f"n8n/{workflow_name}/{self.node}", line, f"{self.detail} ({self.path})",
                             self.severity)


def is_expression(value: Any) -> bool:
    return isinstance(value, str) and (value.startswith("=") or "{{" in value or "$fromAI(" in value)


def _strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Every string parameter, with its path (``headerParameters.parameters[0].value``)."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}[{index}]")


def scan_workflow(workflow: dict) -> list[WorkflowFinding]:
    findings: list[WorkflowFinding] = []
    for node in workflow.get("nodes", []):
        kind, name, params = node.get("type", ""), node.get("name", "?"), node.get("parameters", {}) or {}

        def found(what: str, path: str, detail: str, severity: str = "medium") -> None:
            findings.append(WorkflowFinding(what, str(workflow.get("id", "")), name, path, detail, severity))

        if kind in SQL_NODES and is_expression(params.get("query")):
            found("sql_injection", "query", "the SQL query is assembled from an expression", "high")
        if kind in COMMAND_NODES and is_expression(params.get("command")):
            found("shell_injection", "command", "the shell command is assembled from an expression", "high")
        if kind in HTTP_NODES:
            if is_expression(params.get("url")) and ("$fromAI(" in params["url"] or "$json" in params["url"]):
                found("model_controlled_url", "url", "the request URL comes from run-time data the model or caller controls")
            for path, value in _strings(params):
                if path.endswith(".value") and not is_expression(value) and value.strip():
                    label = _sibling(params, path, "name")
                    if label and SECRET_NAME.search(label):
                        found("hardcoded_secret", path, f"a credential is typed into the '{label}' parameter", "high")
        field = CODE_FIELDS.get(kind)
        if field and isinstance(params.get(field), str):
            for what, line, detail in js_findings(params[field]):
                found(what, f"{field}:{line}", detail, "high" if what != "hardcoded_secret" else "medium")
    return findings


def _sibling(params: dict, path: str, key: str) -> str | None:
    """The ``name`` next to a ``value`` at ``path`` (n8n's name/value parameter pairs)."""
    target: Any = params
    for part in re.findall(r"[^.\[\]]+|\[\d+\]", path.rsplit(".", 1)[0]):
        target = target[int(part[1:-1])] if part.startswith("[") else target.get(part) if isinstance(target, dict) else None
        if target is None:
            return None
    return target.get(key) if isinstance(target, dict) else None


def parse_js(code: str) -> tree_sitter.Tree:
    return _PARSER.parse((_WRAP + code + "\n}").encode("utf-8"))


def _text(node: tree_sitter.Node) -> str:
    return node.text.decode("utf-8", "replace")


def _static_text(node: tree_sitter.Node) -> str:
    """A template or concatenation as written, each run-time part shown as ``{}``."""
    if node.type == "string":
        return _text(node)[1:-1]
    if node.type == "template_string":
        return "".join("{}" if c.type == "template_substitution" else _text(c) for c in node.children if c.type not in ("`",))
    if node.type == "binary_expression":
        return "".join(_static_text(c) if c.type in ("string", "template_string", "binary_expression") else "{}"
                       for c in node.children if c.type != "+")
    return "{}"


def _dynamic(node: tree_sitter.Node) -> bool:
    return (node.type == "template_string" and any(c.type == "template_substitution" for c in node.children)) or \
           (node.type == "binary_expression" and any(c.type == "+" for c in node.children))


def js_findings(code: str) -> list[tuple[str, int, str]]:
    """(kind, line in the Code node, detail) for each unsafe shape. Code that does not parse is itself reported."""
    tree = parse_js(code)
    if tree.root_node.has_error:
        return [("unparseable_code", 1, "the JavaScript does not parse, so it cannot be checked")]
    found = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        line = node.start_point[0]  # the wrapper adds one line before the node's own first line
        if node.type == "call_expression":
            func, args = node.child_by_field_name("function"), node.child_by_field_name("arguments")
            name = _text(func.child_by_field_name("property")) if func.type == "member_expression" else _text(func)
            first = next((a for a in args.named_children), None) if args else None
            if name in _SQL_CALLS and first is not None and _dynamic(first) and _SQL_SHAPE.match(_static_text(first)):
                found.append(("sql_injection", line, f"{name}() gets SQL built from run-time values"))
            if name == "eval":
                found.append(("code_execution", line, "eval() runs text as code"))
            if name in _SHELL_CALLS or (name == "require" and first is not None and "child_process" in _text(first)):
                found.append(("shell_injection", line, f"{name}() can run shell commands"))
        elif node.type == "new_expression" and _text(node.child_by_field_name("constructor")) == "Function":
            found.append(("code_execution", line, "new Function() runs text as code"))
        elif node.type == "variable_declarator":
            name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if value is not None and value.type == "string" and SECRET_NAME.search(_text(name)) and len(_text(value)) > 2:
                found.append(("hardcoded_secret", line, f"'{_text(name)}' holds a literal credential"))
    return sorted(set(found), key=lambda f: (f[1], f[0]))
