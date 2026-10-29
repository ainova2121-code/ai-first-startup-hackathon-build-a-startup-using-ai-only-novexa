"""Fix n8n workflows through n8n's own API, the configuration way: prewritten transforms, never model-written.

A SQL node whose query is assembled from ``{{ expressions }}`` gets a fixed query with ``$1, $2 ...`` and the same
expressions moved into n8n's own *Query Parameters* option, so values are bound, never spliced into SQL. An API key
typed into an HTTP header moves into an n8n credential (encrypted by n8n) that the node then references. Each fix is
applied only when the workflow rescan no longer reports it, nothing new appears, and an independent invariant holds;
everything else -- shell commands, model-chosen URLs, Code-node JavaScript -- is reported for human review.

The original workflow is snapshotted before the first write, so one ``restore_all`` puts back every workflow exactly
(and deletes the credentials a fix created) unless someone edited it since. Secret values never reach the ledger or
an event: they exist only in the original workflow, the snapshot (operator-owned) and n8n's credential store.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from purpleteam.audit.hashing import canonical
from purpleteam.n8n.client import N8nClient
from purpleteam.n8n.scan import WorkflowFinding, is_expression, scan_workflow

_RESOLVABLE = re.compile(r"""(['"]?)\{\{\s*(.+?)\s*\}\}\1""", re.DOTALL)
_PARAMETERIZED = {"n8n-nodes-base.postgres", "n8n-nodes-base.postgresTool", "n8n-nodes-base.mySql", "n8n-nodes-base.mySqlTool"}
_HEADER_NODES = {"n8n-nodes-base.httpRequest", "n8n-nodes-base.httpRequestTool"}


class NotFixable(Exception):
    """No prewritten transform applies; the reason is shown and the finding left for human review."""


@dataclass
class WorkflowFix:
    changes: list[dict] = field(default_factory=list)  # {kind, node, path, before, after} -- secrets redacted
    skipped: list[dict] = field(default_factory=list)  # {kind, node, path, reason}


def _node(workflow: dict, name: str) -> dict:
    return next(n for n in workflow["nodes"] if n.get("name") == name)


def parameterize_query(node: dict) -> tuple[str, str]:
    """(fixed query, Query Parameters expression) for a query assembled from expressions."""
    if node.get("type") not in _PARAMETERIZED:
        raise NotFixable("only Postgres and MySQL nodes have a Query Parameters option to move values into")
    params = node.get("parameters", {})
    if (params.get("options") or {}).get("queryReplacement"):
        raise NotFixable("the node already binds some parameters; merging them is left for review")
    values: list[str] = []

    def bind(match: re.Match) -> str:
        values.append(match.group(2))
        return f"${len(values)}"

    query = _RESOLVABLE.sub(bind, params["query"].lstrip("="))
    if "{{" in query or not values:
        raise NotFixable("the query mixes expressions in a way a fixed template cannot separate")
    return query, "=" + ",".join(f"{{{{ {value} }}}}" for value in values)


def _sql_invariant(node: dict) -> str | None:
    """Independent of the scanner: the query is plain text, every $n is bound, and no $n sits inside quotes."""
    params = node["parameters"]
    query, binding = params.get("query", ""), (params.get("options") or {}).get("queryReplacement", "")
    if is_expression(query):
        return "the query is still an expression"
    used = {int(n) for n in re.findall(r"\$(\d+)", query)}
    bound = len(_RESOLVABLE.findall(binding))
    if used != set(range(1, bound + 1)):
        return "the placeholders and the bound values do not line up"
    if re.search(r"""['"]\$\d+['"]""", query):
        return "a placeholder is quoted, so it would be a literal, not a parameter"
    return None


def _fix_sql(workflow: dict, finding: WorkflowFinding) -> tuple[dict, dict | None]:
    node = _node(workflow, finding.node)
    before = node["parameters"]["query"]
    query, binding = parameterize_query(node)
    node["parameters"]["query"] = query
    node["parameters"].setdefault("options", {})["queryReplacement"] = binding
    problem = _sql_invariant(node)
    if problem:
        raise NotFixable(f"independent invariant failed: {problem}")
    return {"before": before, "after": f"{query}   ⟵ Query Parameters: {binding}"}, None


def _fix_secret(workflow: dict, finding: WorkflowFinding) -> tuple[dict, dict | None]:
    node = _node(workflow, finding.node)
    params = node["parameters"]
    if node.get("type") not in _HEADER_NODES or not finding.path.startswith("headerParameters.parameters["):
        raise NotFixable("only a header on an HTTP Request node can move into a header credential")
    if params.get("authentication", "none") != "none":
        raise NotFixable("the node already uses another credential")
    index = int(re.search(r"\[(\d+)\]", finding.path).group(1))
    header = params["headerParameters"]["parameters"].pop(index)
    if not params["headerParameters"]["parameters"]:
        params["sendHeaders"] = False
    params["authentication"], params["genericAuthType"] = "genericCredentialType", "httpHeaderAuth"
    name = f"purpleteam: {workflow.get('name', 'workflow')} / {node['name']}"[:120]
    node["credentials"] = {"httpHeaderAuth": {"id": "pending", "name": name}}  # the real id once n8n creates it
    if header["value"] in json.dumps(workflow):
        raise NotFixable("independent invariant failed: the secret value still appears in the workflow")
    change = {"before": f"{header['name']}: ••••••", "after": f"{header['name']} from n8n credential '{name}'"}
    return change, {"node": node["name"], "name": name, "type": "httpHeaderAuth",
                    "data": {"name": header["name"], "value": header["value"]}}


FIXERS: dict[str, Callable[[dict, WorkflowFinding], tuple[dict, dict | None]]] = {
    "sql_injection": _fix_sql, "hardcoded_secret": _fix_secret}


def _identity(finding: WorkflowFinding) -> tuple[str, str, str]:
    return finding.kind, finding.node, finding.path


def fix_workflow(client: N8nClient, workflow_id: str, snapshots: "WorkflowSnapshots", ledger: Any,
                 emit: Callable[[dict], None] = lambda event: None) -> WorkflowFix:
    original = client.workflow(workflow_id)
    findings = scan_workflow(original)
    result, patched, credentials = WorkflowFix(), copy.deepcopy(original), []
    for finding in findings:
        fixer = FIXERS.get(finding.kind)
        where = {"kind": finding.kind, "node": finding.node, "path": finding.path}
        attempt = copy.deepcopy(patched)
        try:
            if fixer is None:
                raise NotFixable("no prewritten fix for this kind; it needs human review")
            change, credential = fixer(attempt, finding)
            after = {_identity(f) for f in scan_workflow(attempt)}
            if _identity(finding) in after or after - {_identity(f) for f in findings}:
                raise NotFixable("the rescan still reports it, or the fix introduced a new finding")
        except (NotFixable, KeyError, StopIteration, ValueError) as error:
            result.skipped.append({**where, "reason": str(error)})
            continue
        patched = attempt
        result.changes.append({**where, **change})
        if credential:
            credentials.append(credential)
    if not result.changes:
        return _report(result, ledger, emit, workflow_id)
    snapshots.record(workflow_id, original)
    for credential in credentials:  # created only now, after every check passed; the id goes into the node
        created = client.create_credential(credential["name"], credential["type"], credential["data"])
        snapshots.add_credential(workflow_id, created["id"])
        _node(patched, credential["node"])["credentials"]["httpHeaderAuth"]["id"] = created["id"]
    written = client.update_workflow(workflow_id, patched)
    snapshots.written(workflow_id, written)
    return _report(result, ledger, emit, workflow_id)


def _report(result: WorkflowFix, ledger: Any, emit: Callable[[dict], None], workflow_id: str) -> WorkflowFix:
    for change in result.changes:
        ledger.append("defender", "workflow_patch", {"workflow": workflow_id, "kind": change["kind"],
                                                     "node": change["node"], "path": change["path"],
                                                     "approval": "prewritten n8n fix, verified by rescan + invariant"})
        emit({"type": "workflow_patch", "workflow": workflow_id, **change})
    for skip in result.skipped:
        ledger.append("defender", "workflow_patch_skipped", {"workflow": workflow_id, **skip})
        emit({"type": "workflow_patch_skipped", "workflow": workflow_id, **skip})
    return result


def _digest(workflow: dict) -> str:
    return hashlib.sha256(canonical({k: workflow.get(k) for k in ("name", "nodes", "connections")})).hexdigest()


class WorkflowSnapshots:
    """The original of every workflow a fix changed, kept in the operator's folder (it holds what the workflow held)."""

    def __init__(self, store: str | Path) -> None:
        self._store = Path(store)

    def _load(self) -> dict:
        return json.loads(self._store.read_text(encoding="utf-8")) if self._store.exists() else {}

    def _save(self, entries: dict) -> None:
        self._store.parent.mkdir(parents=True, exist_ok=True)
        self._store.write_text(json.dumps(entries, indent=2), encoding="utf-8")

    def record(self, workflow_id: str, original: dict) -> None:
        entries = self._load()
        entries.setdefault(workflow_id, {"original": original, "credentials": []})  # the first original is kept
        self._save(entries)

    def add_credential(self, workflow_id: str, credential_id: str) -> None:
        entries = self._load()
        entries[workflow_id]["credentials"].append(credential_id)
        self._save(entries)

    def written(self, workflow_id: str, workflow: dict) -> None:
        entries = self._load()
        entries[workflow_id]["written"] = _digest(workflow)
        self._save(entries)

    def modified(self) -> list[str]:
        return sorted(self._load())

    def restore_all(self, client: N8nClient) -> list[dict]:
        entries, results = self._load(), []
        for workflow_id, entry in sorted(entries.items()):
            if _digest(client.workflow(workflow_id)) != entry.get("written"):
                results.append({"workflow": workflow_id, "status": "skipped",
                                "reason": "edited in n8n since the platform changed it; left untouched"})
                continue
            client.update_workflow(workflow_id, entry["original"])
            for credential_id in entry["credentials"]:
                client.delete_credential(credential_id)
            del entries[workflow_id]
            results.append({"workflow": workflow_id, "status": "restored"})
        self._save(entries)
        return results
