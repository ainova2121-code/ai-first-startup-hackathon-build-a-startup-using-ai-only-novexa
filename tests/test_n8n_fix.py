"""n8n workflows are fixed through n8n's own API with prewritten, verified transforms, and restored in one step --
here against a faithful in-memory stand-in for n8n's REST API (the same paths, verbs and refusals)."""

import copy
import json

import httpx
import pytest

from purpleteam.audit.ledger import AuditLedger
from purpleteam.n8n.client import N8nClient, N8nError
from purpleteam.n8n.fix import NotFixable, WorkflowSnapshots, fix_workflow, parameterize_query
from purpleteam.n8n.scan import scan_workflow

SECRET = "Bearer sk-live-9f8e7d"
WORKFLOW = {"id": "wf1", "name": "Customer agent", "active": True, "settings": {"executionOrder": "v1", "binaryMode": "x"},
            "connections": {}, "nodes": [
    {"name": "Find customer", "type": "n8n-nodes-base.postgres", "parameters": {
        "operation": "executeQuery", "query": "=SELECT * FROM customers WHERE name = '{{ $json.name }}' AND id = {{ $json.id }}"}},
    {"name": "Call CRM", "type": "n8n-nodes-base.httpRequest", "parameters": {
        "url": "https://crm.example/api", "sendHeaders": True,
        "headerParameters": {"parameters": [{"name": "Authorization", "value": SECRET}]}}},
    {"name": "Run", "type": "n8n-nodes-base.executeCommand", "parameters": {"command": "=ls {{ $json.dir }}"}},
]}


class FakeN8n:
    """n8n's public API for one workflow: GET/PUT workflows (refusing read-only fields), credentials, auth."""

    def __init__(self):
        self.workflow, self.credentials, self.puts = copy.deepcopy(WORKFLOW), {}, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("X-N8N-API-KEY") != "test-key":
            return httpx.Response(401, json={"message": "unauthorized"})
        path, method = request.url.path, request.method
        if path == "/api/v1/workflows/wf1" and method == "GET":
            return httpx.Response(200, json=self.workflow)
        if path == "/api/v1/workflows/wf1" and method == "PUT":
            body = json.loads(request.content)
            if set(body) - {"name", "nodes", "connections", "settings", "staticData"} or "binaryMode" in body["settings"]:
                return httpx.Response(400, json={"message": "request/body must NOT have additional properties"})
            self.puts.append(body)
            self.workflow = {**self.workflow, **body}
            return httpx.Response(200, json=self.workflow)
        if path == "/api/v1/credentials" and method == "POST":
            body = json.loads(request.content)
            self.credentials[f"c{len(self.credentials) + 1}"] = body
            return httpx.Response(200, json={"id": f"c{len(self.credentials)}", "name": body["name"]})
        if path.startswith("/api/v1/credentials/") and method == "DELETE":
            self.credentials.pop(path.rsplit("/", 1)[1])
            return httpx.Response(200, json={})
        return httpx.Response(404, json={"message": "not found"})


@pytest.fixture
def n8n(tmp_path):
    fake = FakeN8n()
    client = N8nClient("http://n8n.local", "test-key", transport=httpx.MockTransport(fake))
    return fake, client, WorkflowSnapshots(tmp_path / "workflows.json"), AuditLedger(tmp_path / "audit.jsonl")


def test_sql_and_header_secrets_are_fixed_in_n8n_and_the_rest_is_left_for_review(n8n, tmp_path):
    fake, client, snapshots, ledger = n8n
    events = []
    result = fix_workflow(client, "wf1", snapshots, ledger, events.append)

    assert {(c["kind"], c["node"]) for c in result.changes} == {("sql_injection", "Find customer"),
                                                                ("hardcoded_secret", "Call CRM")}
    assert [s["kind"] for s in result.skipped] == ["shell_injection"]
    stored = fake.workflow
    sql = next(n for n in stored["nodes"] if n["name"] == "Find customer")["parameters"]
    assert sql["query"] == "SELECT * FROM customers WHERE name = $1 AND id = $2"
    assert sql["options"]["queryReplacement"] == "={{ $json.name }},{{ $json.id }}"
    http = next(n for n in stored["nodes"] if n["name"] == "Call CRM")
    assert http["credentials"]["httpHeaderAuth"]["id"] == "c1" and fake.credentials["c1"]["data"]["value"] == SECRET
    assert SECRET not in json.dumps(stored)  # the secret now lives only in n8n's credential store
    assert {f.kind for f in scan_workflow(stored)} == {"shell_injection"}  # the rescan agrees
    for record in (json.dumps(events), (tmp_path / "audit.jsonl").read_text()):
        assert "sk-live" not in record  # never in an event or the ledger


def test_one_restore_puts_the_original_workflow_back_and_deletes_the_created_credential(n8n):
    fake, client, snapshots, ledger = n8n
    fix_workflow(client, "wf1", snapshots, ledger)
    assert snapshots.restore_all(client) == [{"workflow": "wf1", "status": "restored"}]
    assert fake.workflow["nodes"] == WORKFLOW["nodes"] and fake.credentials == {}
    assert snapshots.modified() == []


def test_a_workflow_edited_in_n8n_since_the_fix_is_never_overwritten(n8n):
    fake, client, snapshots, ledger = n8n
    fix_workflow(client, "wf1", snapshots, ledger)
    fake.workflow["nodes"][2]["parameters"]["command"] = "ls"  # someone changed it by hand
    assert snapshots.restore_all(client)[0]["status"] == "skipped" and snapshots.modified() == ["wf1"]


def test_a_query_that_cannot_be_separated_cleanly_is_left_for_review():
    node = {"type": "n8n-nodes-base.postgres", "parameters": {"query": "={{ $json.table ? 'a' : 'b' }} {{"}}
    with pytest.raises(NotFixable, match="cannot separate"):
        parameterize_query(node)
    assert parameterize_query({"type": "n8n-nodes-base.mySql", "parameters": {"query": "=DELETE FROM t WHERE id={{ $json.id }}"}}) \
        == ("DELETE FROM t WHERE id=$1", "={{ $json.id }}")


def test_the_api_key_is_required_and_ids_cannot_shape_a_path(n8n):
    _, client, _, _ = n8n
    with pytest.raises(N8nError, match="401"):
        N8nClient("http://n8n.local", "wrong", transport=client._http._transport).workflow("wf1")
    with pytest.raises(ValueError):
        client.workflow("../credentials")
