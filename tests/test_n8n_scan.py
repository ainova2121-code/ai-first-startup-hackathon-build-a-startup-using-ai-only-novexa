"""n8n workflows are scanned from their configuration and the JavaScript in their Code nodes -- parsed, never run."""

from purpleteam.n8n.scan import js_findings, scan_workflow


def _node(name, kind, params):
    return {"name": name, "type": kind, "parameters": params}


WORKFLOW = {"id": "wf1", "nodes": [
    _node("Find customer", "n8n-nodes-base.postgres",
          {"operation": "executeQuery", "query": "=SELECT * FROM customers WHERE name = '{{ $json.name }}'"}),
    _node("Safe lookup", "n8n-nodes-base.postgres", {"operation": "executeQuery", "query": "SELECT 1"}),
    _node("Run", "n8n-nodes-base.executeCommand", {"command": "=ls {{ $json.dir }}"}),
    _node("Call API", "n8n-nodes-base.httpRequest", {
        "url": "={{ $fromAI('url') }}",
        "headerParameters": {"parameters": [{"name": "Authorization", "value": "Bearer sk-live-123"},
                                            {"name": "Accept", "value": "application/json"}]}}),
    _node("Code", "n8n-nodes-base.code", {"jsCode": (
        "const apiKey = 'sk-test-abc';\n"
        "const rows = await db.query(`SELECT * FROM t WHERE id = ${$json.id}`);\n"
        "const safe = await db.query('SELECT * FROM t WHERE id = $1', [$json.id]);\n"
        "return rows?.map((r) => ({ json: r }));")}),
]}


def test_configuration_and_code_findings_name_the_node_and_place():
    found = {(f.kind, f.node, f.path) for f in scan_workflow(WORKFLOW)}
    assert found == {
        ("sql_injection", "Find customer", "query"),
        ("shell_injection", "Run", "command"),
        ("model_controlled_url", "Call API", "url"),
        ("hardcoded_secret", "Call API", "headerParameters.parameters[0].value"),
        ("hardcoded_secret", "Code", "jsCode:1"),
        ("sql_injection", "Code", "jsCode:2"),
    }


def test_modern_javascript_parses_and_dangerous_calls_are_found():
    assert js_findings("const x = await fetch(url);\nreturn x?.json ?? [];") == []
    assert {k for k, _, _ in js_findings("eval(code);\nnew Function(src)();\nrequire('child_process').exec(c);")} \
        == {"code_execution", "shell_injection"}
    assert js_findings("const = ;")[0][0] == "unparseable_code"  # never silently skipped
