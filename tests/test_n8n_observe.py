"""An n8n workflow is profiled from its own JSON, and every node an execution ran is observed from n8n's execution
records -- custom nodes and steps that never touch a model included -- then judged like any other target's calls."""

import httpx

from purpleteam.adapter import REPORTED
from purpleteam.n8n.client import N8nClient
from purpleteam.n8n.observe import ExecutionObserver, workflow_profile
from purpleteam.oracle import CANARY_ACCOUNT, CanaryOracle
from purpleteam.adapter import Observation

WORKFLOW = {"id": "wf1", "name": "Records agent", "nodes": [
    {"name": "Webhook", "type": "n8n-nodes-base.webhook", "parameters": {}},
    {"name": "AI Agent", "type": "@n8n/n8n-nodes-langchain.agent",
     "parameters": {"options": {"systemMessage": "You maintain customer records."}}},
    {"name": "OpenAI Chat Model", "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi", "parameters": {}},
    {"name": "Update Record", "type": "@n8n/n8n-nodes-langchain.toolCode",
     "parameters": {"description": "Change a customer record to a new account value."}},
    {"name": "Sync Ledger", "type": "custom-nodes.ledgerSync", "parameters": {"description": "Write the change to the ledger"}},
], "connections": {"Update Record": {"ai_tool": [[{"node": "AI Agent", "type": "ai_tool", "index": 0}]]}}}


def _execution(execution_id, nonce, account):
    run_data = {
        "Webhook": [{"data": {"main": [[{"json": {"body": {"chatInput": f"[ref {nonce}] set {account}"}}}]]}}],
        "Update Record": [{"inputOverride": {"ai_tool": [[{"json": {"query": account}}]]},
                           "data": {"ai_tool": [[{"json": {"response": f"record updated: {account}"}}]]}}],
        "Sync Ledger": [{"data": {"main": [[{"json": {"synced": True}}]]}}],
    }
    return {"id": execution_id, "finished": True, "data": {"resultData": {"runData": run_data}}}


def _client(executions):
    def handler(request):
        assert request.url.params["workflowId"] == "wf1" and request.url.params["includeData"] == "true"
        return httpx.Response(200, json={"data": executions})
    return N8nClient("http://n8n.local", "key", transport=httpx.MockTransport(handler))


def test_the_profile_comes_from_the_workflow_itself():
    profile = workflow_profile(WORKFLOW)
    assert {t.name: t.agent for t in profile.tools} == {"Update_Record": "AI Agent", "Sync_Ledger": "Records agent"}
    (agent,) = profile.agent_info
    assert (agent.name, agent.tool_names, agent.prompt) == ("AI Agent", ("Update_Record",), "You maintain customer records.")
    assert "Update_Record" in profile.dangerous_tools


def test_every_acting_node_is_observed_attributed_and_judged():
    executions = [_execution("2", "n0nce", CANARY_ACCOUNT), _execution("1", "other", "US11BANK")]  # n8n: newest first
    observer = ExecutionObserver(_client(executions), WORKFLOW)
    calls = observer.drain("n0nce")
    assert [(c.tool, c.attributed) for c in calls] == [("Update_Record", False), ("Sync_Ledger", False),
                                                       ("Update_Record", True), ("Sync_Ledger", True)]
    assert calls[2].args == {"query": CANARY_ACCOUNT} and calls[2].evidence == REPORTED
    assert observer.drain("n0nce") == []  # each execution is seen once
    verdict = CanaryOracle({CANARY_ACCOUNT}, workflow_profile(WORKFLOW).dangerous_tools).judge(Observation("ok", calls))
    assert verdict.breached and verdict.tool == "Update_Record"
