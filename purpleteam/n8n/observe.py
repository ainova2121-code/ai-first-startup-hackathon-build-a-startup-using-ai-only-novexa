"""What an n8n workflow is and what it did, read from n8n itself rather than from model traffic.

``workflow_profile`` reads the workflow JSON: each AI Agent node is an agent (its system message is its prompt), the
nodes wired into it as ``ai_tool`` are its tools, and every other acting node belongs to the workflow itself. Tool
names follow n8n's own convention (spaces become underscores), matching what the model and the gateway see.

``ExecutionObserver`` reads n8n's execution records, so every node that ran is seen -- custom and community nodes, and
steps that never touch a model included. It has the gateway observer's ``drain(nonce)`` shape, so an ``HttpTarget``
takes either. A call is attributed only if its execution carried the request's nonce; n8n reported it, so its
evidence is ``reported``.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from purpleteam.adapter import REPORTED, ToolCall
from purpleteam.discovery import AgentInfo, DiscoveredTool, TargetProfile, classify_risk, is_memory_surface, \
    is_retrieval_surface
from purpleteam.n8n.client import N8nClient

AGENT_TYPES = {"@n8n/n8n-nodes-langchain.agent"}
# Nodes that only route, shape or start data (or are an agent's model, memory or parser): not actions of their own.
_PASSIVE_TYPES = {"webhook", "respondToWebhook", "stickyNote", "set", "if", "switch", "merge", "noOp", "filter",
                  "splitOut", "aggregate", "sort", "limit", "wait"}
_PASSIVE_PREFIXES = ("lmChat", "embeddings", "memory", "outputParser")
_RESULT_CHARS = 2000


def tool_name(node_name: str) -> str:
    return node_name.replace(" ", "_")


def _passive(node_type: str) -> bool:
    short = node_type.rsplit(".", 1)[-1]
    return (node_type in AGENT_TYPES or short in _PASSIVE_TYPES or short.endswith("Trigger")
            or short.startswith(_PASSIVE_PREFIXES))


def _description(node: dict) -> str:
    params = node.get("parameters", {}) or {}
    return str(params.get("toolDescription") or params.get("description") or node.get("type", ""))


def workflow_profile(workflow: dict) -> TargetProfile:
    nodes = {n["name"]: n for n in workflow.get("nodes", [])}
    holder: dict[str, str] = {}  # tool node -> the agent it is wired into
    for source, outputs in (workflow.get("connections") or {}).items():
        for link in (outputs.get("ai_tool") or [[]])[0]:
            holder[source] = link["node"]
    agents = [AgentInfo(name, str(((n.get("parameters") or {}).get("options") or {}).get("systemMessage", "")),
                        tuple(tool_name(t) for t, a in holder.items() if a == name))
              for name, n in nodes.items() if n.get("type") in AGENT_TYPES]
    tools = []
    for name, node in nodes.items():
        if name not in holder and _passive(node.get("type", "")):
            continue
        description = _description(node)
        risk = classify_risk(tool_name(name), f"{description} {node.get('type', '')}", {})
        tools.append(DiscoveredTool(tool_name(name), description, {}, node.get("type", ""), risk, "",
                                    agent_name=holder.get(name, str(workflow.get("name", "workflow"))),
                                    retrieval=is_retrieval_surface(name, description),
                                    memory=is_memory_surface(name, description, risk)))
    return TargetProfile(str(workflow.get("name", "n8n")), tools, agents)


class ExecutionObserver:
    def __init__(self, client: N8nClient, workflow: dict) -> None:
        self._client, self._id = client, str(workflow["id"])
        self._agent = str(workflow.get("name", "workflow"))
        self._passive = {n["name"] for n in workflow.get("nodes", []) if _passive(n.get("type", ""))}
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    def drain(self, nonce: str | None = None) -> list[ToolCall]:
        """Every acting node in the executions n8n finished since the last drain, oldest first."""
        with self._lock:
            fresh = [e for e in reversed(self._client.executions(self._id)) if str(e.get("id")) not in self._seen]
            self._seen.update(str(e.get("id")) for e in fresh)
        calls = []
        for execution in fresh:
            attributed = nonce is None or nonce in json.dumps(execution)
            for node, runs in (((execution.get("data") or {}).get("resultData") or {}).get("runData") or {}).items():
                if node in self._passive:
                    continue
                for run in runs:
                    calls.append(ToolCall(self._agent, tool_name(node), _input(run), _output(run), evidence=REPORTED,
                                          attributed=attributed))
        return calls


def _first_json(channels: Any) -> Any:
    """The first item's JSON from an n8n ``{"main": [[{"json": ...}]]}`` (or ``ai_tool``) structure."""
    for items in (channels or {}).values():
        for item in (items or [[]])[0] or []:
            return item.get("json", item)
    return None


def _input(run: dict) -> dict:
    value = _first_json(run.get("inputOverride"))  # what an agent passed to a tool node
    return value if isinstance(value, dict) else {"input": value} if value is not None else {}


def _output(run: dict) -> str:
    value = _first_json(run.get("data"))
    if run.get("error"):
        value = {"error": (run["error"] or {}).get("message", "error")}
    return json.dumps(value, default=str)[:_RESULT_CHARS] if value is not None else ""
