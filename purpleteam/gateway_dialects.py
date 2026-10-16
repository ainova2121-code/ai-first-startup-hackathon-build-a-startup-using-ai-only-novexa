"""How each model provider's chat API looks on the wire, reduced to the one shape the observer reads.

The observer never sees a provider's JSON. A dialect turns one request/answer pair into an ``Exchange``: the
system prompt, the tools on offer, the text the product sent in, the tool results it reported back, and the
tool calls the model made. A dialect's ``Tap`` does the same for a streamed answer, rebuilding its tool calls
as the events pass. Supported: OpenAI chat completions (also what Azure OpenAI, Ollama, vLLM, LiteLLM and most
gateways speak), Anthropic Messages, and Gemini ``generateContent``. Anything signed per request (AWS Bedrock)
or tied to cloud identity (Vertex AI) cannot be proxied this way.

All of it is untrusted target data, so every read is type-checked, nothing raises, and nothing an oracle reads
is truncated: a call's arguments are kept whole (as raw text when they are not valid JSON), so padding cannot
push a canary out of view. A call is only ever taken from the model's *answer*; request history is the
client's word and can at most attach a result to a call already seen.

Call keys tie a result to its call: the provider's call id where there is one, else ``fn:<name>`` (Gemini
before call ids), so repeated calls to one function in one conversation share a key and the latest wins.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from purpleteam.gateway_taps import AnthropicTap, GeminiTap, OpenAITap, Tap

SYSTEM_ROLES = ("system", "developer")


@dataclass
class Exchange:
    system: str = ""
    tools: list[tuple[Any, str, dict]] = field(default_factory=list)  # (name, description, argument properties)
    users: str = ""        # the user and system text the product sent in, to look for a request nonce in
    first_user: str = ""   # tells one conversation from another
    results: list[tuple[str, str]] = field(default_factory=list)  # (call key, result) as the product reported it
    calls: list[tuple[str | None, Any, Any]] = field(default_factory=list)  # (call key, tool name, raw arguments)
    answer: str = ""       # the text of the model's answer
    native: list[str] = field(default_factory=list)  # tools the provider runs itself, which a gateway cannot hold back


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _dicts(value: Any) -> list[dict]:
    return [v for v in _list(value) if isinstance(v, dict)]


def _text(content: Any) -> str:
    """Text of a message: a string, or the text parts/blocks of a list (images, tool blocks and the like add none)."""
    if isinstance(content, str):
        return content
    return "".join(p["text"] for p in _list(content) if isinstance(p, dict) and isinstance(p.get("text"), str))


def _properties(schema: Any) -> dict:
    properties = schema.get("properties") if isinstance(schema, dict) else None
    return {k: v for k, v in properties.items() if isinstance(v, dict)} if isinstance(properties, dict) else {}


def _description(entry: dict) -> str:
    return entry["description"] if isinstance(entry.get("description"), str) else ""


def _json(value: Any) -> str:
    try:
        return value if isinstance(value, str) else json.dumps(value, default=str)
    except (ValueError, RecursionError, TypeError):
        return repr(value)[:100_000]


def _key(call_id: Any, name: Any) -> str:
    return call_id if isinstance(call_id, str) and call_id else f"fn:{name}"


class Dialect(Protocol):
    name: str

    def parse(self, request: dict, response: dict) -> Exchange: ...

    def tap(self) -> "Tap": ...

    def block(self, response: dict, message: str) -> dict:
        """A copy of the answer with every tool call withdrawn and ``message`` as its text instead."""
        ...


class OpenAI:
    name = "openai"

    def parse(self, request: dict, response: dict) -> Exchange:
        messages = _dicts(request.get("messages"))
        system = [m for m in messages if m.get("role") in SYSTEM_ROLES]
        exchange = Exchange(
            system="\n".join(t for t in (_text(m.get("content")) for m in system) if t),
            users="\n".join(_text(m.get("content")) for m in messages if m.get("role") in ("user", *SYSTEM_ROLES)),
            first_user=next((_text(m.get("content")) for m in messages if m.get("role") == "user"), ""))
        for entry in _dicts(request.get("tools")) + _dicts(request.get("functions")):
            function = entry.get("function") if isinstance(entry.get("function"), dict) else entry
            name = function.get("name") or entry.get("type")  # no name: a provider-native tool
            exchange.tools.append((name, _description(function), _properties(function.get("parameters"))))
            if "parameters" not in function and "name" not in function:
                exchange.native.append(str(name))
        exchange.results = [(m["tool_call_id"], _text(m.get("content"))) for m in messages
                            if m.get("role") == "tool" and isinstance(m.get("tool_call_id"), str)]
        for choice in _dicts(response.get("choices")):
            message = choice.get("message")
            if isinstance(message, dict) and not exchange.answer:
                exchange.answer = _text(message.get("content"))
            for call in _dicts(message.get("tool_calls") if isinstance(message, dict) else None):
                function = call.get("function")
                if isinstance(function, dict):
                    exchange.calls.append((call["id"] if isinstance(call.get("id"), str) else None,
                                           function.get("name"), function.get("arguments")))
        return exchange

    def tap(self) -> "Tap":
        return OpenAITap()

    def block(self, response: dict, message: str) -> dict:
        blocked = copy.deepcopy(response)
        for choice in _dicts(blocked.get("choices")):
            content = choice.get("message")
            if isinstance(content, dict) and (content.get("tool_calls") or content.get("function_call")):
                content.pop("tool_calls", None)
                content.pop("function_call", None)
                content["content"] = message
                choice["finish_reason"] = "stop"
        return blocked


class Anthropic:
    name = "anthropic"

    def parse(self, request: dict, response: dict) -> Exchange:
        exchange = Exchange(system=_text(request.get("system")))
        for entry in _dicts(request.get("tools")):  # a typed tool (bash, computer, web search...) is provider-native
            exchange.tools.append((entry.get("name") or entry.get("type"), _description(entry),
                                   _properties(entry.get("input_schema"))))
            if entry.get("type") not in (None, "custom"):
                exchange.native.append(str(entry.get("name") or entry.get("type")))
        users: list[str] = []
        for message in _dicts(request.get("messages")):
            if message.get("role") != "user":
                continue
            text = _text(message.get("content"))
            users.append(text)
            exchange.first_user = exchange.first_user or text
            for block in _dicts(message.get("content")):
                if block.get("type") == "tool_result" and isinstance(block.get("tool_use_id"), str):
                    exchange.results.append((block["tool_use_id"], _text(block.get("content"))))
        exchange.users = "\n".join([exchange.system, *users])
        exchange.answer = _text(response.get("content"))
        for block in _dicts(response.get("content")):
            if block.get("type") in ("tool_use", "server_tool_use"):
                exchange.calls.append((block["id"] if isinstance(block.get("id"), str) else None,
                                       block.get("name"), block.get("input")))
        return exchange

    def tap(self) -> "Tap":
        return AnthropicTap()

    def block(self, response: dict, message: str) -> dict:
        blocked = copy.deepcopy(response)
        blocks = _dicts(blocked.get("content"))
        if any(b.get("type") in ("tool_use", "server_tool_use") for b in blocks):
            blocked["content"] = [b for b in blocks if b.get("type") not in ("tool_use", "server_tool_use")]
            blocked["content"].append({"type": "text", "text": message})
            blocked["stop_reason"] = "end_turn"
        return blocked


class Gemini:
    name = "gemini"

    def parse(self, request: dict, response: dict) -> Exchange:
        instruction = request.get("systemInstruction") or request.get("system_instruction")
        exchange = Exchange(system="".join(_text(p.get("text")) for p in _dicts(
            instruction.get("parts") if isinstance(instruction, dict) else None)))
        for entry in _dicts(request.get("tools")):
            declarations = entry.get("functionDeclarations") or entry.get("function_declarations")
            for declaration in _dicts(declarations):
                exchange.tools.append((declaration.get("name"), _description(declaration),
                                       _properties(declaration.get("parameters"))))
            for kind in entry:
                if kind not in ("functionDeclarations", "function_declarations"):
                    exchange.tools.append((kind, "", {}))
                    exchange.native.append(kind)
        users: list[str] = []
        for content in _dicts(request.get("contents")):
            for part in _dicts(content.get("parts")):
                reply = part.get("functionResponse") or part.get("function_response")
                if isinstance(reply, dict):
                    exchange.results.append((_key(reply.get("id"), reply.get("name")), _json(reply.get("response"))))
                elif content.get("role", "user") == "user" and isinstance(part.get("text"), str):
                    users.append(part["text"])
                    exchange.first_user = exchange.first_user or part["text"]
        exchange.users = "\n".join([exchange.system, *users])
        for candidate in _dicts(response.get("candidates")):
            content = candidate.get("content")
            for part in _dicts(content.get("parts") if isinstance(content, dict) else None):
                if isinstance(part.get("text"), str) and not exchange.answer:
                    exchange.answer = part["text"]
                call = part.get("functionCall") or part.get("function_call")
                if isinstance(call, dict):
                    exchange.calls.append((_key(call.get("id"), call.get("name")), call.get("name"), call.get("args")))
        return exchange

    def tap(self) -> "Tap":
        return GeminiTap()

    def block(self, response: dict, message: str) -> dict:
        blocked = copy.deepcopy(response)
        for candidate in _dicts(blocked.get("candidates")):
            content = candidate.get("content")
            parts = _dicts(content.get("parts") if isinstance(content, dict) else None)
            if any(isinstance(p.get("functionCall") or p.get("function_call"), dict) for p in parts):
                content["parts"] = [p for p in parts if not isinstance(p.get("functionCall") or p.get("function_call"), dict)]
                content["parts"].append({"text": message})
                candidate["finishReason"] = "STOP"
        return blocked


OPENAI, ANTHROPIC, GEMINI = OpenAI(), Anthropic(), Gemini()
