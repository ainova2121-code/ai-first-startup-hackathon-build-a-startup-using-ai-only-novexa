"""Rebuild the tool calls of a streamed model answer from its server-sent events, as the stream passes.

One tap per provider format (OpenAI, Anthropic, Gemini). Each reads ``data:`` lines, ignores anything that is not
a tool-call event, never raises, is bounded in size, and ends up with the same shape as a non-streamed answer so
the dialect parser reads both alike.
"""

from __future__ import annotations

import json
from typing import Any

MAX_STREAM = 4_000_000


class Tap:
    """Reads a server-sent-event stream line by line and rebuilds the answer's tool calls as a non-streamed answer."""

    def __init__(self) -> None:
        self._pending = b""
        self._fed = 0
        self.overflowed = False

    def feed(self, chunk: bytes) -> None:
        self._fed += len(chunk)
        if self._fed > MAX_STREAM:
            self.overflowed = True
            self._pending = b""
            return
        *lines, self._pending = (self._pending + chunk).split(b"\n")
        for line in lines:
            if line.startswith(b"data:"):
                try:
                    event = json.loads(line[5:].strip())
                    if isinstance(event, dict):
                        self._event(event)
                except (ValueError, RecursionError, KeyError, TypeError, AttributeError):
                    pass  # not a tool-call event (another shape, [DONE], noise)

    def _event(self, event: dict) -> None:
        raise NotImplementedError

    def response(self) -> dict:
        raise NotImplementedError


class OpenAITap(Tap):
    def __init__(self) -> None:
        super().__init__()
        self._calls: dict[tuple[int, int], dict[str, str]] = {}

    def _event(self, event: dict) -> None:
        for choice in event["choices"]:
            for part in choice["delta"].get("tool_calls") or []:
                call = self._calls.setdefault((int(choice.get("index", 0)), int(part["index"])),
                                              {"id": "", "name": "", "arguments": ""})
                function = part.get("function") or {}
                call["id"] = call["id"] or str(part.get("id") or "")
                call["name"] = call["name"] or str(function.get("name") or "")
                call["arguments"] += str(function.get("arguments") or "")

    def response(self) -> dict:
        per_choice: dict[int, list] = {}
        for (choice, _), call in sorted(self._calls.items()):
            per_choice.setdefault(choice, []).append(
                {"id": call["id"], "function": {"name": call["name"], "arguments": call["arguments"]}})
        return {"choices": [{"message": {"tool_calls": calls}} for calls in per_choice.values()]}


class AnthropicTap(Tap):
    def __init__(self) -> None:
        super().__init__()
        self._blocks: dict[int, dict[str, Any]] = {}

    def _event(self, event: dict) -> None:
        if event["type"] == "content_block_start" and event["content_block"].get("type") in ("tool_use", "server_tool_use"):
            block = event["content_block"]
            self._blocks[int(event["index"])] = {"type": "tool_use", "id": block.get("id"), "name": block.get("name"),
                                                 "input": block.get("input") or {}, "json": ""}
        elif event["type"] == "content_block_delta" and int(event["index"]) in self._blocks:
            self._blocks[int(event["index"])]["json"] += str(event["delta"].get("partial_json") or "")

    def response(self) -> dict:
        return {"content": [{**{k: v for k, v in block.items() if k != "json"}, "input": block["json"] or block["input"]}
                            for _, block in sorted(self._blocks.items())]}


class GeminiTap(Tap):
    def __init__(self) -> None:
        super().__init__()
        self._parts: list[dict] = []

    def _event(self, event: dict) -> None:
        for candidate in event["candidates"]:
            self._parts += [p for p in candidate["content"]["parts"] if isinstance(p, dict) and
                            isinstance(p.get("functionCall") or p.get("function_call"), dict)]

    def response(self) -> dict:
        return {"candidates": [{"content": {"parts": self._parts}}]}
