"""A Target for any Python agent project, run in its own interpreter and environment, with no change to
its code: ``purpleteam.targets.shim`` runs inside it and asks this process before every tool call.

Each request starts a fresh process, so every attack meets a clean target and an edited source file is
simply what the next process imports. The guard (the policy) stays here: the shim only asks, and a
blocked call never runs. The target gets this process's environment minus the platform's own
credentials, plus whatever the operator passes in ``env``.
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from purpleteam.adapter import OBSERVED, PROPOSED, Observation, ToolCall
from purpleteam.discovery import AgentInfo, DiscoveredTool, TargetProfile, classify_risk, is_memory_surface, \
    is_retrieval_surface
from purpleteam.patches.base import Blocked

SHIM = Path(__file__).with_name("shim.py")
_RAISED = re.compile(r"^[A-Za-z_][\w.]*(Error|Exception|Exit|Interrupt)\b.*:")  # a traceback's final "Type: message"
_PLATFORM_ONLY = ("PURPLETEAM_", "GATEWAY_", "CODEMOD_", "LEDGERPILOT_", "HF_TOKEN", "GROQ_API_KEY")


class TargetFailed(RuntimeError):
    """The target process could not start or answer; carries the last line it wrote to stderr."""


class ProcessTarget:
    def __init__(self, name: str, python: Path, repo: Path, entry: str, guard: Any = None,
                 env: dict[str, str] | None = None, timeout: float = 300) -> None:
        self.name, self._python, self._repo, self._entry = name, python, repo, entry
        self._guard, self._timeout = guard, timeout
        self._env = {k: v for k, v in os.environ.items() if not k.startswith(_PLATFORM_ONLY)} | (env or {})

    def reset(self) -> None:
        return None  # every request already runs in a fresh process

    def profile(self) -> TargetProfile:
        with _Session(self) as session:
            session.write({"op": "profile"})
            message = session.until("profile")
        tools = []
        for t in message["tools"]:
            risk = classify_risk(t["name"], t["description"], t["args"])
            tools.append(DiscoveredTool(t["name"], t["description"], t["args"], t["source"], risk, t["agent"],
                                        agent_name=t["agent"], retrieval=is_retrieval_surface(t["name"], t["description"]),
                                        memory=is_memory_surface(t["name"], t["description"], risk)))
        agents = [AgentInfo(a["name"], a["prompt"], tuple(a["tools"])) for a in message["agents"]]
        return TargetProfile(self.name, tools, agents)

    def send(self, request: str) -> Observation:
        calls: list[ToolCall] = []
        attempts: list[ToolCall] = []  # calls the guard refused, and calls the model proposed that never ran
        with _Session(self) as session:
            session.write({"op": "send", "request": request})
            message = session.until("reply", calls, attempts)
        if message.get("error"):
            raise TargetFailed(f"the target raised {message['error']}")
        attempts += [ToolCall("model", p["tool"], p["args"], evidence=PROPOSED,
                              stopped_by="the target itself, which did not run it (for example a pause for approval)")
                     for p in message.get("proposed", []) if isinstance(p, dict) and isinstance(p.get("args"), dict)]
        return Observation(message["reply"], calls, attempts=attempts)

    def answer(self, message: dict) -> dict:
        """The guard's decision on one of the shim's questions."""
        if self._guard is None:
            return {"allow": True} if message["type"] == "authorize" else {"text": message["text"]}
        try:
            if message["type"] == "authorize":
                self._guard.authorize(message["agent"], message["tool"], message["args"])
                return {"allow": True}
            return {"text": self._guard.screen(message["agent"], message["text"], message["source"])}
        except Blocked as error:
            return {"allow": False, "reason": str(error)} if message["type"] == "authorize" else {"blocked": str(error)}


class _Session:
    """One target process for one request, read on a thread so a hung target is killed at the deadline."""

    def __init__(self, target: ProcessTarget) -> None:
        self._target = target
        self._lines: queue.Queue = queue.Queue()

    def __enter__(self) -> "_Session":
        t = self._target
        self._proc = subprocess.Popen([str(t._python), "-I", str(SHIM), str(t._repo), t._entry], cwd=t._repo,
                                      env=t._env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        self._deadline = time.monotonic() + t._timeout
        threading.Thread(target=self._pump, daemon=True).start()
        self._stderr: list[str] = []
        threading.Thread(target=lambda: self._stderr.extend(self._proc.stderr), daemon=True).start()
        self.until("ready")
        return self

    def __exit__(self, *exc: Any) -> None:
        try:
            self.write({"op": "quit"})
            self._proc.wait(timeout=10)
        except Exception:
            pass
        if self._proc.poll() is None:
            self._proc.kill()

    def _cause(self) -> str:
        """The exception the target died of (its traceback's ``SomethingError: ...`` line), not whatever
        trailing hint a library printed after it; the last non-empty line when there is no traceback."""
        lines = [l.strip() for l in self._stderr if l.strip()]
        raised = [l for l in lines if _RAISED.match(l)]
        return (raised or lines or ["no output"])[-1]

    def _pump(self) -> None:
        for line in self._proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def write(self, message: dict) -> None:
        self._proc.stdin.write(json.dumps(message) + "\n")
        self._proc.stdin.flush()

    def until(self, kind: str, calls: list[ToolCall] | None = None, attempts: list[ToolCall] | None = None) -> dict:
        """Answer the shim's questions until a message of ``kind`` arrives."""
        while True:
            remaining = self._deadline - time.monotonic()
            try:
                line = self._lines.get(timeout=max(remaining, 0.01))
            except queue.Empty:
                self._proc.kill()
                raise TimeoutError(f"the target did not answer within {self._target._timeout:.0f}s") from None
            if line is None:
                raise TargetFailed(f"the target process exited before answering: {self._cause()[:300]}")
            try:
                message = json.loads(line)
            except ValueError:
                continue  # a library writing straight to the real stdout: not a protocol message
            if message["type"] == kind:
                return message
            if message["type"] in ("authorize", "screen"):
                answer = self._target.answer(message)
                if message["type"] == "authorize" and not answer["allow"] and attempts is not None:
                    attempts.append(ToolCall(message["agent"], message["tool"], message["args"], evidence=OBSERVED,
                                             stopped_by=f"the runtime guard ({answer['reason'][:160]})"))
                self.write(answer)
            elif message["type"] == "call" and calls is not None:
                calls.append(ToolCall(message["agent"], message["tool"], message["args"], message["result"],
                                      evidence=OBSERVED))
