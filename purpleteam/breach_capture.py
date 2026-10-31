"""Keep an unpatched target's database the moment an attack breaches it, so the Database page can show what a breach
really did -- the attacker's payment, the changed bank account -- next to the patched agent's database.

Every attack runs on its own fresh copy of the target, so without this only the last copy the run used (a patched
re-attack) is ever seen. Of all the copies an attack breached, the one where the attack left the most canary values
behind is kept: a payment to the attacker's account is stronger evidence than an invoice recorded with it.

Part of the LedgerPilot live console (like ``live_run``); the domain-agnostic platform never imports it. This is
display evidence only: the signed ledger and the verdict never depend on it.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from typing import Any

from purpleteam.adapter import Observation
from purpleteam.oracle import Oracle


class BreachCapture:
    def __init__(self, oracle: Oracle, canaries: Iterable[str], save: Callable[[dict], None]) -> None:
        self._oracle, self._canaries, self._save = oracle, tuple(canaries), save
        self._best = -1  # canary values left in the kept snapshot; -1 until the first breach
        self._lock = threading.Lock()

    def watch(self, target: Any) -> _Watched:
        """``target``, with every breaching request's database kept (attacks run in parallel, so this is thread-safe)."""
        return _Watched(target, self)

    def _observe(self, target: Any, observation: Observation) -> None:
        verdict = self._oracle.judge(observation)
        if not verdict.breached:
            return
        snapshot = target.database_snapshot()
        left = sum(1 for table in snapshot["tables"] for row in table["rows"] for value in row.values()
                   if isinstance(value, str) and any(canary in value for canary in self._canaries))
        with self._lock:
            if left > self._best:
                self._best = left
                self._save({**snapshot, "proof": verdict.detail,
                            "reached": [{"agent": agent, "tool": tool} for agent, tool in verdict.reached_tools]})


class _Watched:
    def __init__(self, target: Any, capture: BreachCapture) -> None:
        self._target, self._capture = target, capture

    def send(self, request: str) -> Observation:
        observation = self._target.send(request)
        try:
            self._capture._observe(self._target, observation)
        except Exception:  # display evidence only: failing to keep a snapshot must never fail the attack itself
            pass
        return observation

    def __getattr__(self, name: str) -> Any:  # reset, database_snapshot and the rest are the target's own
        return getattr(self._target, name)
