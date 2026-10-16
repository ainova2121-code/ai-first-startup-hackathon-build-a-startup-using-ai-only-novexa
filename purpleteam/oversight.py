"""Human oversight: hold a dangerous action for a person to approve or reject.

In production a consequential tool call is not silently blocked — it is held in a review queue
for a human (an operator or security reviewer) to decide, the way a team holds a suspicious change.
On the retry the gate honours the decision: approved proceeds, rejected stays blocked. Every
hold, approval and rejection is recorded to the signed audit ledger, so the human-oversight
control (EU AI Act Art. 14) is itself evidenced. Decisions are keyed to the exact tool and
arguments, so approving one action never approves another.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from purpleteam.patches.base import Blocked, Patch


def _key(tool: str, args: dict) -> str:
    blob = json.dumps({"tool": tool, "args": args}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


@dataclass
class ReviewItem:
    id: str
    agent: str
    tool: str
    args: dict
    reason: str
    status: str = "pending"  # pending | approved | rejected
    decided_by: str = ""


class ReviewQueue:
    def __init__(self, path: str | Path, ledger: Any = None) -> None:
        self.path = Path(path)
        self._ledger = ledger
        self._items: dict[str, ReviewItem] = {}
        if self.path.exists():
            self._items = {k: ReviewItem(**v) for k, v in json.loads(self.path.read_text()).items()}

    def decision(self, tool: str, args: dict) -> str | None:
        item = self._items.get(_key(tool, args))
        return item.status if item else None

    def hold(self, agent: str, tool: str, args: dict, reason: str) -> ReviewItem:
        key = _key(tool, args)
        if key not in self._items:
            self._items[key] = ReviewItem(id=key, agent=agent, tool=tool, args=args, reason=reason)
            self._save()
            self._record("oversight", {"action": "hold", "tool": tool, "item": key, "reason": reason})
        return self._items[key]

    def approve(self, item_id: str, by: str) -> None:
        self._decide(item_id, "approved", by)

    def reject(self, item_id: str, by: str, reason: str = "") -> None:
        self._decide(item_id, "rejected", by, reason)

    def pending(self) -> list[ReviewItem]:
        return [item for item in self._items.values() if item.status == "pending"]

    def _decide(self, item_id: str, status: str, by: str, reason: str = "") -> None:
        item = self._items[item_id]
        item.status, item.decided_by = status, by
        self._save()
        self._record(by, {"action": status, "tool": item.tool, "item": item_id, "reason": reason})

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({k: asdict(v) for k, v in self._items.items()}, indent=2))

    def _record(self, actor: str, payload: dict) -> None:
        if self._ledger is not None:
            self._ledger.append(actor, "review", payload)


class HumanReviewGate(Patch):
    """Hold a dangerous tool for a human to approve or reject (EU AI Act Art. 14)."""

    id, layer, answers = "P4", "tool-gate", ("injection_action", "excessive_agency", "jailbreak")

    def __init__(self, tools: set[str], queue: ReviewQueue) -> None:
        self._tools = set(tools)
        self._queue = queue

    def authorize(self, agent: str, tool: str, args: dict) -> None:
        if tool not in self._tools:
            return
        decision = self._queue.decision(tool, args)
        if decision == "approved":
            return
        if decision == "rejected":
            raise Blocked(f"{tool} was rejected by a reviewer")
        self._queue.hold(agent, tool, args, "dangerous action needs human verification")
        raise Blocked(f"{tool} held for human review")
