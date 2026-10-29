"""Human oversight: hold a dangerous action for a person to approve or reject.

In production a consequential tool call is not silently blocked — it is held in a review queue
for a human (an operator or security reviewer) to decide, the way a team holds a suspicious change.
On the retry the gate honours the decision: approved proceeds once and is then spent (a repeat of
the exact same call needs a fresh approval, not a standing pass), rejected stays blocked. An
unresolved hold and an unspent approval both expire, so a stale decision can never be honoured long
after the human who made it (or the business state it was made against) has moved on. Every hold,
approval and rejection is recorded to the signed audit ledger, so the human-oversight control (EU
AI Act Art. 14) is itself evidenced. Decisions are keyed to the agent, the exact tool and its exact
arguments, so approving one agent's action never approves another's merely-same-named tool call.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from purpleteam.patches.base import Blocked, HoldForReview, Patch

DEFAULT_TTL = 24 * 3600  # an unresolved hold, or a spent/unspent approval, is stale after this long


def _key(agent: str, tool: str, args: dict) -> str:
    blob = json.dumps({"agent": agent, "tool": tool, "args": args}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


@dataclass
class ReviewItem:
    id: str
    agent: str
    tool: str
    args: dict
    reason: str
    status: str = "pending"  # pending | approved | rejected | consumed
    decided_by: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0


class ReviewQueue:
    """Durable by default (one JSON file, written atomically); pass ``path=None`` for an
    ephemeral, in-process-only queue (tests, a quick local run) — same decisions, just not
    surviving a restart. ``redactor`` (a ``purpleteam.audit.privacy.Redactor``), when given,
    redacts sensitive argument values before they are ever written to disk or the ledger — a
    caller still gets the real values back from ``hold()`` at the moment of the call, the same
    "shown once" discipline a bootstrap key already gets, never a second time after that.
    ``authorized_reviewers``, when given, is the only set of names ``approve``/``reject`` accept
    as ``by`` — anyone else's decision is refused, not silently honoured.
    """

    def __init__(self, path: str | Path | None = None, *, ledger: Any = None, redactor: Any = None,
                authorized_reviewers: set[str] | None = None, ttl_seconds: float = DEFAULT_TTL,
                clock: Any = time.time) -> None:
        self.path = Path(path) if path is not None else None
        self._ledger = ledger
        self._redactor = redactor
        self._authorized = authorized_reviewers
        self._ttl = ttl_seconds
        self._clock = clock
        self._items: dict[str, ReviewItem] = {}
        if self.path is not None and self.path.exists():
            self._items = {k: ReviewItem(**v) for k, v in json.loads(self.path.read_text()).items()}

    def decision(self, agent: str, tool: str, args: dict) -> str | None:
        """``None`` for no record, an expired hold, or a spent/expired approval — any of which
        must be treated as "nothing decided yet", never as a standing pass."""
        item = self._items.get(_key(agent, tool, args))
        if item is None:
            return None
        if item.status in ("pending", "approved") and self._clock() >= item.expires_at:
            return None
        return item.status

    def hold(self, agent: str, tool: str, args: dict, reason: str, ttl_seconds: float | None = None) -> ReviewItem:
        key = _key(agent, tool, args)
        existing = self._items.get(key)
        if existing is not None and existing.status == "pending" and self._clock() < existing.expires_at:
            return existing
        stored_args = self._redactor.redact(args) if self._redactor is not None else dict(args)
        now = self._clock()
        item = ReviewItem(id=key, agent=agent, tool=tool, args=stored_args, reason=reason,
                          created_at=now, expires_at=now + (ttl_seconds or self._ttl))
        self._items[key] = item
        self._save()
        self._record("oversight", {"action": "hold", "agent": agent, "tool": tool, "item": key, "reason": reason})
        return item

    def consume(self, agent: str, tool: str, args: dict) -> None:
        """Marks a live approval spent the instant the call it covered actually goes through, so
        the same approval can never authorize a second, later call with the same arguments."""
        item = self._items.get(_key(agent, tool, args))
        if item is not None and item.status == "approved":
            item.status = "consumed"
            self._save()

    def approve(self, item_id: str, by: str) -> None:
        self._authorize_reviewer(by)
        self._decide(item_id, "approved", by)

    def reject(self, item_id: str, by: str, reason: str = "") -> None:
        self._authorize_reviewer(by)
        self._decide(item_id, "rejected", by, reason)

    def pending(self) -> list[ReviewItem]:
        return [item for item in self._items.values()
               if item.status == "pending" and self._clock() < item.expires_at]

    def _authorize_reviewer(self, by: str) -> None:
        if self._authorized is not None and by not in self._authorized:
            raise PermissionError(f"{by!r} is not an authorized reviewer")

    def _decide(self, item_id: str, status: str, by: str, reason: str = "") -> None:
        item = self._items[item_id]
        item.status, item.decided_by = status, by
        self._save()
        self._record(by, {"action": status, "agent": item.agent, "tool": item.tool, "item": item_id, "reason": reason})

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(f"{self.path.suffix}.tmp")
        tmp.write_text(json.dumps({k: asdict(v) for k, v in self._items.items()}, indent=2))
        tmp.replace(self.path)  # atomic on POSIX and Windows alike

    def _record(self, actor: str, payload: dict) -> None:
        if self._ledger is not None:
            self._ledger.append(actor, "review", payload)


class HumanReviewGate(Patch):
    """Hold a dangerous action for a human to approve or reject (EU AI Act Art. 14) — scoped to
    exactly the ``(agent, tool)`` pairs a proven finding named, never every dangerous tool for
    every agent just because one of them breached."""

    id, layer, answers = "P4", "tool-gate", ("injection_action", "excessive_agency", "jailbreak")

    def __init__(self, scoped: set[tuple[str, str]], queue: ReviewQueue) -> None:
        self._scoped = set(scoped)
        self._queue = queue

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        if (agent, tool) not in self._scoped:
            return
        decision = self._queue.decision(agent, tool, args)
        if decision == "approved":
            self._queue.consume(agent, tool, args)
            return
        if decision == "rejected":
            raise Blocked(f"{tool} was rejected by a reviewer")
        self._queue.hold(agent, tool, args, "dangerous action needs human verification")
        raise HoldForReview(f"{tool} held for human review")
