"""Verify a ledger as it arrives, page by page, against public keys pinned before the first page.

``verify_log`` needs the whole log. A fleet console reads each gateway's log through a paginated export, so every
page is checked here against the state the previous page left: the next sequence number, the same log id, each
actor's previous hash, the recomputed content hash, a signature by a pinned key that was not revoked, and every
seal against the Merkle root of all events before it. Between pages only that small state is kept -- actor heads and
the Merkle frontier -- never the events, and it never moves past the last event that verified.

What this proves: nothing was altered, dropped, reordered, replayed or invented after it was signed, on the
gateway's disk or on the wire. It cannot stop a gateway that holds its own signing keys from signing a false event.
"""

from __future__ import annotations

from purpleteam.audit.hashing import MerkleFrontier
from purpleteam.audit.verify import VerifyResult, event_problem, pinned_keys


class StreamVerifier:
    def __init__(self, trust: dict, state: dict | None = None, *, require_pq: bool = False,
                 max_clock_skew: float = 60.0) -> None:
        """``trust``: the pinned ``{"keys": ..., "revoked": ...}`` bundle (ValueError if malformed or empty).
        ``state``: what ``state`` returned after the last page, or None to start at the first event."""
        self._keys, self._revoked = pinned_keys(trust)
        if not self._keys:
            raise ValueError("the trust bundle pins no public keys")
        state = state or {}
        self._log: str | None = state.get("log")
        self._next = int(state.get("next_seq", 0))
        self._heads: dict[str, str] = dict(state.get("heads", {}))
        self._frontier = MerkleFrontier(state.get("frontier"))
        self._latest: float | None = state.get("latest_ts")
        self._require_pq, self._skew = require_pq, max_clock_skew
        if self._frontier.size != self._next:
            raise ValueError("the saved verification state is inconsistent")

    @property
    def verified(self) -> int:
        """How many events, from the first, have verified."""
        return self._next

    @property
    def log_id(self) -> str | None:
        return self._log

    @property
    def state(self) -> dict:
        return {"log": self._log, "next_seq": self._next, "heads": dict(self._heads),
                "frontier": self._frontier.to_list(), "latest_ts": self._latest}

    def feed(self, events: list) -> VerifyResult:
        """Accept each event in turn; stop at the first that fails, accepting nothing from it on."""
        for event in events:
            try:
                problem = event_problem(event, self._next, self._log, self._heads, self._keys, self._revoked,
                                        self._require_pq, self._frontier.root)
            except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
                problem = "malformed event"
            if problem is None and self._latest is not None and event["ts"] < self._latest - self._skew:
                problem = "timestamp goes backwards"
            if problem is not None:
                return VerifyResult(False, self._next, self._next, problem)
            self._accept(event)
        return VerifyResult(True, self._next)

    def _accept(self, event: dict) -> None:
        self._log = event["log"]
        self._heads[event["actor"]] = event["hash"]
        self._frontier.append(event["hash"])
        self._latest = event["ts"] if self._latest is None else max(self._latest, event["ts"])
        self._next += 1
