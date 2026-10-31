"""Polls every registered gateway's /ledger/export on an interval and publishes a fleet-wide
status update for the console's SSE stream. Never persists raw events -- the signed ledger on
each gateway stays the one source of truth; target_status is a derived, best-effort cache only.
Every event is verified against the gateway's pinned public keys before it counts
(``purpleteam.audit.stream``); a target whose evidence fails is marked untrusted and its cursor stops there.

The recent-events buffer used to compute that cache lives in this process's memory and resets on
restart (it rebuilds as new events arrive) -- a deliberate, documented trade-off against re-
fetching a target's entire history every cycle. A per-target detail view that needs the
authoritative answer should fetch and recompute fresh, not trust this cache.
"""

from __future__ import annotations

import asyncio
import json
import sys

import httpx

from purpleteam.audit.stream import StreamVerifier
from purpleteam.audit.trend import runs as trend_runs
from purpleteam.console.events import Broadcaster
from purpleteam.console.gateway_client import (
    ExportPage, GatewayAuthError, GatewayUnreachable, fetch_events, fetch_trust)
from purpleteam.console.registry import FIRST_USE, FleetRegistry

PAGE_SIZE = 500
MAX_PAGES_PER_CYCLE = 10  # bounds how much one target can make a cycle do, even if it floods its ledger
RECENT_WINDOW = 1000      # events kept in memory per target, for finding the latest sealed run
UNTRUSTED = "untrusted"   # its evidence did not verify: nothing past the failure is shown or counted


async def pinned_trust(registry: FleetRegistry, client: httpx.AsyncClient, target_id: str, base_url: str,
                       admin_key: str) -> dict:
    """The target's pinned public keys; the first time, fetched from the gateway and pinned (trust on first use)."""
    trust = registry.trust_for(target_id)
    if trust is None:
        trust = registry.pin_trust(target_id, await fetch_trust(client, base_url, admin_key), FIRST_USE)
    return trust


class FleetPoller:
    def __init__(self, registry: FleetRegistry, broadcaster: Broadcaster, client: httpx.AsyncClient,
                interval: float = 15.0) -> None:
        self._registry, self._broadcaster, self._client, self._interval = registry, broadcaster, client, interval
        self._recent: dict[str, list[dict]] = {}

    async def run_forever(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception as error:  # one failed cycle must never stop the fleet view for good
                print(f"purpleteam console: a poll cycle failed ({type(error).__name__}); retrying",
                      file=sys.stderr)
            await asyncio.sleep(self._interval)

    async def run_once(self) -> None:
        for target in self._registry.list_targets():
            await self._poll_one(target)

    async def _poll_one(self, target) -> None:
        credentials = self._registry.credentials_for(target.id)
        if credentials is None:
            return
        base_url, admin_key = credentials
        try:
            trust = await pinned_trust(self._registry, self._client, target.id, base_url, admin_key)
            verifier = StreamVerifier(trust, self._registry.verifier_state(target.id))
            fetched, failure = await self._drain(base_url, admin_key, verifier)
        except (GatewayAuthError, GatewayUnreachable) as error:
            status = "error" if isinstance(error, GatewayAuthError) else "unreachable"
            self._registry.record_poll_result(target.id, log_id=target.log_id, last_seq=target.last_seq,
                                              status=status, last_error=str(error))
        except ValueError as error:  # keys that cannot be pinned, or a corrupted saved state
            self._registry.record_poll_result(target.id, log_id=target.log_id, last_seq=target.last_seq,
                                              status=UNTRUSTED, last_error=f"evidence cannot be verified: {error}")
        else:
            self._registry.save_verifier(target.id, verifier.state)
            self._registry.record_poll_result(target.id, log_id=verifier.log_id, last_seq=verifier.verified - 1,
                                              status=UNTRUSTED if failure else "ok", last_error=failure)
            if fetched:
                recent = (self._recent.get(target.id, []) + fetched)[-RECENT_WINDOW:]
                self._recent[target.id] = recent
                self._update_status(target.id, recent)
        self._broadcaster.publish({"target_id": target.id})

    async def _drain(self, base_url: str, admin_key: str, verifier: StreamVerifier) -> tuple[list[dict], str | None]:
        """Pages forward from the last verified event until caught up (or MAX_PAGES_PER_CYCLE is hit), returning
        (the events that verified this cycle, why verification stopped -- None when everything verified)."""
        fetched: list[dict] = []
        for _ in range(MAX_PAGES_PER_CYCLE):
            page: ExportPage = await fetch_events(self._client, base_url, admin_key,
                                                   after_seq=verifier.verified - 1, limit=PAGE_SIZE)
            if verifier.log_id and page.log_id != verifier.log_id:
                return fetched, "the gateway now serves a different log than the one already verified"
            verified_before = verifier.verified
            result = verifier.feed(page.events)
            fetched.extend(page.events[:verifier.verified - verified_before])
            if not result.ok:
                return fetched, f"evidence failed verification at event {result.broken_at}: {result.reason}"
            if page.next_seq is None:
                break
        return fetched, None

    def _update_status(self, target_id: str, events: list[dict]) -> None:
        completed = trend_runs(events)
        if not completed:
            return
        latest = completed[-1]
        self._registry.set_status(target_id, size=latest.size, safe_to_ship=latest.safe_to_ship,
                                  sealed_at=latest.sealed_at, breach_kinds_json=json.dumps(sorted(latest.breach_kinds)))
