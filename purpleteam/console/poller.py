"""Polls every registered gateway's /ledger/export on an interval and publishes a fleet-wide
status update for the console's SSE stream. Never persists raw events -- the signed ledger on
each gateway stays the one source of truth; target_status is a derived, best-effort cache only.

The recent-events buffer used to compute that cache lives in this process's memory and resets on
restart (it rebuilds as new events arrive) -- a deliberate, documented trade-off against re-
fetching a target's entire history every cycle. A per-target detail view that needs the
authoritative answer should fetch and recompute fresh, not trust this cache.
"""

from __future__ import annotations

import asyncio
import json

import httpx

from purpleteam.audit.trend import runs as trend_runs
from purpleteam.console.events import Broadcaster
from purpleteam.console.gateway_client import ExportPage, GatewayAuthError, GatewayUnreachable, fetch_events
from purpleteam.console.registry import FleetRegistry

PAGE_SIZE = 500
MAX_PAGES_PER_CYCLE = 10  # bounds how much one target can make a cycle do, even if it floods its ledger
RECENT_WINDOW = 1000      # events kept in memory per target, for finding the latest sealed run


class FleetPoller:
    def __init__(self, registry: FleetRegistry, broadcaster: Broadcaster, client: httpx.AsyncClient,
                interval: float = 15.0) -> None:
        self._registry, self._broadcaster, self._client, self._interval = registry, broadcaster, client, interval
        self._recent: dict[str, list[dict]] = {}

    async def run_forever(self) -> None:
        while True:
            await self.run_once()
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
            last_seq, log_id, fetched = await self._drain(base_url, admin_key, target.last_seq)
        except (GatewayAuthError, GatewayUnreachable) as error:
            status = "error" if isinstance(error, GatewayAuthError) else "unreachable"
            self._registry.record_poll_result(target.id, log_id=target.log_id, last_seq=target.last_seq,
                                              status=status, last_error=str(error))
        else:
            self._registry.record_poll_result(target.id, log_id=log_id, last_seq=last_seq, status="ok",
                                              last_error=None)
            if fetched:
                recent = (self._recent.get(target.id, []) + fetched)[-RECENT_WINDOW:]
                self._recent[target.id] = recent
                self._update_status(target.id, recent)
        self._broadcaster.publish({"target_id": target.id})

    async def _drain(self, base_url: str, admin_key: str, after_seq: int) -> tuple[int, str | None, list[dict]]:
        """Pages forward until caught up (or MAX_PAGES_PER_CYCLE is hit), returning (new cursor,
        log_id, every event fetched this cycle)."""
        fetched: list[dict] = []
        log_id = None
        for _ in range(MAX_PAGES_PER_CYCLE):
            page: ExportPage = await fetch_events(self._client, base_url, admin_key, after_seq=after_seq,
                                                   limit=PAGE_SIZE)
            log_id = page.log_id
            if page.events:
                fetched.extend(page.events)
                after_seq = page.events[-1]["seq"]  # the real cursor is the last event actually seen,
            if page.next_seq is None:               # regardless of why the page came back short
                break
        return after_seq, log_id, fetched

    def _update_status(self, target_id: str, events: list[dict]) -> None:
        completed = trend_runs(events)
        if not completed:
            return
        latest = completed[-1]
        self._registry.set_status(target_id, size=latest.size, safe_to_ship=latest.safe_to_ship,
                                  sealed_at=latest.sealed_at, breach_kinds_json=json.dumps(sorted(latest.breach_kinds)))
