"""Pulls signed events from a registered gateway's /ledger/export -- the console's only way to
reach a BYOC-deployed gateway, since it has no filesystem access to the customer's host.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class ExportPage:
    log_id: str | None
    size: int
    events: list[dict]
    next_seq: int | None  # set only when the page came back full -- more may be waiting


class GatewayUnreachable(Exception):
    pass


class GatewayAuthError(Exception):
    pass


async def _get(client: httpx.AsyncClient, base_url: str, path: str, admin_key: str, params: dict | None = None) -> dict:
    try:
        response = await client.get(f"{base_url.rstrip('/')}{path}", params=params,
                                    headers={"authorization": f"Bearer {admin_key}"})
    except httpx.HTTPError as error:
        raise GatewayUnreachable(str(error)) from None
    if response.status_code in (401, 403):
        raise GatewayAuthError(f"the gateway rejected this admin key (status {response.status_code})")
    if response.status_code != 200:
        raise GatewayUnreachable(f"unexpected status {response.status_code}")
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise GatewayUnreachable("the gateway answered with something other than a JSON object")
    return body


async def fetch_events(client: httpx.AsyncClient, base_url: str, admin_key: str, *, after_seq: int = -1,
                       limit: int = 500) -> ExportPage:
    body = await _get(client, base_url, "/ledger/export", admin_key, {"after_seq": after_seq, "limit": limit})
    events, next_seq = body.get("events"), body.get("next_seq")
    if not isinstance(events, list) or not (next_seq is None or isinstance(next_seq, int)):
        raise GatewayUnreachable("the gateway answered with a malformed export page")
    return ExportPage(body.get("log_id"), body.get("size", 0), events, next_seq)


async def fetch_trust(client: httpx.AsyncClient, base_url: str, admin_key: str) -> dict:
    """The gateway's public signing keys (``/ledger/trust``), to pin once and verify every exported event against."""
    return await _get(client, base_url, "/ledger/trust", admin_key)
