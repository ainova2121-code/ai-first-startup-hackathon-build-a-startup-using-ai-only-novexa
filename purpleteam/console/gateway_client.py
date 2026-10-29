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


async def fetch_events(client: httpx.AsyncClient, base_url: str, admin_key: str, *, after_seq: int = -1,
                       limit: int = 500) -> ExportPage:
    try:
        response = await client.get(
            f"{base_url.rstrip('/')}/ledger/export", params={"after_seq": after_seq, "limit": limit},
            headers={"authorization": f"Bearer {admin_key}"})
    except httpx.HTTPError as error:
        raise GatewayUnreachable(str(error)) from None
    if response.status_code in (401, 403):
        raise GatewayAuthError(f"the gateway rejected this admin key (status {response.status_code})")
    if response.status_code != 200:
        raise GatewayUnreachable(f"unexpected status {response.status_code}")
    body = response.json()
    return ExportPage(body["log_id"], body["size"], body["events"], body["next_seq"])
