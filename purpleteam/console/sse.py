"""Formats the console's live fleet updates as Server-Sent Events, kept separate from app.py so
it is testable as a plain async generator -- no HTTP/ASGI transport involved.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable

from purpleteam.console.events import Broadcaster

KEEPALIVE_SECONDS = 20


async def sse_events(broadcaster: Broadcaster, render_fragment: Callable[[str], str | None]) -> AsyncIterator[str]:
    """``render_fragment(target_id)`` -> the row's HTML, or ``None`` if that target is gone (a
    publish can race a removal); a keep-alive comment every ``KEEPALIVE_SECONDS`` keeps a proxy
    from idling the connection out."""
    queue = broadcaster.subscribe()
    try:
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=KEEPALIVE_SECONDS)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
                continue
            fragment = render_fragment(message["target_id"])
            if fragment is None:
                continue
            yield f"event: fleet-update\ndata: {fragment.replace(chr(10), '')}\n\n"
    finally:
        broadcaster.unsubscribe(queue)
