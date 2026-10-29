"""In-process pub/sub fanout for the console's SSE stream.

Deliberately in-process, no Redis: a single console process at this scale. A multi-replica
console would need a shared broadcaster instead -- not solved here, the same "flagged, not
solved" stance gateway_keys.py's FileKeyStore already takes on its own single-replica limit.
"""

from __future__ import annotations

import asyncio


class Broadcaster:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def publish(self, message: dict) -> None:
        for queue in self._subscribers:
            queue.put_nowait(message)
