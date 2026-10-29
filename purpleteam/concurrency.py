"""One shared cap on how many independent, slow calls (model requests, target replays) run at once.

Most of an assessment's time is spent waiting on a hosted model, so independent work runs in parallel
-- but a provider that rate-limits answers a burst with errors, and a rate-limited trial is recorded as
inconclusive, never as held. ``PURPLETEAM_CONCURRENCY`` (default 4) bounds the burst. Only work that
does not depend on another result is ever run this way; the attack campaign, escalation levels and
source writes keep their order, because the proof depends on it.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def limit() -> int:
    try:
        return max(1, int(os.environ.get("PURPLETEAM_CONCURRENCY", "4")))
    except ValueError:
        return 4


def parallel_map(fn: Callable[[T], R], items: Iterable[T]) -> list[R]:
    """``[fn(item) for item in items]``, run on up to ``limit()`` threads, results in input order.
    ``fn`` must handle its own failures: one raising aborts the whole map, by design."""
    items = list(items)
    if len(items) <= 1 or limit() == 1:
        return [fn(item) for item in items]
    with ThreadPoolExecutor(max_workers=min(limit(), len(items))) as pool:
        return list(pool.map(fn, items))
