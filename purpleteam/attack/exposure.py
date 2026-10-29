"""Exposure first: every attack meets the unpatched agent, side by side, before any defense exists.

Attacking one at a time with the live patch in between shows the defense react, but hides how exposed the agent
really was: once the first breach is patched, every later attack faces the patched agent, so six attacks that all
work read as one breach. Here each attack gets its own fresh, unpatched target, so the count is the agent's real
exposure; the defender then patches once and every breaching payload is re-attacked against the patched agent.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from pyrit.setup import IN_MEMORY, initialize_pyrit_async

from purpleteam.adapter import Target
from purpleteam.attack.corpus import AttackTemplate, CorpusResult, run_corpus
from purpleteam.concurrency import limit
from purpleteam.oracle import Oracle


async def run_unpatched(make_target: Callable[[], Target], oracle: Oracle, templates: list[AttackTemplate], *,
                        concurrency: int | None = None, **options) -> list[CorpusResult]:
    """Each template on its own fresh target, ``concurrency`` at a time (default: the shared PURPLETEAM_CONCURRENCY
    cap, ``purpleteam.concurrency``); results come back in template order.
    ``options`` are ``run_corpus``'s own (canary, timeout, disguise_with, place_with, on_start, on_result)."""
    await initialize_pyrit_async(IN_MEMORY, silent=True)  # once, before any attempt: they all share its memory
    gate = asyncio.Semaphore(max(1, concurrency or limit()))

    async def attack(template: AttackTemplate) -> list[CorpusResult]:
        async with gate:
            return await run_corpus(make_target(), oracle, [template], initialize=False, **options)

    batches = await asyncio.gather(*(attack(template) for template in templates))
    return [result for batch in batches for result in batch]
