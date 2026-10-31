"""Run one attack attempt against a target and say what it came to.

Three things go wrong with attacks that this guards against. An attempt is judged only on what *it* made the target
do: the previous attempt's observation is cleared first, so a timeout can never inherit another attack's breach.
The target's calls are blocking (HTTP, a database), so they run in a worker thread; otherwise the timeout, which can
only interrupt code that yields to the event loop, could never fire. And every failure to get an answer is
``inconclusive``, never ``held`` (see ``outcome``). A worker abandoned by a timeout may still be talking to the
target; its late result is discarded rather than allowed to overwrite a newer attempt's.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from purpleteam.adapter import TargetUnavailable
from purpleteam.attack.outcome import Trial, classify
from purpleteam.attack.pyrit_target import PlatformPromptTarget
from purpleteam.oracle import Oracle, persuasion


def _reason(failure: BaseException) -> str:
    """Why an attempt failed: a ``TargetUnavailable``'s own message (the platform's, an HTTP status) wherever PyRIT
    wrapped it, else only the exception's type -- never text that came from the target."""
    seen: BaseException | None = failure
    for _ in range(10):  # a bounded walk: exception chains can loop
        if seen is None:
            break
        if isinstance(seen, TargetUnavailable):
            return str(seen)
        seen = seen.__cause__ or seen.__context__
    return type(failure).__name__


async def run_attempt(execute: Callable[[], Awaitable[Any]], target: PlatformPromptTarget, oracle: Oracle,
                      timeout: float | None) -> Trial:
    """``execute`` starts a PyRIT attack (``attack.execute_async(...)``) whose objective target is ``target``."""
    target.begin_attempt()  # forget the last attempt: its observation is not evidence about this one
    timed_out, error = False, None
    try:
        await (asyncio.wait_for(execute(), timeout) if timeout else execute())
    except asyncio.TimeoutError:
        timed_out = True
    except Exception as failure:  # rate limits, a refused connection, a tooling error: none of them is "held"
        error = _reason(failure)
    observation = target.last_observation
    verdict = oracle.judge(observation) if observation else None
    persuaded = persuasion(oracle, observation) if verdict is not None and not verdict.breached else None
    return classify(observation, verdict, timed_out=timed_out, error=error, persuaded=persuaded)
