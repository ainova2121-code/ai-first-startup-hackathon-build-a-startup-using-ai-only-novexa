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
import re
from typing import Any, Awaitable, Callable

from purpleteam.adapter import TargetUnavailable
from purpleteam.attack.outcome import INCONCLUSIVE, Trial, classify
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


# A temporary failure (a rate limit, a server hiccup) is asked again, after a pause, before it can count as untested.
# A rejected key, an unpaid plan or a missing model will not change by waiting, so those are never retried.
RETRY_WAITS = (10.0, 30.0)
_PERMANENT = re.compile(r"answered 40[1-4]\b")


def transient(trial: Trial) -> bool:
    return trial.outcome == INCONCLUSIVE and trial.reason.startswith("target error") and not _PERMANENT.search(trial.reason)


async def run_patiently(execute: Callable[[], Awaitable[Any]], target: PlatformPromptTarget, oracle: Oracle,
                        timeout: float | None, *, control: Any = None, waits: tuple[float, ...] | None = None) -> Trial:
    """``run_attempt``, asked again after a pause while the target only failed for a temporary reason."""
    trial = await run_attempt(execute, target, oracle, timeout)
    for wait in RETRY_WAITS if waits is None else waits:
        if not transient(trial) or target.poisoned or (control is not None and control.stop_requested):
            break
        await asyncio.sleep(wait)
        trial = await run_attempt(execute, target, oracle, timeout)
    return trial
