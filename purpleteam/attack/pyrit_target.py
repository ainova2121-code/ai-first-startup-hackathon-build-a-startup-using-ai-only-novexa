"""Wraps any platform Target as a PyRIT PromptTarget.

PyRIT drives the conversation: an adversarial model writes each attempt and sends it
here. We run it through the wrapped target and keep the resulting Observation. Success is
never read from the reply — the OracleScorer reads ``last_observation`` instead, so an
agent that says "I can't do that" while it quietly wires the money out is still scored as
breached. ``observations`` additionally keeps every send this session, for a search that
branches (PAIR, TAP): the breach, if any, is not necessarily on the last call made.
Adaptive callers may set a hard unique-prompt budget; case, whitespace, Unicode-normalization,
and punctuation-only variants are rejected before they reach the wrapped target.

The target's ``send`` is a blocking call (HTTP, a database), so it runs in a worker thread;
otherwise a timeout, which can only interrupt code that yields to the event loop, would
never fire. ``begin_attempt`` clears the last observation before a new attempt starts, so a
timeout can never be judged on an earlier attempt's breach. If a send is abandoned by a
timeout the thread may still be running against the target; ``poisoned`` reports that so the
caller knows not to reuse this wrapper or target for a further attempt.

The worker thread is a daemon thread, started directly rather than through ``asyncio.to_thread``
(which runs on the event loop's default executor). ``asyncio.run`` waits for that default
executor to finish all its work before the process can exit, so one slow or hanging send would
otherwise stall shutdown of the whole corpus run even though ``run_attempt`` itself returned on
time. A daemon thread carries no such obligation: the process can exit while it is still running,
and whatever it eventually produces is simply discarded, since the future it reports to is by
then already cancelled.
"""

import asyncio
import threading
import unicodedata
from typing import Any

from pyrit.models import Message
from pyrit.prompt_target import PromptTarget, TargetCapabilities, TargetConfiguration

from purpleteam.adapter import Observation, Target
from purpleteam.run_control import RunControl, RunStopped

_CAPS = TargetConfiguration(
    capabilities=TargetCapabilities(
        supports_multi_turn=True,
        supports_editable_history=True,
        supports_system_prompt=True,
        supports_multi_message_pieces=True,
    )
)


class DuplicateTargetPrompt(RuntimeError):
    """A normalized duplicate was skipped instead of being sent to the target."""


class UniquePromptLimitReached(RuntimeError):
    """The adaptive search tried to exceed its configured unique target-prompt budget."""


def _prompt_key(text: str) -> str:
    """Canonicalize formatting-only differences while preserving Unicode letters and marks."""
    normalized = unicodedata.normalize("NFKC", text).casefold()
    without_punctuation = "".join(
        " " if unicodedata.category(character).startswith("P") else character
        for character in normalized
    )
    return " ".join(without_punctuation.split())


def _resolve(future: asyncio.Future, result: Any, error: BaseException | None) -> None:
    if not future.cancelled():  # the awaiter gave up already; nothing left to deliver this to
        future.set_exception(error) if error is not None else future.set_result(result)


def call_in_daemon_thread(func, *args):
    """``func(*args)`` run in a daemon thread, as something this coroutine can await and abandon.

    Cancelling the await does not stop the thread — nothing can, short of killing the process — it only stops
    this coroutine from waiting on it further. The thread's eventual result or exception is then silently
    dropped, which is correct here: the caller has already decided not to trust anything this attempt produces.
    By the time a sufficiently late thread finishes, the event loop itself may be closed (``asyncio.run`` closes
    it right after the coroutine that abandoned this thread returns); that is reported to the thread, not raised
    from it, so it is swallowed rather than becoming an unhandled exception in a thread nobody is watching.
    """
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()

    def worker() -> None:
        try:
            result = func(*args)
        except BaseException as error:
            _tell(loop, future, None, error)
        else:
            _tell(loop, future, result, None)

    threading.Thread(target=worker, daemon=True).start()
    return future


def _tell(loop: asyncio.AbstractEventLoop, future: asyncio.Future, result: Any, error: BaseException | None) -> None:
    try:
        loop.call_soon_threadsafe(_resolve, future, result, error)
    except RuntimeError:  # the loop closed before this thread finished; nothing is listening any more
        pass


class PlatformPromptTarget(PromptTarget):
    def __init__(self, *, target: Target, custom_configuration=None, reset_each_turn: bool = True,
                 control: RunControl | None = None, max_unique_prompts: int | None = None) -> None:
        super().__init__(custom_configuration=custom_configuration or _CAPS)
        if max_unique_prompts is not None and max_unique_prompts not in {1, 5, 10}:
            raise ValueError("max_unique_prompts must be one of 1, 5, or 10")
        self._target = target
        self._reset_each_turn = reset_each_turn  # an agent target resets per request; a stateful chat target does not
        self._control = control
        self._max_unique_prompts = max_unique_prompts
        self._unique_prompt_keys: set[str] = set()
        self._prompt_gate = asyncio.Lock()
        # TAP dispatches several branches at once, but they all drive this one target and its single state (an agent
        # app's database): each reset-then-send must run alone, or one branch wipes or reads another's state.
        self._send_lock = threading.Lock()
        self.duplicate_prompts_skipped = 0
        self.prompt_budget_exhausted = False
        self.last_observation: Observation | None = None
        self.observations: list[Observation] = []  # every real send this session, for a search that branches
        self.attempts: list[str] = []  # unique prompts actually submitted to the wrapped target
        self._in_flight = False

    @property
    def unique_prompt_count(self) -> int:
        """Number of distinct normalized prompts reserved for a real target request."""
        return len(self._unique_prompt_keys)

    @property
    def poisoned(self) -> bool:
        """A send was abandoned by a timeout and may still be running against the target."""
        return self._in_flight

    def begin_attempt(self) -> None:
        """Forget the previous attempt's observation: it is not evidence about the next one."""
        self.last_observation = None

    async def _send_prompt_to_target_async(self, *, normalized_conversation):
        text = normalized_conversation[-1].get_value()
        key = _prompt_key(text)
        async with self._prompt_gate:  # TAP can dispatch several branches simultaneously; reserve atomically
            if key in self._unique_prompt_keys:
                self.duplicate_prompts_skipped += 1
                raise DuplicateTargetPrompt("normalized duplicate prompt skipped")
            if (self._max_unique_prompts is not None
                    and len(self._unique_prompt_keys) >= self._max_unique_prompts):
                self.prompt_budget_exhausted = True
                raise UniquePromptLimitReached("unique target-prompt limit reached")
            self._unique_prompt_keys.add(key)
            self.attempts.append(text)
        self._in_flight = True
        try:
            observation = await call_in_daemon_thread(self._send, text)
        except asyncio.CancelledError:
            raise  # the thread keeps running; nothing ever clears `poisoned` — not even begin_attempt — so this
            # instance must not be reused for a further attempt; the caller needs a fresh one
        except Exception:
            self._in_flight = False
            raise
        self._in_flight = False
        self.last_observation = observation
        self.observations.append(observation)
        reply = observation.reply or "(no reply)"
        return [Message.from_prompt(prompt=reply, role="assistant")]

    def _send(self, text: str) -> Observation:
        if self._control is not None and not self._control.checkpoint():
            raise RunStopped("run stopped before the next target request")
        with self._send_lock:
            if self._reset_each_turn:
                self._target.reset()
            return self._target.send(text)

    def _validate_request(self, *, normalized_conversation) -> None:
        pass

    async def cleanup_target_async(self) -> None:
        pass
