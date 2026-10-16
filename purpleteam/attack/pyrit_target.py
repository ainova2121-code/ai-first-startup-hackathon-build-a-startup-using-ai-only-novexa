"""Wraps any platform Target as a PyRIT PromptTarget.

PyRIT drives the conversation: an adversarial model writes each attempt and sends it
here. We run it through the wrapped target and keep the resulting Observation. Success is
never read from the reply — the OracleScorer reads ``last_observation`` instead, so an
agent that says "I can't do that" while it quietly wires the money out is still scored as
breached.

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
from typing import Any

from pyrit.models import Message
from pyrit.prompt_target import PromptTarget, TargetCapabilities, TargetConfiguration

from purpleteam.adapter import Observation, Target

_CAPS = TargetConfiguration(
    capabilities=TargetCapabilities(
        supports_multi_turn=True,
        supports_editable_history=True,
        supports_system_prompt=True,
        supports_multi_message_pieces=True,
    )
)


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
    def __init__(self, *, target: Target, custom_configuration=None, reset_each_turn: bool = True) -> None:
        super().__init__(custom_configuration=custom_configuration or _CAPS)
        self._target = target
        self._reset_each_turn = reset_each_turn  # an agent target resets per request; a stateful chat target does not
        self.last_observation: Observation | None = None
        self.attempts: list[str] = []
        self._in_flight = False

    @property
    def poisoned(self) -> bool:
        """A send was abandoned by a timeout and may still be running against the target."""
        return self._in_flight

    def begin_attempt(self) -> None:
        """Forget the previous attempt's observation: it is not evidence about the next one."""
        self.last_observation = None

    async def _send_prompt_to_target_async(self, *, normalized_conversation):
        text = normalized_conversation[-1].get_value()
        self.attempts.append(text)
        self._in_flight = True
        try:
            observation = await call_in_daemon_thread(self._send, text)
        except asyncio.CancelledError:
            raise  # the thread keeps running; `poisoned` stays True until a fresh begin_attempt
        except Exception:
            self._in_flight = False
            raise
        self._in_flight = False
        self.last_observation = observation
        reply = observation.reply or "(no reply)"
        return [Message.from_prompt(prompt=reply, role="assistant")]

    def _send(self, text: str) -> Observation:
        if self._reset_each_turn:
            self._target.reset()
        return self._target.send(text)

    def _validate_request(self, *, normalized_conversation) -> None:
        pass

    async def cleanup_target_async(self) -> None:
        pass
