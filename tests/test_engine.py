"""run_attempt: a fresh attempt never inherits a stale observation, a timeout is honest, and a poisoned target stays poisoned."""

import asyncio
import threading
import time

from pyrit.setup import IN_MEMORY, initialize_pyrit_async

from purpleteam.adapter import Observation, ToolCall
from purpleteam.attack.engine import run_attempt
from purpleteam.attack.outcome import BREACHED, HELD, INCONCLUSIVE
from purpleteam.attack.pyrit_target import PlatformPromptTarget
from purpleteam.oracle import CanaryOracle

asyncio.run(initialize_pyrit_async(IN_MEMORY, silent=True))  # PlatformPromptTarget needs PyRIT's memory set up

CANARY = "US00ATTACKER0666"
ORACLE = CanaryOracle({CANARY}, {"schedule_payment"})


class _Piece:
    """The one method run_attempt's execute() needs from a PyRIT conversation piece."""

    def __init__(self, text: str) -> None:
        self._text = text

    def get_value(self) -> str:
        return self._text


class _FakeTarget:
    def __init__(self, reply: Observation | Exception, delay: float = 0.0) -> None:
        self._reply, self._delay = reply, delay
        self.sent: list[str] = []

    def reset(self) -> None:
        pass

    def send(self, request: str) -> Observation:
        self.sent.append(request)
        if self._delay:
            time.sleep(self._delay)
        if isinstance(self._reply, Exception):
            raise self._reply
        return self._reply


def _execute(wrapper: PlatformPromptTarget, text: str = "attack"):
    async def go():
        await wrapper._send_prompt_to_target_async(normalized_conversation=[_Piece(text)])
    return go


def test_a_normal_attempt_is_classified_from_its_own_observation():
    held = Observation("ok", [])
    wrapper = PlatformPromptTarget(target=_FakeTarget(held))
    trial = asyncio.run(run_attempt(_execute(wrapper), wrapper, ORACLE, timeout=5))
    assert trial.outcome == HELD and not wrapper.poisoned


def test_a_breach_is_classified_as_breached():
    breach = Observation("ok", [ToolCall("payment", "schedule_payment", {"bank_account": CANARY})])
    wrapper = PlatformPromptTarget(target=_FakeTarget(breach))
    trial = asyncio.run(run_attempt(_execute(wrapper), wrapper, ORACLE, timeout=5))
    assert trial.outcome == BREACHED and trial.verdict.breached


def test_a_stale_observation_is_never_inherited_by_the_next_attempt():
    wrapper = PlatformPromptTarget(target=_FakeTarget(RuntimeError("boom")))
    wrapper.last_observation = Observation("ok", [ToolCall("payment", "schedule_payment", {"bank_account": CANARY})])
    trial = asyncio.run(run_attempt(_execute(wrapper), wrapper, ORACLE, timeout=5))
    # not BREACHED from the leftover observation; only the exception's type is reported, never its raw message
    assert trial.outcome == INCONCLUSIVE and "RuntimeError" in trial.detail and "boom" not in trial.detail
    assert wrapper.last_observation is None


def test_a_target_failure_is_inconclusive_not_held():
    wrapper = PlatformPromptTarget(target=_FakeTarget(ConnectionError("refused")))
    trial = asyncio.run(run_attempt(_execute(wrapper), wrapper, ORACLE, timeout=5))
    assert trial.outcome == INCONCLUSIVE and "ConnectionError" in trial.detail and "refused" not in trial.detail
    assert not wrapper.poisoned  # the thread finished (with an error), it is not still running


def test_a_slow_target_times_out_honestly_and_poisons_the_wrapper():
    wrapper = PlatformPromptTarget(target=_FakeTarget(Observation("late", []), delay=2.0))
    started = time.monotonic()
    trial = asyncio.run(run_attempt(_execute(wrapper), wrapper, ORACLE, timeout=0.2))
    assert time.monotonic() - started < 1.0  # the wait_for actually cut it off, not the slow target's own delay
    assert trial.outcome == INCONCLUSIVE and "time" in trial.reason
    assert wrapper.poisoned  # the thread is still sleeping; must not be reused


def test_a_poisoned_wrapper_stays_poisoned_across_begin_attempt():
    wrapper = PlatformPromptTarget(target=_FakeTarget(Observation("late", []), delay=1.0))
    asyncio.run(run_attempt(_execute(wrapper), wrapper, ORACLE, timeout=0.1))
    assert wrapper.poisoned
    wrapper.begin_attempt()  # starting a new attempt must not paper over an unsafe target
    assert wrapper.poisoned
    time.sleep(1.2)  # let the orphaned thread actually finish so it doesn't outlive the test process


def test_concurrent_in_flight_calls_are_visible_as_poisoned_while_running():
    gate = threading.Event()

    class Blocking(_FakeTarget):
        def send(self, request: str) -> Observation:
            gate.wait(timeout=5)
            return Observation("ok", [])

    wrapper = PlatformPromptTarget(target=Blocking(Observation("ok", [])))

    async def probe():
        task = asyncio.create_task(_execute(wrapper)())
        await asyncio.sleep(0.05)
        assert wrapper.poisoned  # in flight, before the fake target has returned
        gate.set()
        await task
        assert not wrapper.poisoned  # completed normally, no longer in flight

    asyncio.run(probe())


def test_begin_attempt_clears_only_the_observation_not_the_attempt_history():
    wrapper = PlatformPromptTarget(target=_FakeTarget(Observation("ok", [])))
    asyncio.run(run_attempt(_execute(wrapper, "first"), wrapper, ORACLE, timeout=5))
    wrapper.begin_attempt()
    assert wrapper.last_observation is None and wrapper.attempts == ["first"]


def test_observations_accumulate_across_the_whole_session_not_just_the_last_one():
    # a search that branches needs every observation, not only the most recent call (see attack.adaptive)
    wrapper = PlatformPromptTarget(target=_FakeTarget(Observation("ok", [])))
    asyncio.run(run_attempt(_execute(wrapper, "first"), wrapper, ORACLE, timeout=5))
    asyncio.run(run_attempt(_execute(wrapper, "second"), wrapper, ORACLE, timeout=5))
    assert len(wrapper.observations) == 2 and wrapper.observations[-1] is wrapper.last_observation


def test_a_daemon_thread_that_outlives_its_loop_does_not_raise_unhandled():
    """The loop that a very late worker thread tries to notify may already be closed (asyncio.run closes it as
    soon as the coroutine that abandoned the thread returns); that must be swallowed, not crash the thread."""
    captured: list = []
    original = threading.excepthook
    threading.excepthook = captured.append
    try:
        wrapper = PlatformPromptTarget(target=_FakeTarget(Observation("late", []), delay=0.3))
        asyncio.run(run_attempt(_execute(wrapper), wrapper, ORACLE, timeout=0.05))
        time.sleep(0.5)  # outlive asyncio.run()'s loop closing, so the orphaned thread's late notification fires here
    finally:
        threading.excepthook = original
    assert captured == []


def test_reset_each_turn_true_resets_the_target_and_false_does_not():
    class Counting(_FakeTarget):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.resets = 0

        def reset(self):
            self.resets += 1

    stateless = PlatformPromptTarget(target=Counting(Observation("ok", [])))
    asyncio.run(run_attempt(_execute(stateless), stateless, ORACLE, timeout=5))
    assert stateless._target.resets == 1

    stateful = PlatformPromptTarget(target=Counting(Observation("ok", [])), reset_each_turn=False)
    asyncio.run(run_attempt(_execute(stateful), stateful, ORACLE, timeout=5))
    assert stateful._target.resets == 0
