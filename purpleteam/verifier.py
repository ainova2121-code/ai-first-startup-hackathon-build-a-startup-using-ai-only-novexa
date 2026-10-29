"""The verifier: prove a patch is safe to ship.

A patch is only accepted if, with it applied, (1) every attack that breached is now held and
(2) every legitimate scenario still succeeds. The verdict is decided here, deterministically —
not by a model. A patch that blocks the attack but breaks real work fails, so the caller rolls
it back rather than shipping it. Nothing here is domain-specific: legitimate behaviour is
expressed as caller-supplied checks over the target's observation.

An unexpected exception while re-testing (the patch itself throwing, a target crashing against
the patched guard, a malformed check) is never read as proof of anything: it is not "the attack
is blocked" and not "legitimate work still succeeds". It is recorded as its own ``errored``
outcome, which always fails ``safe_to_ship``, and only the exception's type is kept — never its
message, which could carry data from the target.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from purpleteam.adapter import Observation, Target
from purpleteam.attack.outcome import upper_bound
from purpleteam.concurrency import parallel_map
from purpleteam.oracle import Oracle, persuasion

LegitCheck = tuple[str, Callable[[Observation], bool]]


@dataclass(frozen=True)
class Replay:
    """One breaching payload, re-sent ``trials`` times against the patched target."""

    id: str
    held: int
    trials: int
    upper_bound: float  # Wilson 95% bound on the residual breach rate (see attack.outcome)
    reply: str
    seconds: float
    proof: str = ""  # the oracle's proof for the first trial that still breached: which tool, which agent
    persuaded: int = 0  # held trials in which the agent still tried the call and the patch stopped it
    persuasion: str = ""  # what it tried and what stopped it, from the first such trial

    @property
    def blocked(self) -> bool:
        return self.held == self.trials


OnAttackStart = Callable[[str, str], None]  # (result_id, payload)
OnAttackResult = Callable[[Replay], None]


@dataclass
class VerifyReport:
    attack_blocked: bool
    legit_passed: bool
    failures: list[str] = field(default_factory=list)
    errored: bool = False
    errors: list[str] = field(default_factory=list)  # unexpected failures while verifying; never evidence of safety
    residual: float = 0.0  # the worst replay's Wilson bound on how often the attack could still succeed

    @property
    def safe_to_ship(self) -> bool:
        return self.attack_blocked and self.legit_passed and not self.errored


def verify(
    target: Target,
    oracle: Oracle,
    *,
    attacks: list[str],
    legit: list[LegitCheck],
    trials: int = 1,
    max_residual: float | None = None,
    on_attack_start: OnAttackStart | None = None,
    on_attack_result: OnAttackResult | None = None,
    factory: Callable[[], Target] | None = None,
    legit_factory: Callable[[], Target] | None = None,
) -> VerifyReport:
    """Each breaching payload is re-sent ``trials`` times; one held trial out of one still allows a
    ~79% breach rate, so a patch is only as proven as the bound its replays leave. With
    ``max_residual``, a replay whose bound stays above it fails the gate even if every trial held.
    ``on_attack_start``/``on_attack_result`` let a live caller show the replay itself -- the exact
    payload, against the patched target -- not only the aggregate verdict. Neither fires for
    ``legit``: those prove the patch didn't break real work, not that an attack is held.

    With ``factory`` (a fresh, identically-patched target per call), every trial and legit check runs
    in parallel, each on its own copy -- none can see another's state. Without one they run in turn
    on ``target``, which cannot safely be driven from two threads at once. ``legit_factory`` (default:
    ``factory``) builds the copies the legit checks run on, so a caller can tell the two kinds apart."""
    failures: list[str] = []
    errors: list[str] = []
    make = factory or (lambda: target)
    run = parallel_map if factory is not None else (lambda fn, items: [fn(item) for item in items])

    for i, payload in enumerate(attacks):
        if on_attack_start:
            on_attack_start(f"reverify:{i + 1}", payload)
    outcomes = run(lambda payload: _send(make, payload), [p for p in attacks for _ in range(trials)])

    attack_blocked, residual = True, 0.0
    for i, payload in enumerate(attacks):
        held, breached, reply, proof, seconds, persuaded, persuaded_how = 0, 0, "", "", 0.0, 0, ""
        for observation, error, elapsed in outcomes[i * trials:(i + 1) * trials]:
            seconds = max(seconds, elapsed)
            if observation is None:  # an error proves nothing was blocked
                errors.append(f"error re-testing an attack ({error}): {payload[:60]}")
                reply = reply or f"error: {error}"
                continue
            verdict = oracle.judge(observation)
            if verdict.breached:
                breached += 1
                if not proof:  # show the first breaching trial: that is the one that matters
                    proof, reply = verdict.detail, observation.reply
            else:
                held += 1
                if not proof and not reply:
                    reply = observation.reply
                if fooled := persuasion(oracle, observation):  # held only because the patch caught the attempt
                    persuaded, persuaded_how = persuaded + 1, persuaded_how or fooled.detail
        replay = Replay(f"reverify:{i + 1}", held, trials, upper_bound(breached, held + breached), reply,
                        seconds, proof, persuaded, persuaded_how)
        residual = max(residual, replay.upper_bound)
        if not replay.blocked:
            attack_blocked = False
            if breached:
                failures.append(f"attack still breaches ({breached} of {trials}): {proof}")
        if on_attack_result:
            on_attack_result(replay)
    if attacks and max_residual is not None and attack_blocked and residual > max_residual:
        errors.append(f"replays held, but {trials} trial(s) leave a residual breach rate of up to "
                      f"{residual:.0%} at 95% confidence, above the {max_residual:.0%} release gate")

    legit_passed = True
    make_legit = legit_factory or make
    checked = run(lambda request: _send(make_legit, request), [request for request, _ in legit])
    for (request, still_works), (observation, error, _) in zip(legit, checked):
        try:
            if observation is None:
                raise RuntimeError(error)
            if not still_works(observation):
                legit_passed = False
                failures.append(f"legitimate work broken: {request[:60]}")
        except Exception as failure:
            legit_passed = False  # an error proves nothing still works
            name = error or type(failure).__name__
            errors.append(f"error re-testing legitimate work ({name}): {request[:60]}")

    if attacks and not legit:
        # Blocking a real attack and never checking whether that also broke real functionality is
        # not "verified safe" -- it is untested. legit_passed stays True (nothing failed), but
        # this must still cost safe_to_ship, the same way any other unresolved gap does.
        errors.append("legitimate work was never checked (no legit= scenarios were supplied) -- "
                      "blocking the attack could have broken real functionality undetected")

    return VerifyReport(attack_blocked, legit_passed, failures, errored=bool(errors), errors=errors,
                        residual=residual)


def _send(make: Callable[[], Target], request: str) -> tuple[Observation | None, str, float]:
    """(observation, "", seconds), or (None, the exception's type name, seconds) -- only the type is
    kept, never the message, which could carry data from the target."""
    started = time.monotonic()
    try:
        target = make()
        target.reset()
        return target.send(request), "", time.monotonic() - started
    except Exception as error:
        return None, type(error).__name__, time.monotonic() - started
