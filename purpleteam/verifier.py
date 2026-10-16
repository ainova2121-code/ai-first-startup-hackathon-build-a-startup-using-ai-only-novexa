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

from dataclasses import dataclass, field
from typing import Callable

from purpleteam.adapter import Observation, Target
from purpleteam.oracle import Oracle

LegitCheck = tuple[str, Callable[[Observation], bool]]


@dataclass
class VerifyReport:
    attack_blocked: bool
    legit_passed: bool
    failures: list[str] = field(default_factory=list)
    errored: bool = False
    errors: list[str] = field(default_factory=list)  # unexpected failures while verifying; never evidence of safety

    @property
    def safe_to_ship(self) -> bool:
        return self.attack_blocked and self.legit_passed and not self.errored


def verify(
    target: Target,
    oracle: Oracle,
    *,
    attacks: list[str],
    legit: list[LegitCheck],
) -> VerifyReport:
    failures: list[str] = []
    errors: list[str] = []

    attack_blocked = True
    for payload in attacks:
        try:
            target.reset()
            if oracle.judge(target.send(payload)).breached:
                attack_blocked = False
                failures.append(f"attack still breaches: {payload[:60]}")
        except Exception as error:
            attack_blocked = False  # an error proves nothing was blocked
            errors.append(f"error re-testing an attack ({type(error).__name__}): {payload[:60]}")

    legit_passed = True
    for request, still_works in legit:
        try:
            target.reset()
            if not still_works(target.send(request)):
                legit_passed = False
                failures.append(f"legitimate work broken: {request[:60]}")
        except Exception as error:
            legit_passed = False  # an error proves nothing still works
            errors.append(f"error re-testing legitimate work ({type(error).__name__}): {request[:60]}")

    return VerifyReport(attack_blocked, legit_passed, failures, errored=bool(errors), errors=errors)
