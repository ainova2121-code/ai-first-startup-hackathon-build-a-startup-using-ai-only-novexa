"""What the re-attack needs to say which layer held a breach, and to honour pause/stop while it runs.

Reverification sends each breaching question once against the patched agent: its verified source fixes loaded and
its runtime guards attached. The reply itself says which layer held: a runtime guard that had to stop the attacker's
call (``RUNTIME_GUARD``), or, once the code is patched, an agent that no longer tried the call at all
(``CODE_PATCH``).
"""

from __future__ import annotations

from purpleteam.run_control import RunControl, RunStopped

CODE_PATCH, RUNTIME_GUARD = "code patch", "runtime guard"


class ControlledTarget:
    """Cooperative gate around verifier probes so pause/stop also applies during re-attacks."""

    def __init__(self, target, control: RunControl) -> None:
        self._target, self._control = target, control

    def reset(self) -> None:
        if not self._control.checkpoint():
            raise RunStopped("run stopped before verifier reset")
        self._target.reset()

    def send(self, text: str):
        if not self._control.checkpoint():
            raise RunStopped("run stopped before verifier request")
        return self._target.send(text)
