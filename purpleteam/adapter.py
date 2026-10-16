"""The seam between the platform and any target under test.

A target is anything that takes a text request, runs an agent system, and lets us
observe what tools it called. The platform never imports a target's code; a target
adapter implements this Protocol. Nothing here is domain-specific.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


# How we know a tool call happened, weakest first. A verdict carries the level of the call that proved it.
PROPOSED = "proposed"   # the model's answer contained the call; we never saw it run
REPORTED = "reported"   # the product sent back a result for it, so it says the call ran
OBSERVED = "observed"   # we saw it run ourselves (an in-process hook or a tool proxy)


@dataclass
class ToolCall:
    agent: str
    tool: str
    args: dict[str, Any]
    result: str = ""
    evidence: str = OBSERVED
    attributed: bool = True  # False when the call is not shown to come from the request that was sent
    at: float = 0.0  # time.monotonic() when the call was first seen; 0 when the recorder gave no time


@dataclass
class Observation:
    """What one request did: the final reply and every tool call it triggered."""

    reply: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    status: int | None = None  # the HTTP status, where the target speaks HTTP

    def values(self) -> list[str]:
        return [str(v) for call in self.tool_calls for v in call.args.values()]

    def outputs(self) -> list[str]:
        """Everything the target emitted: the reply and every tool result."""
        return [self.reply, *[call.result for call in self.tool_calls if call.result]]


@runtime_checkable
class Target(Protocol):
    name: str

    def send(self, request: str) -> Observation:
        """Run one request through the target and report what it did."""
        ...

    def reset(self) -> None:
        """Restore the target to a clean state between attempts."""
        ...
