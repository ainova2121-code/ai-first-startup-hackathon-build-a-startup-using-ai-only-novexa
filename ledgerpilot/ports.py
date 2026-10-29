"""Extension points where the purple-team platform plugs into LedgerPilot."""

from typing import Any, Literal, Protocol

TextSource = Literal["input", "tool_result", "output"]


class Blocked(Exception):
    """Raised by a guard to stop untrusted text or a tool call."""


class ReviewRequired(Blocked):
    """Raised when a tool call is held for a human review decision."""


class Guard(Protocol):
    def screen(self, agent: str, text: str, source: TextSource) -> str:
        """Return the text (possibly sanitized) or raise Blocked."""
        ...

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        """Raise Blocked if the tool call must not run."""
        ...


class EventSink(Protocol):
    def emit(self, agent: str, kind: str, payload: dict[str, Any]) -> None: ...

    def hold_for_review(self, agent: str, tool: str, args: dict[str, Any], reason: str) -> str: ...


class NoGuard:
    def screen(self, agent: str, text: str, source: TextSource) -> str:
        return text

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        return None


class NullSink:
    def emit(self, agent: str, kind: str, payload: dict[str, Any]) -> None:
        return None

    def hold_for_review(self, agent: str, tool: str, args: dict[str, Any], reason: str) -> str:
        return f"Held for human review: {tool} — {reason}"
