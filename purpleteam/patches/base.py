"""A patch is a prewritten guard. The defender only selects patches; it never writes code.

Each patch plugs into a target's guard port — it may screen untrusted text and/or authorize a
tool call, raising ``Blocked`` to stop it. A CompositeGuard runs the chosen patches in order and
is itself a valid Guard, so it attaches through whatever port the target exposes.

``Blocked`` is the platform's own exception, not any one target's: the platform is domain-agnostic
and must not hard-code a specific target's module here. A target whose own guard contract expects
a different exception type adapts between the two in its ``targets/`` adapter (see
``targets/ledgerpilot.py``'s guard adapter) — core patch code never needs to know.
"""

from __future__ import annotations

import hashlib
import inspect
from typing import Any

__all__ = ["Blocked", "HoldForReview", "Patch", "CompositeGuard"]


class Blocked(Exception):
    """Raised by a patch to stop untrusted text or a tool call."""


class HoldForReview(Blocked):
    """Raised when a tool call must be held for an out-of-band human decision."""


class Patch:
    """Base class: no-op screen and authorize. A concrete patch overrides what it needs."""

    id: str = ""
    layer: str = ""
    answers: tuple[str, ...] = ()

    def screen(self, agent: str, text: str, source: str) -> str:
        return text

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        return None

    def explain(self) -> str:
        return (self.__doc__ or "").strip().splitlines()[0] if self.__doc__ else self.id

    def code_hash(self) -> str:
        return hashlib.sha256(inspect.getsource(type(self)).encode("utf-8")).hexdigest()[:12]


class CompositeGuard:
    """Runs a list of patches as one Guard (chained screen, all-must-pass authorize)."""

    def __init__(self, patches: list[Patch]) -> None:
        self.patches = patches

    def screen(self, agent: str, text: str, source: str) -> str:
        for patch in self.patches:
            text = patch.screen(agent, text, source)
        return text

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        for patch in self.patches:
            patch.authorize(agent, tool, args)
