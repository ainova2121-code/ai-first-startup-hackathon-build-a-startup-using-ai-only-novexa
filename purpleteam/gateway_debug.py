"""An explicit, operator-opted-in escape hatch for seeing a model's own reasoning/thinking text.

The signed audit ledger holds no raw data (see ``gateway_policy``'s module docstring) — on purpose,
because it is durable, append-only and meant to be kept. Reasoning text is exactly the kind of thing
that rule exists to keep out: it can repeat a vendor's bank details, a system prompt, anything a tool
result handed back. So it never reaches the ledger, full stop — not even as a redacted commitment.

``ReasoningDebugLog`` is the separate, narrower trade-off instead: unsigned, not tamper-evident, not
meant to be kept, written only when an operator has explicitly turned it on
(``GATEWAY_DEBUG_REASONING_PATH`` in ``gateway_main``) to see what a model was "thinking" while
debugging a run. The same deliberate, loud, off-by-default shape as ``GATEWAY_ALLOW_UNREDACTED_LEDGER``.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path


class ReasoningDebugLog:
    """Appends one JSON line per exchange that carried reasoning text. Best-effort: a write that
    fails is noted by the caller, never raised — this must not be able to block or fail a live
    request the way a signed ledger write legitimately can."""

    def __init__(self, path: Path) -> None:
        self._path, self._lock = path, threading.Lock()

    def record(self, *, agent: str | None, model: str, reasoning: str, redacted: bool) -> None:
        if not reasoning and not redacted:
            return
        line = json.dumps({"ts": time.time(), "agent": agent or "", "model": model,
                           "reasoning": reasoning, "redacted": redacted}, default=str)
        with self._lock, self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
