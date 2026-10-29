"""P14: a destination or identity value must come from the system's own records, not from outside content.

An agent that reads outside content (an email, a message, a page, a file) can be handed a value -- a bank account, a
recipient, a payee name -- and copy it into a tool that acts. No wording gives that away: "the account for this
request is X" is an ordinary sentence. So this guard follows the value, not the words. It remembers what each tool
returned, split by where it came from: outside-content readers on one side (``TargetProfile.outside_content_readers``;
a result it cannot place, and the incoming request itself, count as outside too), the system's own records on the
other. Before a dangerous tool runs, every destination or identity argument (``TargetProfile.value_args``) is checked:
a value that appeared in outside content and in no system record is refused, with the argument named, so it can be
confirmed out of band. Values found nowhere (constants the agent supplies) and values on record pass.

It never reads a tool's code or the target's domain; it needs only the discovered profile. It does not see values
the agent paraphrases or splits, and it trusts a system record as much as the record itself deserves.
"""

from __future__ import annotations

import re
import threading
from collections import deque
from typing import Any

from purpleteam.patches.base import Blocked, Patch

MIN_VALUE = 4  # shorter values ("a", "no") would match almost any text: never treated as planted
REMEMBERED = 64  # tool results kept per side; enough for one request through a multi-agent pipeline


class ProvenanceGuard(Patch):
    """Refuse a dangerous call whose destination or identity value only outside content supplied."""

    id, layer, answers = "P14", "provenance", ("untrusted_value_flow",)

    def __init__(self, outside_readers: set[str], value_args: dict[str, set[str]]) -> None:
        self._outside, self._value_args = set(outside_readers), {t: set(a) for t, a in value_args.items()}
        self._seen = {"outside": deque(maxlen=REMEMBERED), "record": deque(maxlen=REMEMBERED)}
        self._last_tool: dict[str, str] = {}  # agent -> the tool it last called, whose result is screened next
        self._lock = threading.Lock()

    def screen(self, agent: str, text: str, source: str) -> str:
        if source in ("input", "tool_result"):
            tool = self._last_tool.get(agent) if source == "tool_result" else None
            side = "record" if tool and tool not in self._outside else "outside"
            with self._lock:
                self._seen[side].append(str(text).lower())
        return text

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        with self._lock:
            self._last_tool[agent] = tool
            outside, record = list(self._seen["outside"]), list(self._seen["record"])
        for arg in sorted(self._value_args.get(tool, ())):
            value = str(args.get(arg) or "").strip().lower()
            if len(value) < MIN_VALUE:
                continue
            found = re.compile(rf"(?<![a-z0-9]){re.escape(value)}(?![a-z0-9])")
            if any(found.search(t) for t in outside) and not any(found.search(t) for t in record):
                raise Blocked(f"{tool}.{arg} takes a value that only outside content supplied and no system record "
                              "confirms: verify it out of band before this call runs")
