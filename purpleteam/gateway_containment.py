"""Wires purpleteam.defender.containment's escalation ladder into the gateway's live decisions: a
proven block narrows that agent's access automatically, signed into the ledger as it happens.
Restoring narrowed access needs a human, the same as widening the signed policy itself ever does
— this only ever tightens what the declared policy already allows, never grants anything beyond
it, so it needs no separate approval the way a wider change would: narrowing is safe by
construction.

Held-for-review (``ContainmentLevel.HELD_FOR_REVIEW``) is recorded but never auto-applied:
deciding a tool is "relied on" needs a legitimate-use record this module does not have, so it is
surfaced for a human to act on, not guessed at.

State lives only in this process's memory — a restart forgets every automatic narrowing and every
breach count, back to whatever the signed policy and keyring already say on their own. That is a
real, known limit, not an oversight: every escalation is also a signed ledger event, so the
history survives a restart even though the live override itself does not.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from purpleteam.defender.containment import ContainmentLevel, decide
from purpleteam.gateway_keys import GatewayKeys
from purpleteam.identity import PermissionManifest


@dataclass(frozen=True)
class ContainmentEvent:
    level: str
    agent: str
    tool: str
    kind: str
    reason: str


class LiveContainment:
    def __init__(self, declared: PermissionManifest, keys: GatewayKeys | None = None) -> None:
        self._declared = declared  # the signed policy's own manifest; never mutated by this class
        self._keys = keys          # for credential_revoked; that level is a no-op without one
        self._denied: set[tuple[str, str]] = set()
        self._breaches: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def permits(self, agent: str, tool: str, args: dict) -> bool:
        """Whether containment has anything to say about this call — never an opinion beyond what
        it has itself narrowed, or what the declared policy already restricts for this pair."""
        with self._lock:
            if (agent, tool) in self._denied:
                return False
        if self._declared.resources.get((agent, tool)) is None:
            return True  # no declared resource rule for this pair; not containment's call to make
        return self._declared.reason_denied(agent, tool, args) is None

    def observe_block(self, kind: str, agent: str, tool: str, key_id: str | None = None, *,
                      relied_on: bool = False) -> ContainmentEvent | None:
        """A patch (or containment's own prior narrowing) just proved another call from ``agent``
        to ``tool`` violates the policy. Escalates automatically for the two levels that only ever
        narrow access or revoke a credential. Returns the event to log — including for
        ``held_for_review``, which changes nothing automatically but must still be seen — or
        ``None`` only when ``credential_revoked`` had no keyring, key id, or live key to act on."""
        with self._lock:
            key = (agent, tool)
            prior = self._breaches.get(key, 0)
            self._breaches[key] = prior + 1
            level = decide(kind, agent, tool, self._declared, prior_breaches=prior, relied_on=relied_on)
            if level is ContainmentLevel.TOOL_DENIED:
                self._denied.add(key)
            elif level is ContainmentLevel.CREDENTIAL_REVOKED:
                if self._keys is None or key_id is None:
                    return None
                try:
                    self._keys.revoke(key_id)
                except ValueError:
                    return None  # the key was already gone; nothing new to report
            # held_for_review changes nothing automatically, but is still reported below — a
            # level a human must act on is exactly the one that must not go unrecorded.
        return ContainmentEvent(level.name.lower(), agent, tool, kind,
                               f"{kind} via {tool}: escalated to {level.name.lower()}")
