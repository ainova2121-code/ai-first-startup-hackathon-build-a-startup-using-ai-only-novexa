"""Proof-gated, graduated containment: given a proven breach, the narrowest response that would
have stopped exactly that proof — never a full agent kill when a scoped denial would do.

Four levels, narrowest first:
  resource_denied     a declared resource allowlist already exists for this (agent, tool); the
                       fix is enforcing what the business already told us, not inventing a rule
                       from one bad example.
  tool_denied          no declared allowlist exists, so the honest fix is removing the tool from
                       what this agent may call — guessing at what a safe value looks like from a
                       single malicious one is not a real fix.
  held_for_review      what ``tool_denied`` would be, downgraded: a legitimate-use record shows
                       this agent actually relies on the tool, so autonomous damage is stopped
                       without blocking the business outright.
  credential_revoked   this agent has proven more than one distinct breach, or the breach is about
                       its identity rather than one tool — a narrower fix would not address either.

This module only decides and describes; it never calls a guard or a keyring itself. ``escalate``
produces the updated ``PermissionManifest`` for the two levels that have one; ``held_for_review``
is a catalog patch (``purpleteam.oversight.HumanReviewGate``) and ``credential_revoked`` is a keyring
action (``purpleteam.gateway_keys.GatewayKeys.revoke``) — both already exist, so the caller applies
them directly rather than this module wrapping them, the same separation ``Defender.select`` and
``Verifier`` already keep between deciding and acting.
"""

from __future__ import annotations

from enum import IntEnum

from purpleteam.identity import PermissionManifest

REPEAT_THRESHOLD = 2  # this agent's 2nd distinct proven breach escalates straight to revocation
_IDENTITY_KINDS = frozenset({"unauthenticated_agent", "identity_mismatch"})


class ContainmentLevel(IntEnum):
    RESOURCE_DENIED = 1
    TOOL_DENIED = 2
    HELD_FOR_REVIEW = 3
    CREDENTIAL_REVOKED = 4


def decide(kind: str, agent: str, tool: str, manifest: PermissionManifest, *,
          prior_breaches: int = 0, relied_on: bool = False) -> ContainmentLevel:
    """The narrowest level that would have stopped a breach of ``kind`` through ``tool``, given
    what ``manifest`` already declares. ``prior_breaches`` is the caller's own count of this
    agent's earlier distinct proven breaches — this module keeps no state of its own.
    ``relied_on``: a legitimate-use record shows this agent actually calls the tool for real work."""
    if prior_breaches >= REPEAT_THRESHOLD or kind in _IDENTITY_KINDS:
        return ContainmentLevel.CREDENTIAL_REVOKED
    if manifest.resources.get((agent, tool)) is not None:
        return ContainmentLevel.RESOURCE_DENIED
    return ContainmentLevel.HELD_FOR_REVIEW if relied_on else ContainmentLevel.TOOL_DENIED


def escalate(level: ContainmentLevel, agent: str, tool: str, manifest: PermissionManifest) -> PermissionManifest | None:
    """The updated manifest ``level`` calls for, or ``None`` when this level has no manifest shape
    of its own (``held_for_review``, ``credential_revoked`` — see the module docstring)."""
    if level is ContainmentLevel.RESOURCE_DENIED:
        return manifest  # the declared allowlist already covers this; nothing to change
    if level is ContainmentLevel.TOOL_DENIED:
        allowed = dict(manifest.allowed)
        allowed[agent] = allowed.get(agent, frozenset()) - {tool}
        resources = {pair: rule for pair, rule in manifest.resources.items() if pair != (agent, tool)}
        return PermissionManifest(allowed, resources)
    return None
