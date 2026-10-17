"""Infer which agents in a multi-agent pipeline probably hand off to each other, from model
traffic the gateway already observed — a suggestion to feed ``blast.blast_radius``'s ``handoffs``
parameter, never an assertion.

A handoff is detected as one agent's reply text recurring, largely unchanged, as the text that
starts another agent's conversation: strong evidence B picked up what A produced, not proof. A
heavily rephrased handoff will not match; a coincidental overlap could produce a false edge. The
result is named "inferred" everywhere it is used, the same way an auto-derived permission
manifest is — meant to be reviewed before being trusted, never applied silently.

Needs ``GatewayObserver(track_handoffs=True)``: off by default, since this is the one place raw
prompt/reply text is kept rather than hashed (see ``gateway_observer``'s own docstring).
"""

from __future__ import annotations

MIN_OVERLAP = 40  # characters; shorter overlaps are too easy to produce by coincidence


def infer_handoffs(exchanges: list[tuple[str, str, str]], *, min_overlap: int = MIN_OVERLAP) -> list[tuple[str, str]]:
    """``exchanges``: (agent, first_user, answer) for each observed conversation — see
    ``GatewayObserver.exchanges_for_handoffs``. Returns sorted (from_agent, to_agent) pairs, each
    found at least once: ``from_agent``'s own reply text recurred inside ``to_agent``'s opening
    input. Self-pairs and overlaps shorter than ``min_overlap`` are never reported."""
    edges: set[tuple[str, str]] = set()
    for from_agent, _, answer in exchanges:
        fragment = answer.strip()
        if len(fragment) < min_overlap:
            continue
        for to_agent, first_user, _ in exchanges:
            if to_agent != from_agent and fragment in first_user:
                edges.add((from_agent, to_agent))
    return sorted(edges)
