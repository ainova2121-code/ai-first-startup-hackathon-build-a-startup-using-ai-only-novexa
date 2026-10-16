"""Blast radius: if an agent is compromised, what is the worst it can do, and how far can that spread?

A pre-deployment answer, computed from what discovery found, with no model calls and nothing domain-specific.
Danger is rarely one tool; it is a *chain* of capabilities an attacker can string together:

- ``unbounded_execution``: a tool that runs whatever code or query the model writes.
- ``lethal_trifecta``: private data it can read, untrusted content it takes in, and a way to send things out.
- ``injection_to_action``: untrusted content it takes in, and a tool that changes or sends something.
- ``exfiltration_path``: data it can read, and a way to send things out.
- ``destructive_action``: a tool that deletes.
- ``cross_agent_propagation``: untrusted content entering one agent, and an action tool in an agent it hands work to.
- ``state_change``: it can change records at all (the baseline, low).

Chains are found on each agent's own tools, on the union of tools behind a *shared credential*, and along hand-offs
the operator declares (how agents pass work on cannot be seen from outside, so without them propagation is not
assessed and the report says so). A shared credential only matters if an attacker obtains it (a prompt or config leak,
an unbounded tool), because steering an agent through its own tools never reaches another agent's tools; so those
chains are one severity lower and say so. A chain is ``predicted`` until a proven breach in the same assessment went
through one of its tools, then ``demonstrated``.

Each agent gets two scores that rank agents against each other and are not probabilities. ``score`` is what it can do
with its *own* tools; ``reach`` also counts what it could get to through a shared credential or a hand-off. Each kind
of chain has a weight (critical 0.9, high 0.7, medium 0.4, low 0.15) and kinds combine as independent risks,
1 - the product of (1 - weight), so a second route raises a score without ever passing 100. Shared credentials and
undeclared permissions are listed as amplifiers and are not scored. Which
tools take in untrusted content is guessed from channel words in their names (email, message, url, document...) unless
the caller says; the guess is reported as an assumption. Tools never used in legitimate runs, if those are given, are
listed as removable, for a person to confirm.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from purpleteam.discovery import DELETE, EXECUTE, EXTERNAL, READ, WRITE, DiscoveredTool, TargetProfile, name_tokens
from purpleteam.identity import PermissionManifest, check_credentials

SEVERITY = {"critical": 90, "high": 70, "medium": 40, "low": 15}  # also the order chains are listed in
_CHANNEL_WORDS = {"email", "mail", "message", "chat", "web", "url", "page", "document", "file", "upload", "attachment",
                  "ticket", "comment", "feed", "inbox", "webhook", "request", "input", "form"}
_LOWER = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}
_FIX = {
    "unbounded_execution": "replace it with fixed, parameterised operations, or hold every call for approval",
    "lethal_trifecta": "remove one leg: the private-data reader, the untrusted-content reader or the outward channel",
    "injection_to_action": "hold the action for approval, or keep untrusted content away from this agent",
    "exfiltration_path": "limit what the reader can see, or remove or allow-list the outward tool",
    "destructive_action": "hold every call for approval, or remove it",
    "cross_agent_propagation": "treat the hand-off as untrusted input: scan or structure it, and limit the next agent's tools",
    "state_change": "limit what it may write with argument allow-lists",
}


@dataclass(frozen=True)
class Chain:
    kind: str
    agents: tuple[str, ...]
    tools: tuple[str, ...]
    severity: str
    detail: str
    via: str = "its own tools"  # its own tools | a shared credential | a declared hand-off
    status: str = "predicted"   # predicted | demonstrated

    @property
    def fix(self) -> str:
        return _FIX[self.kind]


@dataclass
class AgentRadius:
    agent: str
    score: int   # from its own tools alone
    reach: int   # also counting a shared credential or a declared hand-off
    chains: list[Chain] = field(default_factory=list)
    amplifiers: list[str] = field(default_factory=list)
    removable: list[str] = field(default_factory=list)


@dataclass
class BlastReport:
    agents: list[AgentRadius]
    chains: list[Chain]
    assumptions: list[str]

    def to_dict(self) -> dict:
        return {
            "agents": [{"agent": a.agent, "score": a.score, "reach": a.reach, "chains": [c.kind for c in a.chains],
                        "amplifiers": a.amplifiers, "removable": a.removable} for a in self.agents],
            "chains": [{"kind": c.kind, "agents": list(c.agents), "tools": list(c.tools), "severity": c.severity,
                        "status": c.status, "via": c.via, "detail": c.detail, "fix": c.fix} for c in self.chains],
            "assumptions": self.assumptions,
        }


def _find(tools: list[DiscoveredTool], untrusted: set[str]) -> list[tuple[str, list[DiscoveredTool], str, str]]:
    """(kind, the tools in the chain, severity, detail) for every chain these tools form together."""
    ingest = [t for t in tools if t.name in untrusted]
    rest = [t for t in tools if t.name not in untrusted]
    reads = [t for t in rest if t.risk == READ]
    sends = [t for t in rest if t.risk == EXTERNAL]
    actors = [t for t in rest if t.risk in (WRITE, DELETE, EXTERNAL, EXECUTE)]
    found = []
    if executes := [t for t in tools if t.risk == EXECUTE]:
        found.append(("unbounded_execution", executes, "critical", "runs whatever code or query the model writes"))
    if ingest and reads and sends:
        found.append(("lethal_trifecta", ingest + reads + sends, "critical",
                      "reads private data, takes in untrusted content and can send things out"))
    if ingest and actors:
        found.append(("injection_to_action", ingest + actors, "high",
                      "untrusted content it reads can steer a tool that changes or sends something"))
    if reads and sends:
        found.append(("exfiltration_path", reads + sends, "high", "can read data and send it out"))
    if deletes := [t for t in tools if t.risk == DELETE]:
        found.append(("destructive_action", deletes, "high", "can delete"))
    if writes := [t for t in tools if t.risk == WRITE]:
        found.append(("state_change", writes, "low", "can change records"))
    return found


def _risk(chains: list[Chain]) -> int:
    """Kinds of chain combined as independent risks (the strongest chain of each kind counts)."""
    safe = 1.0
    for kind in {c.kind for c in chains}:
        safe *= 1 - SEVERITY[max((c.severity for c in chains if c.kind == kind), key=SEVERITY.__getitem__)] / 100
    return round(100 * (1 - safe))


def _upstream(edges: set[tuple[str, str]], agent: str) -> set[str]:
    seen, queue = set(), [agent]
    while queue:
        current = queue.pop()
        for source, target in edges:
            if target == current and source not in seen:
                seen.add(source)
                queue.append(source)
    return seen - {agent}


def blast_radius(profile: TargetProfile, *, manifest: PermissionManifest | None = None,
                 credentials: dict[str, str] | None = None, untrusted: Iterable[str] | None = None,
                 used: Iterable[str] | None = None, handoffs: Iterable[tuple[str, str]] = (),
                 proven: Iterable[tuple[str, str]] = ()) -> BlastReport:
    """``untrusted``: names of tools that take in untrusted content. ``used``: tools legitimate runs call.
    ``handoffs``: (from_agent, to_agent) pairs. ``proven``: (agent, tool) pairs a proven breach went through."""
    held: dict[str, list[DiscoveredTool]] = {agent: [] for agent in sorted(profile.agents)}
    for tool in profile.tools:
        held[tool.agent].append(tool)
    names = {t.name for t in profile.tools}
    edges = {(a, b) for a, b in handoffs}
    if unknown := sorted({a for pair in edges for a in pair} - set(held)):
        raise ValueError(f"hand-offs name agents that were not found: {', '.join(unknown)}")
    guessed = untrusted is None
    ingest = ({t.name for t in profile.tools if t.risk in (READ, EXTERNAL) and set(name_tokens(t.name)) & _CHANNEL_WORDS}
              if guessed else set(untrusted))
    if missing := sorted(ingest - names):
        raise ValueError(f"untrusted names tools that were not found: {', '.join(missing)}")
    credentials = check_credentials(credentials or {})

    chains: dict[tuple, Chain] = {}

    def add(kind: str, agents: Iterable[str], tools: list[DiscoveredTool], severity: str, detail: str, via: str) -> None:
        key = (kind, tuple(sorted(set(agents))), tuple(sorted({t.name for t in tools})))
        chains.setdefault(key, Chain(kind, key[1], key[2], severity, detail, via))

    for agent, tools in held.items():
        for kind, chain_tools, severity, detail in _find(tools, ingest):
            add(kind, [agent], chain_tools, severity, detail, "its own tools")
    users: dict[str, list[str]] = {}
    for agent, label in credentials.items():
        users.setdefault(label, []).append(agent)
    for label, group in sorted(users.items()):
        if len(group) > 1:
            union = [t for a in group for t in held.get(a, [])]
            for kind, chain_tools, severity, detail in _find(union, ingest):
                add(kind, group, chain_tools, _LOWER[severity], f"{detail}, if the one credential {label!r} is obtained",
                    "a shared credential")
    for source, target in sorted(edges):
        for upstream in sorted({source} | _upstream(edges, source)):
            entry = [t for t in held[upstream] if t.name in ingest]
            actors = [t for t in held[target] if t.risk in (WRITE, DELETE, EXTERNAL, EXECUTE)]
            if entry and actors:
                add("cross_agent_propagation", [upstream, target], entry + actors, "high",
                    f"untrusted content entering {upstream!r} can steer {target!r}", "a declared hand-off")

    reached = {(agent, tool) for agent, tool in proven}
    ordered = sorted(chains.values(), key=lambda c: (-SEVERITY[c.severity], c.kind, c.agents, c.tools))
    ordered = [Chain(c.kind, c.agents, c.tools, c.severity, c.detail, c.via,
                     "demonstrated" if any(a in c.agents and t in c.tools for a, t in reached) else "predicted")
               for c in ordered]
    used_names = None if used is None else set(used)
    shared = {a for group in users.values() if len(group) > 1 for a in group}
    radii = []
    for agent, tools in held.items():
        mine = [c for c in ordered if agent in c.agents]
        amplifiers = (["shares a credential with another agent"] if agent in shared else []) + (
            ["no declared permissions"] if manifest is None else [])
        removable = sorted(t.name for t in tools if used_names is not None and t.name not in used_names)
        radii.append(AgentRadius(agent, _risk([c for c in mine if c.via == "its own tools"]), _risk(mine), mine,
                                 amplifiers, removable))
    radii.sort(key=lambda r: (-r.score, -r.reach, r.agent))

    assumptions = []
    if guessed:
        assumptions.append("which tools take in untrusted content was guessed from channel words in their names")
    if not edges:
        assumptions.append("no hand-offs were declared, so propagation between agents was not assessed")
    if used is None:
        assumptions.append("no legitimate-use data was given, so no tool is suggested for removal")
    if not credentials:
        assumptions.append("no credentials were given, so shared-credential reach was not assessed")
    return BlastReport(radii, ordered, assumptions)
