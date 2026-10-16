"""Agent identity: who may call which tool, and what the discovered setup says about it.

The platform does not issue credentials; vendors that do exist, and customers already run one.
It does three things around identity: it states what each agent *should* be allowed to do (a
permission manifest), it checks the discovered setup against that and against common structural
weaknesses (posture), and it proves exploitation (the scope oracle) and blocks it (the P11 guard).

A manifest is what the customer *intends*; ``PermissionManifest.from_profile`` infers a draft from
what each agent holds today, which can only be corrected downwards by a person. Findings are
signals for review, not verdicts. Domain-agnostic: nothing here knows what the tools are for.

Identity has two more parts. *Authentication*: an agent reached through a key bound to it is authenticated, and one
told apart only by its prompt or a header it sets itself is not (anything can claim its name), which is a finding.
*Baseline*: ``baseline`` records what each agent is (its tools and a hash of its prompt, never the text) and ``drift``
compares a later profile with it, so an assessment can show the agent that was tested is the agent that is deployed.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from purpleteam.discovery import DELETE, EXECUTE, EXTERNAL, WRITE, DiscoveredTool, TargetProfile, needs_review
from purpleteam.secrets import SecretFinder, looks_random

MAX_AGENTS = 200
MAX_TOOLS_PER_AGENT = 500
MAX_MANIFEST_BYTES = 1_000_000
_BARE_TOKEN = re.compile(r"[A-Za-z0-9+/=]{16,}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[\w.:/-]+(?: [\w.:/-]+)*")  # plain words, single spaces allowed, no control characters
_OUTWARD = (EXTERNAL, DELETE, EXECUTE)


def valid_name(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 128 and _NAME.fullmatch(value) is not None


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):  # json would silently keep the last of two entries for one agent
        raise ValueError("duplicate key in the manifest")
    return dict(pairs)


@dataclass(frozen=True)
class PermissionManifest:
    allowed: dict[str, frozenset[str]]  # agent name -> tools it may call; anything else is denied

    def permits(self, agent: str, tool: str) -> bool:
        return tool in self.allowed.get(agent, frozenset())

    def to_dict(self) -> dict[str, list[str]]:
        return {agent: sorted(tools) for agent, tools in sorted(self.allowed.items())}

    @classmethod
    def from_profile(cls, profile: TargetProfile) -> PermissionManifest:
        """A draft: each agent may call exactly the tools it holds today."""
        held: dict[str, set[str]] = {agent: set() for agent in profile.agents}
        for tool in profile.tools:
            held[tool.agent].add(tool.name)
        return cls({agent: frozenset(tools) for agent, tools in held.items()})

    @classmethod
    def from_dict(cls, data: Any) -> PermissionManifest:
        if not isinstance(data, dict) or len(data) > MAX_AGENTS:
            raise ValueError("a manifest maps agent names to lists of tool names")
        allowed: dict[str, frozenset[str]] = {}
        for agent, tools in data.items():
            if not valid_name(agent) or not isinstance(tools, list) or len(tools) > MAX_TOOLS_PER_AGENT:
                raise ValueError(f"invalid manifest entry for agent {str(agent)[:40]!r}")
            if not all(valid_name(tool) for tool in tools):
                raise ValueError(f"invalid tool name in the manifest entry for {agent!r}")
            allowed[agent] = frozenset(tools)
        return cls(allowed)

    @classmethod
    def load(cls, path: str | Path) -> PermissionManifest:
        path = Path(path)
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValueError("the manifest file is too large")
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicates))


# IdentityFinding kinds, split by what they say: did the agent's own setup go outside what was declared
# (SCOPE_KINDS), or has the agent itself changed since the baseline it was last checked against (DRIFT_KINDS).
SCOPE_KINDS = frozenset({"excess_privilege", "undeclared_agent", "unknown_agent", "duty_conflict",
                         "unscoped_execution", "shared_credential", "unauthenticated_agent", "identity_mismatch"})
DRIFT_KINDS = frozenset({"agent_added", "agent_missing", "tools_added", "tools_removed", "prompt_changed",
                         "model_changed"})


@dataclass(frozen=True)
class IdentityFinding:
    kind: str          # one of SCOPE_KINDS or DRIFT_KINDS
    agent: str         # the agent, or a comma-separated list for a shared credential
    tools: tuple[str, ...]
    detail: str
    severity: str      # high | medium | low


def _held(profile: TargetProfile) -> dict[str, list[DiscoveredTool]]:
    held: dict[str, list[DiscoveredTool]] = {agent: [] for agent in sorted(profile.agents)}
    for tool in profile.tools:
        held[tool.agent].append(tool)
    return held


def check_credentials(credentials: dict[str, str]) -> dict[str, str]:
    """Credential *labels* name which credential an agent uses; they must never be the secret itself."""
    finder = SecretFinder()
    for agent, label in credentials.items():
        if not (valid_name(agent) and isinstance(label, str) and 0 < len(label) <= 128):
            raise ValueError(f"invalid credential entry for agent {str(agent)[:40]!r}")
        bare_token = _BARE_TOKEN.fullmatch(label) is not None and looks_random(label)  # no words or separators
        if finder.contains(label) or bare_token:
            raise ValueError("credential labels must be names, never the secret itself")
    return credentials


def posture(profile: TargetProfile, manifest: PermissionManifest | None = None,
            credentials: dict[str, str] | None = None) -> list[IdentityFinding]:
    """Structural identity weaknesses in what discovery found, and gaps against a declared manifest."""
    held = _held(profile)
    findings: list[IdentityFinding] = []
    for agent, tools in held.items():
        names = tuple(sorted(t.name for t in tools))
        if manifest is not None:
            findings += _manifest_gaps(agent, names, manifest)
        outward = tuple(sorted(t.name for t in tools if t.risk in _OUTWARD))
        if any(t.risk == WRITE for t in tools) and outward:
            written = tuple(sorted(t.name for t in tools if t.risk == WRITE))
            findings.append(IdentityFinding(
                "duty_conflict", agent, written + outward,
                "one agent can both change records and act outward (send, delete or execute)", "medium"))
        for tool in tools:
            if tool.risk == EXECUTE:
                findings.append(IdentityFinding(
                    "unscoped_execution", agent, (tool.name,),
                    "takes raw code or queries, so its scope is whatever the model writes", "high"))
    if manifest is not None:
        for agent in sorted(set(manifest.allowed) - set(held)):
            findings.append(IdentityFinding("unknown_agent", agent, (), "the manifest names an agent that was not found",
                                            "low"))
    for info in profile.agent_info:
        if info.authenticated is False:
            findings.append(IdentityFinding(
                "unauthenticated_agent", info.name, (),
                "told apart only by its prompt or a header it sets itself, so anything can claim its name; "
                "give each agent its own gateway key", "medium"))
        if info.claimed_other:
            findings.append(IdentityFinding(
                "identity_mismatch", info.name, (),
                f"{info.claimed_other} requests under this agent's key claimed to be a different agent", "high"))
    return findings + _shared_credentials(held, check_credentials(credentials or {}))


def baseline(profile: TargetProfile) -> dict[str, dict[str, Any]]:
    """What each agent is right now: its tools, a hash of its prompt, and the model name its traffic carried
    (gateway-observed targets only; never any prompt text)."""
    info = {a.name: a for a in profile.agent_info}
    return {agent: {"tools": sorted(t.name for t in tools),
                    "prompt_sha256": info[agent].prompt_sha256 if agent in info else None,
                    "model": info[agent].model if agent in info else None}
            for agent, tools in _held(profile).items()}


_BASELINE_FIELDS = ({"tools", "prompt_sha256"}, {"tools", "prompt_sha256", "model"})  # "model" is a later addition;
# a baseline saved before it existed is still accepted, so an old saved file never needs migrating.


def check_baseline(data: Any) -> dict[str, dict[str, Any]]:
    """A saved baseline is read from a file, so it is checked as strictly as a manifest."""
    if not isinstance(data, dict) or len(data) > MAX_AGENTS:
        raise ValueError("a baseline maps agent names to what each agent was")
    for agent, entry in data.items():
        if not (valid_name(agent) and isinstance(entry, dict) and set(entry) in _BASELINE_FIELDS):
            raise ValueError(f"invalid baseline entry for agent {str(agent)[:40]!r}")
        tools, digest, model = entry["tools"], entry["prompt_sha256"], entry.get("model")
        if not (isinstance(tools, list) and len(tools) <= MAX_TOOLS_PER_AGENT and all(valid_name(t) for t in tools)):
            raise ValueError(f"invalid tool list in the baseline entry for {agent!r}")
        if digest is not None and not (isinstance(digest, str) and _SHA256.fullmatch(digest)):
            raise ValueError(f"invalid prompt hash in the baseline entry for {agent!r}")
        if model is not None and not valid_name(model):
            raise ValueError(f"invalid model name in the baseline entry for {agent!r}")
    return data


def drift(profile: TargetProfile, saved: Any) -> list[IdentityFinding]:
    """How the agents now differ from a saved baseline: new or missing agents, tools gained or lost, a changed prompt."""
    before, now = check_baseline(saved), baseline(profile)
    findings = [IdentityFinding("agent_added", agent, tuple(now[agent]["tools"]),
                                "was not there when the baseline was taken", "medium")
                for agent in sorted(set(now) - set(before))]
    findings += [IdentityFinding("agent_missing", agent, (), "was in the baseline and has not been found", "low")
                 for agent in sorted(set(before) - set(now))]
    for agent in sorted(set(now) & set(before)):
        added = tuple(sorted(set(now[agent]["tools"]) - set(before[agent]["tools"])))
        removed = tuple(sorted(set(before[agent]["tools"]) - set(now[agent]["tools"])))
        if added:
            findings.append(IdentityFinding("tools_added", agent, added, "holds tools it did not hold in the baseline", "high"))
        if removed:
            findings.append(IdentityFinding("tools_removed", agent, removed, "no longer holds tools it held in the baseline", "low"))
        if None not in (now[agent]["prompt_sha256"], before[agent]["prompt_sha256"]) and \
                now[agent]["prompt_sha256"] != before[agent]["prompt_sha256"]:
            findings.append(IdentityFinding(
                "prompt_changed", agent, (), "its instructions differ from the baseline (a prompt with changing text, "
                "such as a date, differs on every run)", "medium"))
        now_model, before_model = now[agent].get("model"), before[agent].get("model")
        if None not in (now_model, before_model) and now_model != before_model:
            findings.append(IdentityFinding(
                "model_changed", agent, (), f"was answered by {before_model!r}, is now answered by {now_model!r}",
                "medium"))
    return findings


def _manifest_gaps(agent: str, names: tuple[str, ...], manifest: PermissionManifest) -> list[IdentityFinding]:
    permitted = manifest.allowed.get(agent)
    if permitted is None:
        return [IdentityFinding("undeclared_agent", agent, names,
                                "the agent is not in the manifest, so it should have no tools", "medium")] if names else []
    extra = tuple(name for name in names if name not in permitted)
    return [IdentityFinding("excess_privilege", agent, extra,
                            "holds tools its permissions do not allow", "high")] if extra else []


def _shared_credentials(held: dict[str, list[DiscoveredTool]], credentials: dict[str, str]) -> list[IdentityFinding]:
    users: dict[str, list[str]] = {}
    for agent, label in credentials.items():
        users.setdefault(label, []).append(agent)
    findings = []
    for label, agents in sorted(users.items()):
        if len(agents) > 1:
            names = tuple(sorted({t.name for a in agents for t in held.get(a, []) if t.dangerous}))
            findings.append(IdentityFinding(
                "shared_credential", ",".join(sorted(agents)), names,
                f"{len(agents)} agents act through one credential, so actions cannot be told apart or limited "
                "per agent", "high" if names else "medium"))
    return findings


def inventory(profile: TargetProfile, manifest: PermissionManifest | None, findings: list[IdentityFinding],
              credentials: dict[str, str] | None = None) -> dict[str, Any]:
    """The evidence view: every agent, its tools and permissions, and the findings. Never prompt text."""
    info = {a.name: a for a in profile.agent_info}
    credentials = check_credentials(credentials or {})
    agents = []
    for agent, tools in _held(profile).items():
        entry: dict[str, Any] = {
            "name": agent,
            "tools": [{"name": t.name, "risk": t.risk} for t in sorted(tools, key=lambda t: t.name)],
            "credential": credentials.get(agent),
            "permitted": sorted(manifest.allowed.get(agent, ())) if manifest is not None else None,
        }
        if agent in info:
            entry |= {"prompt_sha256": info[agent].prompt_sha256, "prompt_chars": info[agent].prompt_chars,
                      "authenticated": info[agent].authenticated, "model": info[agent].model}
        agents.append(entry)
    return {"manifest": "declared" if manifest is not None else "none", "agents": agents,
            "findings": [asdict(f) for f in findings], "needs_review": needs_review(profile),
            "baseline": baseline(profile)}
