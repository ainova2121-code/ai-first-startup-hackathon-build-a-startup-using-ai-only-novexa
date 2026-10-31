"""The defender: given a proven breach, choose patches from the catalog and compose a guard.

The selection is deterministic (finding kind -> catalog IDs); an optional LLM selector may
reorder or narrow within the catalog, but can never invent a patch or write code. Patches are
built with parameters from the target profile and the business's facts. The result is a
CompositeGuard ready to attach to the target, plus the evidence an audit trail needs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from purpleteam.adapter import OBSERVED, PROPOSED, REPORTED
from purpleteam.defender.containment import ContainmentLevel, escalate
from purpleteam.discovery import TargetProfile
from purpleteam.identity import PermissionManifest
from purpleteam.oversight import HumanReviewGate, ReviewQueue
from purpleteam.patches.base import CompositeGuard, Patch
from purpleteam.patches.caller_scope import CallerScopeGuard
from purpleteam.patches.catalog import (
    FINDING_PATCHES, GLOBAL_PATCHES, PATCH_SUMMARY, SCOPED_REPLACES_HOLD, fallback_patches)
from purpleteam.patches.prompt_hardening import PromptHardeningGuard
from purpleteam.patches.provenance import ProvenanceGuard
from purpleteam.patches.rules import (
    AgentScopeGuard, ArgumentAllowlist, EgressGuard, LoopGuard, MemoryWriteGuard, SqlFirewall)
from purpleteam.patches.scanners import InjectionScanner, OutputRedactor, injection_backend_available
from purpleteam.secrets import SecretFinder

if TYPE_CHECKING:  # pyrit (attack.corpus's own dependency) is attack/SAST-time only, not a gateway runtime need
    from purpleteam.attack.corpus import CorpusResult

_SECRET_PATTERNS = [re.compile(r"\b[A-Z]{2}\d{10,}\b"), re.compile(r"\bHTK-[A-Z0-9-]+\b")]


@dataclass(frozen=True)
class Finding:
    kind: str          # injection_action | exfiltration | sql_injection | jailbreak | ...
    tool: str          # the tool the breach went through
    agent: str = ""
    detail: str = ""
    signals: tuple = ()  # extra pattern evidence on the breach (purpleteam.attack.signals.Signal); not itself proof
    source: str = "dynamic"  # dynamic (exploited against the running target) | static (found by reading its source)
    evidence: str = ""  # proposed | reported | observed (purpleteam.adapter) for a dynamic breach; "" for static


MODES = ("staging", "production")


@dataclass
class Defense:
    patch_ids: list[str]
    guard: CompositeGuard
    rationale: str
    mode: str = "staging"  # staging = auto-apply; production = needs explicit human approval to ship
    applied: list[dict] = field(default_factory=list)  # {id, hash, summary} for the audit trail


# What each escalation level adds when the previous one still let a replay through.
ESCALATIONS = ("the catalog patches for each finding",
               "hold every side-effecting tool of each breaching agent, not just the one that breached",
               "deny the breached tool to the breaching agent outright")


class Defender:
    """Selects catalog patches for a finding and composes them into a guard. ``review_queue``
    backs every P4 hold (durable by default when given a path; an ephemeral in-process queue when
    omitted, so a caller that never wired one up still gets a working P4, just not one that
    survives a restart — see ``purpleteam.oversight``). ``escalation`` (an index into
    ``ESCALATIONS``) tightens the defense when a verified replay showed the lighter one failing;
    it only ever narrows what the breaching agents may do, never another agent's tools."""

    def __init__(self, profile: TargetProfile, facts: dict | None = None,
                review_queue: ReviewQueue | None = None, escalation: int = 0,
                exclude: frozenset[str] = frozenset()) -> None:
        self._profile = profile
        self._facts = facts or {}
        self._mode = self._facts.get("mode", "staging")
        if self._mode not in MODES:
            raise ValueError(f"facts['mode'] must be one of {MODES}")
        if not 0 <= escalation < len(ESCALATIONS):
            raise ValueError(f"escalation must be between 0 and {len(ESCALATIONS) - 1}")
        self._review_queue = review_queue if review_queue is not None else ReviewQueue()
        self._escalation = escalation
        self._exclude = exclude  # patches a verified replay proved break legitimate work (see assessment)

    def select(self, finding: Finding) -> Defense:
        ids = [pid for pid in fallback_patches(finding.kind, bool(finding.tool)) if pid not in self._exclude]
        built = [(pid, self._build(pid, finding)) for pid in ids]
        if self._escalation == 0 and SCOPED_REPLACES_HOLD <= {pid for pid, patch in built if patch is not None}:
            built = [(pid, patch) for pid, patch in built if pid != "P4"]  # the tool is already confined to its job
        patches = [patch for _, patch in built if patch is not None]
        applied = [{"id": pid, "hash": patch.code_hash(), "summary": PATCH_SUMMARY[pid]}
                   for pid, patch in built if patch is not None]
        rationale = f"{finding.kind} via {finding.tool}: applied {', '.join(p['id'] for p in applied)}"
        return Defense([p["id"] for p in applied], CompositeGuard(patches), rationale,
                       mode=self._mode, applied=applied)

    def select_all(self, findings: list[Finding]) -> Defense:
        """One defense for several findings; a patch is applied once per target, or once per
        (agent, tool) for P4 (never merging across agents — see ``_scope_key``), or once per tool
        for the rest."""
        merged: dict[tuple, tuple[dict, Patch]] = {}
        rationale: list[str] = []
        for finding in findings:
            defense = self.select(finding)
            rationale.append(defense.rationale)
            for entry, patch in zip(defense.applied, defense.guard.patches):
                merged.setdefault((entry["id"], self._scope_key(entry["id"], finding)), (entry, patch))
        denied = sorted({(f.agent, f.tool) for f in findings if f.tool and f.source == "dynamic"})
        if self._escalation >= 2 and denied and "P11" not in self._exclude:
            manifest = self._manifest()
            for agent, tool in denied:
                manifest = escalate(ContainmentLevel.TOOL_DENIED, agent, tool, manifest)
            patch = AgentScopeGuard(manifest)
            names = ", ".join(f"{agent}.{tool}" for agent, tool in denied)
            merged[("P11", None)] = ({"id": "P11", "hash": patch.code_hash(),
                                      "summary": f"{PATCH_SUMMARY['P11']} — denied: {names}"}, patch)
            rationale.append(f"escalated: {names} denied")
        # P16 screens first: it reads the caller from the application's framing before any patch (P15) rewraps it.
        ordered = sorted(merged.values(), key=lambda item: item[0]["id"] != "P16")
        entries = [entry for entry, _ in ordered]
        guard = CompositeGuard([patch for _, patch in ordered])
        return Defense([e["id"] for e in entries], guard, "; ".join(rationale), mode=self._mode, applied=entries)

    def _scope_key(self, patch_id: str, finding: Finding) -> tuple | str | None:
        if patch_id in GLOBAL_PATCHES:
            return None
        if patch_id == "P4":
            # Agent-bound: a breach on one agent's tool call must never cause a merge that lets
            # a different agent's same-named tool share the hold/approval (see oversight.py).
            return (finding.agent, finding.tool)
        return finding.tool

    def _build(self, patch_id: str, finding: Finding) -> Patch | None:
        if not finding.tool and patch_id not in GLOBAL_PATCHES:
            # A source-level finding names a line, not a tool: a tool-scoped guard on tool "" would
            # guard nothing while still reading as "patched". Its only real fix is a source edit.
            return None
        if patch_id == "P2":
            return InjectionScanner() if injection_backend_available() else None
        if patch_id == "P4":
            scope = {(finding.agent, finding.tool)}
            if self._escalation >= 1:  # this agent is proven manipulable: every side effect it has waits
                scope |= {(finding.agent, t.name) for t in self._profile.tools
                          if t.agent == finding.agent and t.dangerous}
            return HumanReviewGate(scope, self._review_queue)
        if patch_id == "P5":
            allowed, arg = self._facts.get("verified_values"), self._facts.get("verified_arg")
            return ArgumentAllowlist(finding.tool, arg, set(allowed)) if allowed and arg else None  # operator-supplied
        if patch_id == "P8":
            return self._sql_firewall(finding)
        if patch_id == "P9":
            return OutputRedactor(self._finder(_SECRET_PATTERNS + self._redact_patterns()))
        if patch_id == "P10":
            return EgressGuard(None, self._finder())
        if patch_id == "P11":
            return AgentScopeGuard(self._manifest())
        if patch_id == "P12":
            scanner = InjectionScanner() if injection_backend_available() else None
            return MemoryWriteGuard(self._profile.memory_tools | {finding.tool}, self._finder(), scanner)
        if patch_id == "P13":
            return LoopGuard()
        if patch_id == "P14":
            return ProvenanceGuard(self._profile.outside_content_readers, self._profile.value_args)
        if patch_id == "P15":
            return PromptHardeningGuard()
        if patch_id == "P16":
            return self._caller_scope(finding)
        return None

    def _manifest(self) -> PermissionManifest:
        """The declared permissions (``facts["manifest"]``); without one, what each agent holds today."""
        declared = self._facts.get("manifest")
        if declared is None:
            return PermissionManifest.from_profile(self._profile)
        if not isinstance(declared, PermissionManifest):
            raise ValueError('facts["manifest"] must be a PermissionManifest')
        return declared

    def _caller_scope(self, finding: Finding) -> Patch | None:
        """P16 over the finding's tool, when the operator declared which query tools serve one caller per request
        (``facts["caller_scope"]``: ``tools``, ``columns`` {table: caller-id column}, ``pattern`` -- a regular
        expression whose first group reads the caller from the application's framing at the start of the input).
        Declare it only where the application writes that framing itself: a pattern a user's own text could match
        would let them name their caller. A malformed declaration is refused, never silently dropped."""
        scope = self._facts.get("caller_scope")
        if scope is None:
            return None
        try:
            tools, columns, pattern = set(scope["tools"]), dict(scope["columns"]), str(scope["pattern"])
            if isinstance(scope["tools"], str) or not (columns and re.compile(pattern).groups >= 1):
                raise ValueError
        except (KeyError, TypeError, ValueError, re.error) as error:
            raise ValueError('facts["caller_scope"] needs tools, columns {table: column} and a pattern with one '
                             'group') from error
        if finding.tool not in tools:
            return None
        return CallerScopeGuard({finding.tool}, columns, pattern, arg=self._facts.get("sql_arg", "sql"))

    def _redact_patterns(self) -> list[re.Pattern[str]]:
        """The operator's own value shapes for P9 to redact too (``facts["redact_patterns"]``: regular expressions),
        beyond the account- and honeytoken-shaped defaults. One that does not compile is refused, never dropped."""
        patterns = self._facts.get("redact_patterns", ())
        if not (isinstance(patterns, (list, tuple)) and all(isinstance(p, str) and p for p in patterns)):
            raise ValueError('facts["redact_patterns"] must be a list of regular expressions')
        try:
            return [re.compile(pattern) for pattern in patterns]
        except re.error as error:
            raise ValueError(f'facts["redact_patterns"] holds an invalid pattern: {error}') from error

    def _finder(self, extra_patterns: list[re.Pattern[str]] | tuple = ()) -> SecretFinder:
        """Known secrets come from the caller's facts (``facts["secrets"]``); formats are always on."""
        return SecretFinder(known=self._facts.get("secrets", ()), extra_patterns=extra_patterns)

    def _sql_firewall(self, finding: Finding) -> Patch | None:
        """Only the tool the finding actually named — never every ``EXECUTE``-risk tool in the
        whole profile, which swept shell/code tools with no SQL to parse into the same firewall
        and simply blocked them outright (gap: a tool with no ``sql`` argument can never parse as
        one valid SELECT, so it always fails closed, for the wrong, confusing reason). Even
        without ``facts["tables"]``, this still blocks every non-SELECT and multi-statement query;
        supplying it additionally scopes which tables a SELECT may name, which is still worth
        doing but is not the only thing standing between this and an unrestricted query tool."""
        return SqlFirewall({finding.tool}, arg=self._facts.get("sql_arg", "sql"), tables=self._facts.get("tables"))


_EVIDENCE_STRENGTH = {PROPOSED: 1, REPORTED: 2, OBSERVED: 3}  # weakest first, matching adapter.py's own ordering


def findings_from_breaches(breaches: list[CorpusResult]) -> list[Finding]:
    """One finding per distinct (kind, tool, agent); several attacks through one hole are one hole. Signal
    evidence (never the breach verdict itself) is pooled across every attack that found the same hole.

    ``evidence`` records the strongest level any pooled attack reached: a canary that only ever
    appeared in a *proposed* tool call (the model offered it; nothing confirms the call ran) is
    real evidence the model is willing to break policy, but it is not proof of executed impact —
    the two must never be presented as the same thing, so the distinction travels with the
    finding into every report and the defender's own audit entry, not just the raw attack log."""
    signals: dict[tuple, dict] = {}
    evidence: dict[tuple, str] = {}
    for r in breaches:
        for key in _keys(r):
            pool = signals.setdefault(key, {})
            for s in r.signals:
                pool[(s.scorer, s.pattern, s.where)] = s
            if _EVIDENCE_STRENGTH.get(r.evidence, 0) >= _EVIDENCE_STRENGTH.get(evidence.get(key, ""), 0):
                evidence[key] = r.evidence
    unique: dict[tuple, Finding] = {}
    for r in breaches:
        for key in _keys(r):
            unique.setdefault(key, Finding(*key, r.detail, tuple(signals[key].values()), evidence=evidence[key]))
    return list(unique.values())


def _keys(r: CorpusResult) -> list[tuple[str, str, str]]:
    """(kind, tool, agent) for every tool one breach went through: a planted value that travels on through a
    multi-agent pipeline is a breach at each dangerous tool it reaches, each needing its own defense."""
    return [(r.kind, tool, agent) for agent, tool in r.breached_tools] or [(r.kind, r.tool, r.agent)]
