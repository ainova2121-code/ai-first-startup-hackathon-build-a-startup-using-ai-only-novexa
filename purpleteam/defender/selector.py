"""The defender: given a proven breach, choose patches from the catalog and compose a guard.

The selection is deterministic (finding kind -> catalog IDs); an optional LLM selector may
reorder or narrow within the catalog, but can never invent a patch or write code. Patches are
built with parameters from the target profile and the business's facts. The result is a
CompositeGuard ready to attach to the target, plus the evidence an audit trail needs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from purpleteam.discovery import EXECUTE, TargetProfile
from purpleteam.identity import PermissionManifest
from purpleteam.patches.base import CompositeGuard, Patch
from purpleteam.patches.catalog import FINDING_PATCHES, GLOBAL_PATCHES, PATCH_SUMMARY
from purpleteam.patches.rules import AgentScopeGuard, ArgumentAllowlist, EgressGuard, SqlFirewall, ToolGate
from purpleteam.patches.scanners import InjectionScanner, OutputRedactor, injection_backend_available
from purpleteam.secrets import SecretFinder

_SECRET_PATTERNS = [re.compile(r"\b[A-Z]{2}\d{10,}\b"), re.compile(r"\bHTK-[A-Z0-9-]+\b")]


@dataclass(frozen=True)
class Finding:
    kind: str          # injection_action | exfiltration | sql_injection | jailbreak | ...
    tool: str          # the tool the breach went through
    agent: str = ""
    detail: str = ""
    signals: tuple = ()  # extra pattern evidence on the breach (purpleteam.attack.signals.Signal); not itself proof
    source: str = "dynamic"  # dynamic (exploited against the running target) | static (found by reading its source)


MODES = ("staging", "production")


@dataclass
class Defense:
    patch_ids: list[str]
    guard: CompositeGuard
    rationale: str
    mode: str = "staging"  # staging = auto-apply; production = needs explicit human approval to ship
    applied: list[dict] = field(default_factory=list)  # {id, hash, summary} for the audit trail


class Defender:
    """Selects catalog patches for a finding and composes them into a guard."""

    def __init__(self, profile: TargetProfile, facts: dict | None = None) -> None:
        self._profile = profile
        self._facts = facts or {}
        self._mode = self._facts.get("mode", "staging")
        if self._mode not in MODES:
            raise ValueError(f"facts['mode'] must be one of {MODES}")

    def select(self, finding: Finding) -> Defense:
        ids = FINDING_PATCHES.get(finding.kind, [])
        built = [(pid, self._build(pid, finding)) for pid in ids]
        patches = [patch for _, patch in built if patch is not None]
        applied = [{"id": pid, "hash": patch.code_hash(), "summary": PATCH_SUMMARY[pid]}
                   for pid, patch in built if patch is not None]
        rationale = f"{finding.kind} via {finding.tool}: applied {', '.join(p['id'] for p in applied)}"
        return Defense([p["id"] for p in applied], CompositeGuard(patches), rationale,
                       mode=self._mode, applied=applied)

    def select_all(self, findings: list[Finding]) -> Defense:
        """One defense for several findings; a patch is applied once per target or per tool."""
        merged: dict[tuple, tuple[dict, Patch]] = {}
        rationale: list[str] = []
        for finding in findings:
            defense = self.select(finding)
            rationale.append(defense.rationale)
            for entry, patch in zip(defense.applied, defense.guard.patches):
                scope = None if entry["id"] in GLOBAL_PATCHES else finding.tool
                merged.setdefault((entry["id"], scope), (entry, patch))
        entries = [entry for entry, _ in merged.values()]
        guard = CompositeGuard([patch for _, patch in merged.values()])
        return Defense([e["id"] for e in entries], guard, "; ".join(rationale), mode=self._mode, applied=entries)

    def _build(self, patch_id: str, finding: Finding) -> Patch | None:
        if patch_id == "P2":
            return InjectionScanner() if injection_backend_available() else None
        if patch_id == "P4":
            return ToolGate(self._profile.dangerous_tools | {finding.tool})
        if patch_id == "P5":
            allowed, arg = self._facts.get("verified_values"), self._facts.get("verified_arg")
            return ArgumentAllowlist(finding.tool, arg, set(allowed)) if allowed and arg else None  # operator-supplied
        if patch_id == "P8":
            return SqlFirewall(self._sql_tools(finding), tables=self._facts.get("tables"))
        if patch_id == "P9":
            return OutputRedactor(self._finder(_SECRET_PATTERNS))
        if patch_id == "P10":
            return EgressGuard(None, self._finder())
        if patch_id == "P11":
            return AgentScopeGuard(self._manifest())
        return None

    def _manifest(self) -> PermissionManifest:
        """The declared permissions (``facts["manifest"]``); without one, what each agent holds today."""
        declared = self._facts.get("manifest")
        if declared is None:
            return PermissionManifest.from_profile(self._profile)
        if not isinstance(declared, PermissionManifest):
            raise ValueError('facts["manifest"] must be a PermissionManifest')
        return declared

    def _finder(self, extra_patterns: list[re.Pattern[str]] | tuple = ()) -> SecretFinder:
        """Known secrets come from the caller's facts (``facts["secrets"]``); formats are always on."""
        return SecretFinder(known=self._facts.get("secrets", ()), extra_patterns=extra_patterns)

    def _sql_tools(self, finding: Finding) -> set[str]:
        execute_tools = {t.name for t in self._profile.tools if t.risk == EXECUTE}
        return execute_tools | {finding.tool}
