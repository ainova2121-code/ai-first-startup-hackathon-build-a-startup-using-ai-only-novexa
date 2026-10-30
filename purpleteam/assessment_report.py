"""What one assessment found and proved, and the verdict it reaches: ``blockers()`` is the single list of
reasons a run may not ship, so the verdict and the reasons shown for it can never disagree. Plus the
findings an assessment raises from structure alone, before any attack lands."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from purpleteam.attack.corpus import CorpusResult
from purpleteam.attack.outcome import INCONCLUSIVE
from purpleteam.defender.selector import Defense, Finding
from purpleteam.discovery import TargetProfile
from purpleteam.explainer import Explanation
from purpleteam.patches.catalog import FINDING_PATCHES, fallback_patches  # noqa: F401
from purpleteam.verifier import VerifyReport


@dataclass
class AssessmentReport:
    target: str
    results: list[CorpusResult]
    findings: list[Finding] = field(default_factory=list)
    defense: Defense | None = None
    verification: VerifyReport | None = None
    explanations: list[Explanation] = field(default_factory=list)
    sealed_root: str = ""
    chain_ok: bool = False
    identity: dict = field(default_factory=dict)  # agents, tools, permissions and identity findings
    trust: dict = field(default_factory=dict)  # public keys + signed checkpoint (+ anchors), to pin out of band
    anchor_errors: list[str] = field(default_factory=list)
    coverage: dict[str, dict] = field(default_factory=dict)
    scope: dict = field(default_factory=dict)  # for a focused run: topics, agent and what was skipped (and why)
    blast: dict = field(default_factory=dict)  # per-agent blast radius and the chains behind it, when it was requested
    baseline_checked: bool = False  # whether every agent was compared against a saved baseline, not just its manifest
    coverage_gaps: list[str] = field(default_factory=list)  # checks that were meant to run but could not
    escalation: int = 0  # the escalation level the verified defense reached
    excluded: frozenset[str] = frozenset()  # patches left out because a verified replay showed them blocking legit work
    impacts: list[str] = field(default_factory=list)  # what the defense costs legitimate work (e.g. waits for review)
    decisions: dict = field(default_factory=dict)  # every verified decision's inputs and outcome (purpleteam.decisions)
    policy: dict = field(default_factory=dict)  # what rebuilds the verified defense (defender.policy.policy_data)
    decision_drift: list[dict] = field(default_factory=list)  # decisions that changed since the approved baseline

    @property
    def safe_to_ship(self) -> bool:
        return not self.blockers()

    def blockers(self) -> list[str]:
        """Every reason this run may not ship -- the verdict is defined as this list being empty, so the
        verdict and the reasons shown for it can never disagree. Not safe whenever no attack ran, any one
        was inconclusive, the audit chain does not verify, a configured check could not cover the target
        (a scan that failed, code no scanner reads), the policy loosens an approved decision, or a finding
        was not proven defended: proving nothing, or on evidence that cannot be trusted, is not proving safety."""
        reasons = [] if self.results else ["no attack ran, so nothing was proven"]
        if self.scope.get("stopped"):
            reasons.append("the run was stopped before the assessment and verification completed")
        reasons += [f"attack {r.id} was inconclusive ({r.detail}): untested is not safe"
                    for r in self.results if r.outcome == INCONCLUSIVE]
        if not self.chain_ok:
            reasons.append("the audit chain does not verify")
        if self.scope.get("skipped"):
            reasons.append(f"requested topics were not tested: {self.scope['skipped']}")
        reasons += self.coverage_gaps
        loosened = sum(1 for flip in self.decision_drift if flip["severity"] == "high")
        if loosened:
            reasons.append(f"policy-decision drift: {loosened} approved decision(s) on verified attack input "
                           "(or redaction) would be looser under this run's policy")
        if self.findings and not (self.verification and self.verification.safe_to_ship):
            gate = (self.verification.failures + self.verification.errors) if self.verification else []
            reasons += gate or ["the findings were not proven defended"]
        return list(dict.fromkeys(reasons))  # each reason once, in order

    def to_dict(self) -> dict:
        verification = None
        if self.verification:
            verification = {**asdict(self.verification), "safe_to_ship": self.verification.safe_to_ship}
        return {
            "target": self.target,
            "scope": self.scope,
            "blast_radius": self.blast,
            "attacks": [{"id": r.id, "technique": r.technique, "breached": r.breached, "detail": r.detail,
                         "evidence": r.evidence, "signals": [asdict(s) for s in r.signals],
                         "outcome": r.outcome, "trials": r.trials, "conclusive": r.conclusive,
                         "upper_bound": r.upper_bound} for r in self.results],
            "findings": [asdict(f) for f in self.findings],  # asdict already recurses into the signals tuple
            "patches": self.defense.applied if self.defense else [],
            "verification": verification,
            "explanations": [asdict(e) for e in self.explanations],
            "identity": self.identity,
            "baseline_checked": self.baseline_checked,
            "coverage_gaps": self.coverage_gaps,
            "decisions": {k: self.decisions[k] for k in ("digest", "dropped") if k in self.decisions}
                         | {"count": len(self.decisions.get("probes", []))},
            "decision_drift": self.decision_drift,
            "excluded": sorted(self.excluded),
            "impacts": self.impacts,
            "safe_to_ship": self.safe_to_ship,
            "audit": {"merkle_root": self.sealed_root, "chain_ok": self.chain_ok, "trust": self.trust,
                      "anchor_errors": self.anchor_errors},
            "compliance": self.coverage,
        }



def surface_findings(profile: TargetProfile) -> list[Finding]:
    """Standing risks, before any attack lands. A memory-write tool: whatever is planted in it is recalled by every
    later conversation (P12). Outside content reaching a tool that takes a destination or identity value: a planted
    account or recipient can be copied straight into the call (P14), whether or not this run's attacks found it."""
    found = [Finding("memory_write_surface", t.name, t.agent, f"{t.name} persists content for later recall",
                     source="static") for t in profile.tools if t.memory]
    if profile.outside_content_readers:
        by_name = {t.name: t for t in profile.tools}
        found += [Finding("untrusted_value_flow", tool, by_name[tool].agent,
                          f"{tool} takes {', '.join(sorted(args))}, and outside content reaches this system",
                          source="static") for tool, args in sorted(profile.value_args.items())]
    return found


def patch_scopes(findings: list[Finding], applied: list[str]) -> list[dict]:
    """Which agent/tool each applied runtime guard actually covers, for display: a guard is never
    described as covering more than the findings that caused it."""
    return [{"id": pid, "agent": f.agent, "tool": f.tool, "kind": f.kind}
            for f in findings if f.tool for pid in fallback_patches(f.kind, bool(f.tool)) if pid in applied]


IDENTITY_PATCHABLE = {"excess_privilege", "undeclared_agent", "unscoped_execution"}


def patchable_identity_findings(identity: dict) -> list[Finding]:
    """Structural identity findings the catalog can answer (excess_privilege, undeclared_agent,
    unscoped_execution) feed into the same Defender pipeline a breach does. Every other kind
    (shared_credential, a prompt or model change...) has no sensible runtime guard and stays
    report-only: claiming a patch for those would assert a fix that does not exist."""
    found = []
    for f in identity.get("findings", []):
        if f["kind"] not in IDENTITY_PATCHABLE:
            continue
        for tool in (f["tools"] or [""]):
            found.append(Finding(f["kind"], tool, f["agent"], f["detail"], source="static"))
    return found
