"""One assessment: attack a target, prove each breach, patch it, verify the fix, seal the evidence.

This is the platform's single entry point. It chains the proven pieces — attack corpus,
proof-based oracle, defender, verifier, signed audit ledger, compliance mapping and (optionally)
the explainer — into one report. It stays domain-agnostic: the target factory, oracle, discovery
profile and the legitimate-behaviour checks are all supplied by the caller.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from purpleteam.adapter import Target
from purpleteam.blast import blast_radius
from purpleteam.attack.corpus import AttackTemplate, CorpusResult, action_objective, build_corpus, run_corpus
from purpleteam.audit.compliance import evidence_report
from purpleteam.audit.ledger import AuditLedger
from purpleteam.defender.selector import Defender, Defense, Finding
from purpleteam.patches.catalog import FINDING_PATCHES
from purpleteam.discovery import TargetProfile
from purpleteam.explainer import Explanation
from purpleteam.focus import plan_focus
from purpleteam.identity import PermissionManifest, check_baseline, check_credentials, drift, inventory, posture
from purpleteam.oracle import CANARY_ACCOUNT, Oracle
from purpleteam.sast import Scanner
from purpleteam.verifier import LegitCheck, VerifyReport, verify

TargetFactory = Callable[[Any], Target]  # guard (or None) -> a fresh target
Explainer = Callable[[Finding, Defense, VerifyReport], Explanation]
Anchorer = Callable[[dict], tuple[dict, list[str]]]  # trust bundle -> (bundle with timestamp anchors, problems)


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

    @property
    def safe_to_ship(self) -> bool:
        return not self.findings or bool(self.verification and self.verification.safe_to_ship)

    def to_dict(self) -> dict:
        verification = None
        if self.verification:
            verification = {**asdict(self.verification), "safe_to_ship": self.verification.safe_to_ship}
        return {
            "target": self.target,
            "scope": self.scope,
            "blast_radius": self.blast,
            "attacks": [{"id": r.id, "technique": r.technique, "breached": r.breached, "detail": r.detail,
                         "evidence": r.evidence, "signals": [asdict(s) for s in r.signals]} for r in self.results],
            "findings": [asdict(f) for f in self.findings],  # asdict already recurses into the signals tuple
            "patches": self.defense.applied if self.defense else [],
            "verification": verification,
            "explanations": [asdict(e) for e in self.explanations],
            "identity": self.identity,
            "baseline_checked": self.baseline_checked,
            "safe_to_ship": self.safe_to_ship,
            "audit": {"merkle_root": self.sealed_root, "chain_ok": self.chain_ok, "trust": self.trust,
                      "anchor_errors": self.anchor_errors},
            "compliance": self.coverage,
        }


class Assessment:
    def __init__(
        self,
        factory: TargetFactory,
        oracle: Oracle,
        profile: TargetProfile,
        ledger: AuditLedger,
        *,
        legit: list[LegitCheck],
        canary: str = CANARY_ACCOUNT,
        facts: dict | None = None,
        explainer: Explainer | None = None,
        anchorer: Anchorer | None = None,
        manifest: PermissionManifest | None = None,
        credentials: dict[str, str] | None = None,
        blast: dict | None = None,
        baseline: dict | None = None,
        scanner: Scanner | None = None,
        repo: str | Path | None = None,
    ) -> None:
        self._factory = factory
        self._oracle = oracle
        self._profile = profile
        self._ledger = ledger
        self._legit = legit
        self._canary = canary
        declared = manifest if manifest is not None else (facts or {}).get("manifest")
        if declared is not None and not isinstance(declared, PermissionManifest):
            raise ValueError("the manifest must be a PermissionManifest")
        self._manifest = declared
        self._facts = {**(facts or {}), **({} if declared is None else {"manifest": declared})}
        self._credentials = None if credentials is None else check_credentials(credentials)  # before any attack runs
        self._explainer = explainer
        self._anchorer = anchorer
        self._blast = blast  # blast_radius options (handoffs, untrusted, used); None leaves blast radius out
        self._baseline = None if baseline is None else check_baseline(baseline)  # what the agents were, to spot drift
        self._scanner = scanner  # optional static-analysis backend (purpleteam.sast); None skips repo analysis
        self._repo = None if repo is None else Path(repo)

    async def run(self, templates: list[AttackTemplate] | None = None, *, focus: list[str] | None = None,
                  agent: str | None = None, disguise_with: list[str] | None = None,
                  place_with: list[str] | None = None) -> AssessmentReport:
        """Attack with ``templates``, or only the chosen ``focus`` topics (optionally one ``agent``), or the default
        corpus. Judge a focused run with ``focus_oracle`` so only the oracles that apply to the topic can call a
        breach. ``disguise_with``/``place_with`` additionally run each template disguised or placed inside cover
        text (see ``attack.corpus.run_corpus``); a breach is verified against the exact variant that caused it,
        disguised or placed form included, never against the plain template alone."""
        scope: dict = {}
        if focus is not None:
            plan = plan_focus(self._profile, focus, agent=agent, secrets=self._facts.get("secrets", ()),
                              manifest=self._manifest)
            templates, scope = plan.templates, {"focus": list(focus), "agent": agent, "skipped": plan.skipped}
        elif templates is None:
            templates = build_corpus(action_objective(self._profile.dangerous_tools))
        results = await run_corpus(self._factory(None), self._oracle, templates, canary=self._canary,
                                   disguise_with=disguise_with, place_with=place_with)
        report = AssessmentReport(self._profile.name, results, scope=scope)
        self._check_identity(report)
        static = self._scan_repo(report)
        self._assess_blast(report, results)
        if scope:  # the evidence says what was not tested, so a narrow run is never read as a clean bill
            self._ledger.append("attacker", "scope", scope)
        self._record_attacks(results)

        breaches = [r for r in results if r.breached]
        if breaches or static:
            self._defend_and_verify(report, breaches, static)
        self._seal(report)
        return report

    def _scan_repo(self, report: AssessmentReport) -> list[Finding]:
        """Static findings from the target's own source (optional; see ``purpleteam.sast``), converted to the
        same Finding type a dynamic breach produces. Logged whether or not anything is found, like identity."""
        if self._scanner is None or self._repo is None:
            return []
        static = self._scanner.scan(self._repo)
        self._ledger.append("scanner", "static", {
            "findings": [{"kind": f.kind, "file": f.file, "line": f.line, "severity": f.severity} for f in static]})
        return [f.as_finding() for f in static]

    def _defend_and_verify(self, report: AssessmentReport, breaches: list[CorpusResult],
                           static: list[Finding] = ()) -> None:
        report.findings = _findings(breaches) + list(static)
        report.defense = Defender(self._profile, self._facts).select_all(report.findings)
        unpatched = sorted({f.kind for f in report.findings
                            if not set(FINDING_PATCHES.get(f.kind, [])) & set(report.defense.patch_ids)})
        patch_event = {"patch_ids": report.defense.patch_ids, "patches": report.defense.applied,
                       "rationale": report.defense.rationale}
        if "P11" in report.defense.patch_ids:  # an inferred manifest only forbids what an agent does not already hold
            patch_event["manifest"] = "declared" if self._manifest is not None else "inferred"
        if unpatched:
            patch_event["unpatched"] = unpatched  # the catalog had nothing that actually got built for these findings
        self._ledger.append("defender", "patch", patch_event)

        payloads = [b.payload for b in breaches]  # the exact text that breached, disguise/placement included
        patched = self._factory(report.defense.guard)
        report.verification = verify(patched, self._oracle, attacks=payloads, legit=self._legit)
        if unpatched:
            report.verification.errored = True
            report.verification.errors.append(f"no patch was built for: {', '.join(unpatched)}")
        self._ledger.append("verifier", "verdict", {
            **asdict(report.verification), "safe_to_ship": report.verification.safe_to_ship})

        if self._explainer:
            report.explanations = [self._explainer(f, report.defense, report.verification)
                                   for f in report.findings]

    def _check_identity(self, report: AssessmentReport) -> None:
        """Every agent's tools and permissions, checked against its declared manifest and its baseline (if any).
        Logged whether or not anything is wrong: a clean result needs a signed record as much as a finding does,
        or "the agents matched their mandated scope" could never be more than an unproven assertion."""
        findings = posture(self._profile, self._manifest, self._credentials)
        if self._baseline is not None:
            findings += drift(self._profile, self._baseline)
        report.identity = inventory(self._profile, self._manifest, findings, self._credentials)
        report.baseline_checked = self._baseline is not None
        self._ledger.append("identity", "identity", {
            "agents": len(report.identity["agents"]),
            "manifest": report.identity["manifest"],  # declared | none (see identity.inventory)
            "baseline_checked": self._baseline is not None,
            "clean": not findings,
            "findings": [{"kind": f.kind, "agent": f.agent, "tools": list(f.tools), "severity": f.severity}
                         for f in findings]})

    def _assess_blast(self, report: AssessmentReport, results: list[CorpusResult]) -> None:
        """How far a compromised agent could go, with the chains this run's breaches already demonstrate marked as such."""
        if self._blast is None:
            return
        proven = [(r.agent, r.tool) for r in results if r.breached and r.tool]
        radius = blast_radius(self._profile, manifest=self._manifest, credentials=self._credentials, proven=proven,
                              **self._blast)
        report.blast = radius.to_dict()
        self._ledger.append("identity", "blast_radius", {
            "agents": [{"agent": a["agent"], "score": a["score"], "reach": a["reach"]} for a in report.blast["agents"]],
            "chains": [{"kind": c["kind"], "severity": c["severity"], "status": c["status"], "agents": c["agents"]}
                       for c in report.blast["chains"]],
            "assumptions": report.blast["assumptions"]})

    def _record_attacks(self, results: list[CorpusResult]) -> None:
        for r in results:
            self._ledger.append("attacker", "attack", {"id": r.id, "technique": r.technique})
            if r.breached:
                payload = {"id": r.id, "kind": r.kind, "tool": r.tool, "agent": r.agent,
                           "proof": r.detail, "evidence": r.evidence}
                if r.signals:
                    payload["signals"] = [{"scorer": s.scorer, "pattern": s.pattern, "where": s.where}
                                          for s in r.signals]
                self._ledger.append("oracle", "breach", payload)

    def _seal(self, report: AssessmentReport) -> None:
        report.sealed_root = self._ledger.seal()
        self._ledger.append("audit", "seal", {"merkle_root": report.sealed_root})
        report.chain_ok = self._ledger.verify().ok
        report.trust = self._ledger.export_trust()
        if self._anchorer:  # best effort: sealing never waits on, or fails because of, an outside service
            try:
                report.trust, report.anchor_errors = self._anchorer(report.trust)
            except Exception as error:  # the anchorer is caller-supplied code on a network boundary
                report.anchor_errors = [f"{type(error).__name__}: {error}"]
        report.coverage = {
            clause: {"description": entry["control"].description, "events": entry["events"]}
            for clause, entry in evidence_report(self._ledger.events()).items()
        }


def _findings(breaches: list[CorpusResult]) -> list[Finding]:
    """One finding per distinct (kind, tool, agent); several attacks through one hole are one hole. Signal
    evidence (never the breach verdict itself) is pooled across every attack that found the same hole."""
    signals: dict[tuple, dict] = {}
    for r in breaches:
        key = (r.kind, r.tool, r.agent)
        pool = signals.setdefault(key, {})
        for s in r.signals:
            pool[(s.scorer, s.pattern, s.where)] = s
    unique: dict[tuple, Finding] = {}
    for r in breaches:
        key = (r.kind, r.tool, r.agent)
        unique.setdefault(key, Finding(r.kind, r.tool, r.agent, r.detail, tuple(signals[key].values())))
    return list(unique.values())
