"""One assessment: attack a target, prove each breach, patch it, verify the fix, seal the evidence.

This is the platform's single entry point. It chains the proven pieces — attack corpus,
proof-based oracle, defender, verifier, signed audit ledger, compliance mapping and (optionally)
the explainer — into one report. Domain-agnostic: the target factory, oracle, discovery profile
and legitimate-behaviour checks are all supplied by the caller.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from purpleteam.adapter import Target
from purpleteam.blast import blast_radius
from purpleteam.attack.corpus import AttackTemplate, CorpusResult, action_objective, build_corpus, run_corpus
from purpleteam.attack.outcome import INCONCLUSIVE
from purpleteam.attack.regressions import load_regressions, record_breaches, retest_against
from purpleteam.audit.compliance import evidence_report
from purpleteam.audit.ledger import AuditLedger
from purpleteam.defender.selector import Defender, Defense, Finding, findings_from_breaches
from purpleteam.patches.catalog import missing_patches
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
        """False whenever no attack ran, any one was inconclusive, or the audit chain itself does
        not verify — even with zero findings: proving nothing, or on evidence that cannot be
        trusted, is not the same as proving safety (the same reason ``run`` never lets a narrow
        scope's ledger entry read as a clean bill)."""
        if not self.results or any(r.outcome == INCONCLUSIVE for r in self.results) or not self.chain_ok:
            return False
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
        regressions: str | Path | None = None,
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
        self._regressions = None if regressions is None else Path(regressions)  # see attack.regressions

    async def run(self, templates: list[AttackTemplate] | None = None, *, focus: list[str] | None = None,
                  agent: str | None = None, disguise_with: list[str] | None = None,
                  place_with: list[str] | None = None, timeout: float | None = 120) -> AssessmentReport:
        """Attack with ``templates``, or only the chosen ``focus`` topics (optionally one ``agent``), or the default
        corpus. Judge a focused run with ``focus_oracle`` so only the oracles that apply to the topic can call a
        breach. ``disguise_with``/``place_with`` additionally run each template disguised or placed inside cover
        text; a breach is verified against the exact variant that caused it, never the plain template alone.
        ``timeout`` bounds each attempt — raise it for a slow-but-honest target rather than poison the run."""
        scope: dict = {}
        if focus is not None:
            plan = plan_focus(self._profile, focus, agent=agent, secrets=self._facts.get("secrets", ()),
                              manifest=self._manifest)
            templates, scope = plan.templates, {"focus": list(focus), "agent": agent, "skipped": plan.skipped}
        elif templates is None:
            templates = build_corpus(action_objective(self._profile.dangerous_tools))
            scope = {"corpus": "default", "templates": [t.id for t in templates],
                     "not_run": "adaptive (PAIR/TAP) search and disguise/placement variants were not run — "
                               "pass disguise_with/place_with, or see purpleteam.attack.adaptive, to add them"}
        results = await run_corpus(self._factory(None), self._oracle, templates, canary=self._canary,
                                   disguise_with=disguise_with, place_with=place_with, timeout=timeout)
        report = AssessmentReport(self._profile.name, results, scope=scope)
        self._check_identity(report)
        static = self._scan_repo(report)
        identity_findings = _identity_findings(report.identity)
        self._assess_blast(report, results)
        if scope:  # the evidence says what was not tested, so a narrow run is never read as a clean bill
            self._ledger.append("attacker", "scope", scope)
        self._record_attacks(results)

        breaches = [r for r in results if r.breached]
        all_breaches = breaches + self._regression_breaches()
        if all_breaches or static or identity_findings:
            self._defend_and_verify(report, all_breaches, static, identity_findings)
            record_breaches(self._regressions, breaches)  # only this run's own, new breaches
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
                           static: list[Finding] = (), identity_findings: list[Finding] = ()) -> None:
        report.findings = findings_from_breaches(breaches) + list(static) + list(identity_findings)
        report.defense = Defender(self._profile, self._facts).select_all(report.findings)
        applied = set(report.defense.patch_ids)
        gaps = {kind: missing for kind in sorted({f.kind for f in report.findings})
               if (missing := missing_patches(kind, applied))}
        patch_event = {"patch_ids": report.defense.patch_ids, "patches": report.defense.applied,
                       "rationale": report.defense.rationale}
        if "P11" in report.defense.patch_ids:  # an inferred manifest only forbids what an agent does not already hold
            patch_event["manifest"] = "declared" if self._manifest is not None else "inferred"
        if gaps:
            patch_event["unpatched"] = sorted(gaps)  # the kind
            patch_event["unpatched_detail"] = gaps  # kind -> exactly which recommended patch ids did not apply
        self._ledger.append("defender", "patch", patch_event)

        payloads = self._verification_attacks(breaches)
        patched = self._factory(report.defense.guard)
        report.verification = verify(patched, self._oracle, attacks=payloads, legit=self._legit)
        if gaps:
            report.verification.errored = True
            report.verification.errors.extend(f"{kind}: {', '.join(missing)}" for kind, missing in gaps.items())
        if report.defense.mode == "production" and not self._facts.get("approved"):
            report.verification.errored = True
            report.verification.errors.append(
                "production-mode defense needs explicit human approval before it can ship "
                "(set facts['approved']=True once reviewed)")
        self._ledger.append("verifier", "verdict", {
            **asdict(report.verification), "safe_to_ship": report.verification.safe_to_ship})

        if self._explainer:
            report.explanations = [self._explainer(f, report.defense, report.verification)
                                   for f in report.findings]

    def _regression_breaches(self) -> list[CorpusResult]:
        """Every exploit proven earlier, re-tested before being treated as a breach. [] without ``regressions=``."""
        cases = load_regressions(self._regressions)
        if not cases:
            return []
        breaches, log = retest_against(cases, self._factory(None), self._oracle)
        self._ledger.append("attacker", "regressions_retested", {"results": log})
        return breaches

    def _verification_attacks(self, breaches: list[CorpusResult]) -> list[str]:
        """Every distinct payload among ``breaches`` — a regression case can coincide with a fresh breach."""
        seen, payloads = set(), []
        for b in breaches:
            if b.payload and b.payload not in seen:
                seen.add(b.payload)
                payloads.append(b.payload)
        return payloads

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


_IDENTITY_PATCHABLE = {"excess_privilege", "undeclared_agent", "unscoped_execution"}


def _identity_findings(identity: dict) -> list[Finding]:
    """Structural identity findings the catalog can answer (excess_privilege, undeclared_agent,
    unscoped_execution) feed into the same Defender pipeline a breach does. Every other kind
    (shared_credential, a prompt or model change...) has no sensible runtime guard and stays
    report-only: claiming a patch for those would assert a fix that does not exist."""
    found = []
    for f in identity.get("findings", []):
        if f["kind"] not in _IDENTITY_PATCHABLE:
            continue
        for tool in (f["tools"] or [""]):
            found.append(Finding(f["kind"], tool, f["agent"], f["detail"], source="static"))
    return found
