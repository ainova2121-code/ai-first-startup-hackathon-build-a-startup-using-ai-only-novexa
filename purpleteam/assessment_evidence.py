"""The evidence an assessment gathers around its attacks: the static scan and the verified source fixes it
leads to, identity posture, blast radius, re-tested regressions, every attack and breach in the signed ledger,
and the seal. A mixin of ``purpleteam.assessment.Assessment``, whose constructor sets every ``self._``
attribute used here."""

from __future__ import annotations

from typing import Callable

from purpleteam.assessment_report import AssessmentReport
from purpleteam.attack.corpus import CorpusResult
from purpleteam.attack.regressions import load_regressions, retest_against
from purpleteam.audit.compliance import evidence_report
from purpleteam.blast import blast_radius
from purpleteam.identity import drift, inventory, posture
from purpleteam.sast import ScanFailed, StaticFinding, unscanned_sources
from purpleteam.source_fix import SourceFixResult, fix_sources


class EvidencePass:
    def _scan(self) -> tuple[list[StaticFinding], list[str]]:
        """Static findings from the target's own source (optional; see ``purpleteam.sast``), and what
        the scan could not cover: a scan that failed, or source in a language the scanner does not read
        (checked when the scanner declares its ``languages``)."""
        if self._scanner is None or self._repo is None:
            return [], []
        gaps: list[str] = []
        try:
            findings = self._scanner.scan(self._repo)
        except ScanFailed as error:
            findings, gaps = [], [f"the static scan did not complete: {error}"]
        languages = getattr(self._scanner, "languages", None)
        unread = unscanned_sources(self._repo, languages) if languages is not None else {}
        if unread:
            files = ", ".join(f"{count} {suffix}" for suffix, count in sorted(unread.items()))
            gaps.append(f"source no configured scanner reads was not statically checked ({files} files)")
        return findings, gaps

    def _log_scan(self, static: list[StaticFinding], gaps: list[str]) -> None:
        """Logged whether or not anything is found, like identity -- whenever a scan ran at all."""
        if self._scanner is not None and self._repo is not None:
            self._ledger.append("scanner", "static", {
                "findings": [{"kind": f.kind, "file": f.file, "line": f.line, "severity": f.severity} for f in static],
                "gaps": gaps})

    async def _fix_sources(self, static: list[StaticFinding], emit: Callable[[dict], None]) -> SourceFixResult:
        """Edit the target's real files for what the scan found (``purpleteam.source_fix``), then reload it
        once -- here, after the patch is written and before any defense is applied or re-attack runs -- so
        everything after (the replay and the legit checks) imports the edited bytes and a stale import is
        never counted as source verification. A dynamic attack finding alone never reaches here: it is
        answered by a runtime guard."""
        if not static or self._codemod_catalog is None or self._repo is None or self._scanner is None:
            return SourceFixResult()
        result = await fix_sources(static, self._repo, self._scanner, self._codemod_catalog,
                                   complete=self._codemod_complete, snapshots=self._snapshots,
                                   ledger=self._ledger, emit=emit)
        if result.changes and self._reload_target is not None:
            try:
                self._reload_target()
            except Exception as exc:
                raise RuntimeError("target source reload failed; refusing to treat reverification as proof") from exc
            emit({"type": "target_reloaded", "files": sorted({change["path"] for change in result.changes})})
        return result

    def _regression_breaches(self) -> list[CorpusResult]:
        """Every exploit proven earlier, re-tested before being treated as a breach. [] without ``regressions=``."""
        cases = load_regressions(self._regressions)
        if not cases:
            return []
        breaches, log = retest_against(cases, self._factory(None), self._oracle)
        self._ledger.append("attacker", "regressions_retested", {"results": log})
        return breaches

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

    def _record_attack(self, r: CorpusResult) -> None:
        self._ledger.append("attacker", "attack", {"id": r.id, "technique": r.technique})
        if r.breached:
            payload = {"id": r.id, "kind": r.kind, "tool": r.tool, "agent": r.agent,
                       "proof": r.detail, "evidence": r.evidence}
            if r.signals:
                payload["signals"] = [{"scorer": s.scorer, "pattern": s.pattern, "where": s.where}
                                      for s in r.signals]
            self._ledger.append("oracle", "breach", payload)
        elif r.persuaded:  # held, but only because a control caught what the agent tried: evidence in its own right
            self._ledger.append("oracle", "attempt", {"id": r.id, "persuaded": r.persuaded, "proof": r.detail})

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
