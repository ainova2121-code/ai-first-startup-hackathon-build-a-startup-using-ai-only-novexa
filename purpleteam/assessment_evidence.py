"""The evidence an assessment gathers around its attacks: the static scan and the verified source fixes it
leads to, identity posture, blast radius, re-tested regressions, every attack and breach in the signed ledger,
and the seal. A mixin of ``purpleteam.assessment.Assessment``, whose constructor sets every ``self._``
attribute used here."""

from __future__ import annotations

import asyncio
from typing import Callable

from purpleteam.adapter import Observation
from purpleteam.assessment_report import AssessmentReport
from purpleteam.attack.corpus import CorpusResult
from purpleteam.attack.regressions import load_regressions, retest_against
from purpleteam.audit.compliance import evidence_report
from purpleteam.blast import blast_radius
from purpleteam.defender.selector import Defender, Finding, findings_from_breaches
from purpleteam.explainer import Explanation
from purpleteam.gate_scan import GATE_KIND, GATE_TAG
from purpleteam.hardening_scan import HARDENING_KINDS
from purpleteam.identity import drift, inventory, posture
from purpleteam.sast import ScanFailed, StaticFinding, unscanned_sources
from purpleteam.source_fix import SourceFixResult, display, fix_sources

# Fixed only for what actually breached: hardening a prompt or gating a tool legitimate work relies on would change
# that work, so only proven ones are touched. Code vulnerabilities (SQL...) are always fixed.
SCOPED_KINDS = HARDENING_KINDS | {GATE_KIND}


def _same_work(still_works: Callable[[Observation], bool], expected: set[tuple[str, str]]
               ) -> Callable[[Observation], bool]:
    """``still_works``, and every (agent, tool) in ``expected`` ran for real again (not an approval-gate stub)."""
    def check(observation: Observation) -> bool:
        done = {(c.agent, c.tool) for c in observation.tool_calls if GATE_TAG not in str(c.result or "")}
        return still_works(observation) and expected <= done
    return check


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
        """Edit the target's real files for what the scan found (``purpleteam.source_fix``). Nothing is loaded
        here: ``_load_fixes`` reloads the target once every fix is written, so an attack still running meets the
        target as it was. A dynamic attack finding alone never reaches here: it is answered by a runtime guard."""
        if not static or self._codemod_catalog is None or self._repo is None or self._scanner is None:
            return SourceFixResult()
        # A source-level approval gate turns its tool into a stub: on a tool legitimate work runs, it stops that work
        # by design. Those breaches are left to the runtime guard, which holds only the planted values.
        held_back = [f for f in static if f.kind == GATE_KIND and f.subject in self._legit_tools]
        result = await fix_sources([f for f in static if f not in held_back], self._repo, self._scanner,
                                   self._codemod_catalog, complete=self._codemod_complete, snapshots=self._snapshots,
                                   ledger=self._ledger, emit=emit)
        for finding in held_back:
            skip = {"kind": finding.kind, "path": display(self._repo, finding.file), "line": finding.line,
                    "reason": f"legitimate work runs {finding.subject}: a source-level gate would stop it, so the "
                              "runtime guard answers this breach instead"}
            result.skipped.append(skip)
            self._ledger.append("defender", "source_patch_skipped", skip)
            emit({"type": "source_patch_skipped", **skip})
        return result

    def _start_fixing(self, breach: CorpusResult, scan_task: asyncio.Task, fixing: dict,
                      emit: Callable[[dict], None]) -> None:
        """The moment a breach is proven: name the runtime patches the defender selects for it, and start writing
        the code fixes for everything it reached. Nothing is loaded until the last attack (``_load_fixes``), so every
        attack still meets the target as it was."""
        patch_ids = Defender(self._profile, self._facts).select_all(findings_from_breaches([breach])).patch_ids
        emit({"type": "finding_detected", "id": breach.id, "kind": breach.kind, "agent": breach.agent,
              "tool": breach.tool, "patch_ids": patch_ids})
        subjects = {s for pair in ((breach.agent, breach.tool), *breach.breached_tools) for s in pair if s}
        fixing["tasks"].append(asyncio.ensure_future(self._fix_breached(subjects, scan_task, fixing, emit)))

    async def _fix_breached(self, subjects: set[str], scan_task: asyncio.Task, fixing: dict,
                            emit: Callable[[dict], None]) -> None:
        static_raw, _ = await scan_task
        async with fixing["lock"]:  # one writer at a time: two breaches can reach the same file
            todo = [f for f in static_raw if (f.kind not in SCOPED_KINDS or f.subject in subjects)
                    and (f.kind, f.file, f.line) not in fixing["done"]]
            fixing["done"].update((f.kind, f.file, f.line) for f in todo)
            if todo:
                fixing["results"].append(await self._fix_sources(todo, emit))

    def _load_fixes(self, results: list[SourceFixResult], emit: Callable[[dict], None]) -> SourceFixResult:
        """Every fix written this run, as one result, and the target reloaded once -- after the last attack, before
        any defense is applied or re-attack runs -- so the replay and the legit checks import the edited bytes and a
        stale import is never counted as source verification."""
        merged = SourceFixResult()
        for result in results:
            merged.changes += result.changes
            merged.skipped += result.skipped
            merged.resolved |= result.resolved
        if merged.changes and self._reload_target is not None:
            try:
                self._reload_target()
            except Exception as exc:
                raise RuntimeError("target source reload failed; refusing to treat reverification as proof") from exc
            emit({"type": "target_reloaded", "files": sorted({change["path"] for change in merged.changes})})
        return merged

    def _take_legit_baseline(self) -> None:
        """What each legitimate request really does before any defense or source fix. The side-effecting calls it
        makes become part of its check -- once defended, the same agents must still make them, and they must
        really run: not stopped by a guard, held, or answered by an approval-gate stub -- so a fix that silently
        stops legitimate work can never pass as one that keeps it. A request whose baseline did not pass its own
        check keeps only that check: there is nothing reliable to compare against. A request the caller already sent to
        the unpatched target (``legit_seen``) is not sent again."""
        checks = []
        for request, still_works in self._legit:
            try:
                baseline = self._legit_seen.get(request)
                if baseline is None:
                    target = self._factory(None)
                    target.reset()
                    baseline = target.send(request)
                works = still_works(baseline)
            except Exception:  # an unavailable target is judged by the verifier's own legit check later
                baseline, works = None, False
            if not works:
                checks.append((request, still_works))
                continue
            expected = {(c.agent, c.tool) for c in baseline.tool_calls if c.tool in self._profile.dangerous_tools}
            self._legit_tools |= {tool for _, tool in expected}
            checks.append((request, _same_work(still_works, expected)))
        self._legit = checks

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
            if len(r.breached_tools) > 1:  # the planted value travelled on: every tool it reached is on the record
                payload["reached"] = [{"agent": agent, "tool": tool} for agent, tool in r.breached_tools]
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

    def _source_gaps(self, static_raw: list[StaticFinding], source_fix: SourceFixResult) -> tuple[list[str], list[str]]:
        """(unfixed findings that block a release, unfixed low-severity ones reported as advisory)."""
        def where(f: StaticFinding) -> str:
            return f"{f.kind} at {display(self._repo, f.file) if self._repo else f.file}:{f.line}"

        unresolved = [f for f in static_raw if (f.kind, f.file, f.line) not in source_fix.resolved]
        return ([f"{where(f)}: no verified source fix applied" for f in unresolved if f.blocking],
                [f"{where(f)} ({f.severity} severity, advisory)" for f in unresolved if not f.blocking])

    def _explain(self, finding: Finding, report: AssessmentReport) -> Explanation:
        try:
            return self._explainer(finding, report.defense, report.verification)
        except Exception as error:  # a model or network failure costs this explanation, never the run
            return Explanation(facts={}, text="", verified=False,
                               issues=[f"explanation unavailable ({type(error).__name__})"])

    def _verification_attacks(self, breaches: list[CorpusResult]) -> list[str]:
        """Every distinct payload among ``breaches`` — a regression case can coincide with a fresh breach."""
        seen, payloads = set(), []
        for b in breaches:
            if b.payload and b.payload not in seen:
                seen.add(b.payload)
                payloads.append(b.payload)
        return payloads
