"""The defend-and-verify pass of an assessment: build the defense for every finding, check legitimate work
first, narrow and escalate only on proof, re-attack with every breaching payload, pin each verified decision,
and record the verdict. A mixin of ``purpleteam.assessment.Assessment``, whose constructor sets every
``self._`` attribute used here."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import Callable

from purpleteam.assessment_report import AssessmentReport, patch_scopes
from purpleteam.attack.corpus import CorpusResult
from purpleteam.concurrency import parallel_map
from purpleteam.decisions import ATTACK, LEGIT, DecisionRecorder, ProbeLog, compare, decide, summarize, take_baseline
from purpleteam.defender.policy import policy_data
from purpleteam.defender.selector import ESCALATIONS, Defender, Finding, findings_from_breaches
from purpleteam.explainer import Explanation
from purpleteam.patches.base import CompositeGuard
from purpleteam.patches.catalog import missing_patches
from purpleteam.sast import StaticFinding
from purpleteam.source_fix import SourceFixResult, display
from purpleteam.run_control import RunControl, RunStopped
from purpleteam.verifier import Replay, verify


class _ControlledTarget:
    """Cooperative gate around verifier probes so pause/stop also applies during re-attacks."""

    def __init__(self, target, control: RunControl) -> None:
        self._target, self._control = target, control

    def reset(self) -> None:
        if not self._control.checkpoint():
            raise RunStopped("run stopped before verifier reset")
        self._target.reset()

    def send(self, text: str):
        if not self._control.checkpoint():
            raise RunStopped("run stopped before verifier request")
        return self._target.send(text)


class DefensePass:
    def _defend_and_verify(self, report: AssessmentReport, breaches: list[CorpusResult],
                           static: list[Finding] = (), identity_findings: list[Finding] = (),
                           emit: Callable[[dict], None] = lambda payload: None, *,
                           source_fix: SourceFixResult | None = None,
                           static_raw: list[StaticFinding] = (), record_decisions: bool = False,
                           control: RunControl | None = None) -> None:
        report.findings = findings_from_breaches(breaches) + list(static) + list(identity_findings)
        source_fix = source_fix or SourceFixResult()
        source_gaps, advisories = self._source_gaps(static_raw, source_fix)
        payloads = self._verification_attacks(breaches)
        origins = {b.payload: b.id for b in reversed(breaches) if b.payload}  # each payload's first breach
        # Each payload is re-tested against the one breach it caused, so a re-attack that wanders into a
        # different hole is never credited as proof the original was fixed (see verifier.verify ``scopes``).
        # A breach that spread is re-tested against every tool it reached: the canary arriving at any of them again is
        # the same breach recurring, not a different hole.
        scope_by_payload = {b.payload: frozenset((b.kind, tool, agent) for agent, tool in b.breached_tools)
                            or (b.kind, b.tool, b.agent) for b in reversed(breaches) if b.payload}

        def attempt(level: int, excluded: frozenset[str], legit_only: bool = False) -> tuple[dict, ProbeLog, set[str]]:
            gaps = self._apply_defense(report, level, source_fix, source_gaps, emit, advisories, excluded,
                                       announce=not legit_only)  # a legit-only probe is not a verdict pass
            # The edited bytes were already loaded once by _fix_sources, before any defense or replay ran, so
            # every target this re-attack builds imports them. No reload here: a stale-import replay can never
            # be counted as source verification because the original bytes are no longer importable.
            attacks = [] if legit_only else [(origins.get(p, ""), p) for p in payloads]
            scopes = None if legit_only else [scope_by_payload.get(p) for p in payloads]
            probes = self._replay(report, attacks, emit, scopes=scopes, control=control)
            return gaps, probes, self._legit_impact(report, probes, level, excluded, emit)

        def narrow(excluded: frozenset[str], where: str) -> None:
            note = {"excluded": sorted(excluded), "reason": f"blocked legitimate work in {where}"}
            self._ledger.append("defender", "narrow", note)
            emit({"type": "defense_narrowing", **note})

        # Escalate only on proof: a level is tightened only after its own replays showed the attack still
        # getting through. Narrow only on proof too: a patch shown blocking legitimate work is dropped once,
        # and the narrower defense is kept only if the attack is still proven blocked without it. Legitimate
        # work is checked alone first, so a patch that breaks it is dropped before the attacks are replayed
        # rather than after: one replay pass instead of two.
        level, excluded, narrowed = 0, frozenset(), False
        if payloads and self._legit:
            culprits = attempt(level, excluded, legit_only=True)[2]
            if control is not None and control.stop_requested:
                return
            if culprits:
                narrowed, excluded = True, frozenset(culprits)
                narrow(excluded, "a legit check, before any replay")
        while True:
            gaps, probes, culprits = attempt(level, excluded)
            if control is not None and control.stop_requested:
                return
            if excluded and not report.verification.attack_blocked:  # the narrower defense let an attack through:
                excluded = frozenset()  # keep the one that holds, broken legit and all
                continue
            if report.verification.attack_blocked and culprits and not narrowed:
                narrowed, trial = True, excluded | culprits
                narrow(trial, "a verified replay")
                gaps, probes, culprits = attempt(level, trial)
                if report.verification.attack_blocked:
                    excluded = trial
                else:  # the narrower defense let the attack through: keep the one that holds, broken legit and all
                    gaps, probes, culprits = attempt(level, excluded)
                break
            if report.verification.attack_blocked or not payloads or level == len(ESCALATIONS) - 1:
                break
            level += 1
        report.escalation, report.excluded = level, excluded
        if record_decisions and not (control and control.stop_requested):  # only a completed authoritative pass is pinned
            self._record_decisions(report, probes, emit)
        self._finish_verdict(report, source_fix, gaps, source_gaps, emit, final=record_decisions)

    def _legit_impact(self, report: AssessmentReport, probes: ProbeLog, level: int, excluded: frozenset[str],
                      emit: Callable[[dict], None]) -> set[str]:
        """What the defense did to legitimate work in this replay. A decision it blocked means legitimate work
        is broken, whatever the legit check's own reply looked like; one held for review is disclosed as an
        impact. Returns the patches that blocked legitimate work."""
        fresh = Defender(self._profile, self._facts, escalation=level, exclude=excluded).select_all(report.findings).guard
        blocked, held, culprits = [], [], set()
        for probe, was_held in probes.stopped(LEGIT):
            by = decide(fresh, probe)[1]  # a fresh copy names the patch without touching live review state
            where = f"{probe.agent} · {probe.tool or probe.source} ({by or 'guard'})"
            (held if was_held else blocked).append(where)
            if not was_held and by:
                culprits.add(by)
        if blocked:
            report.verification.legit_passed = False
            report.verification.failures.append(f"the defense blocked legitimate work: {'; '.join(blocked)}")
        report.impacts = [f"legitimate work now waits for human review at {place}" for place in held]
        if blocked or held:
            emit({"type": "legit_impact", "blocked": blocked, "held": held})
        return culprits

    def _record_decisions(self, report: AssessmentReport, probes: ProbeLog, emit: Callable[[dict], None]) -> None:
        """Pin every decision the verified defense made, and -- against an earlier approved baseline -- every
        decision this policy would now make differently. Ledger entries hold counts and keys, never inputs."""
        def factory():  # a fresh copy of exactly the verified policy, so no probe sees another's state
            return Defender(self._profile, self._facts, escalation=report.escalation,
                            exclude=report.excluded).select_all(report.findings).guard

        report.decisions = take_baseline(probes, factory, sorted([e["id"], e["hash"]] for e in report.defense.applied))
        try:
            report.policy = policy_data(report.findings, self._profile, self._facts, escalation=report.escalation,
                                        exclude=report.excluded)
        except ValueError:  # known secrets need an operator key to be stored at all; never kept in plaintext
            report.policy = {}
        origins = Counter(origin for entry in report.decisions["probes"] for origin in entry["origins"])
        pinned = {"probes": len(report.decisions["probes"]), "dropped": report.decisions["dropped"],
                  "digest": report.decisions["digest"], "origins": dict(origins)}
        self._ledger.append("verifier", "decision_baseline", pinned)
        emit({"type": "decision_baseline", **pinned})
        if self._decision_baseline is not None:
            self._compare_decisions(report, factory, emit)

    def _compare_decisions(self, report: AssessmentReport, factory: Callable[[], CompositeGuard],
                           emit: Callable[[dict], None]) -> None:
        report.decision_drift = compare(self._decision_baseline, factory)
        counts = summarize(report.decision_drift)
        self._ledger.append("verifier", "decision_drift", {
            "against": self._decision_baseline["digest"], **counts,
            "flips": [{k: f[k] for k in ("key", "check", "agent", "tool", "origins", "before", "after", "by_before",
                                         "by_after", "severity")} for f in report.decision_drift]})
        emit({"type": "decision_drift", "against": self._decision_baseline["digest"],
              "against_run": self._decision_baseline.get("run"), "counts": counts,
              "compared": len(self._decision_baseline["probes"]), "flips": report.decision_drift})

    def _source_gaps(self, static_raw: list[StaticFinding], source_fix: SourceFixResult) -> tuple[list[str], list[str]]:
        """(unfixed findings that block a release, unfixed low-severity ones reported as advisory)."""
        def where(f: StaticFinding) -> str:
            return f"{f.kind} at {display(self._repo, f.file) if self._repo else f.file}:{f.line}"

        unresolved = [f for f in static_raw if (f.kind, f.file, f.line) not in source_fix.resolved]
        return ([f"{where(f)}: no verified source fix applied" for f in unresolved if f.blocking],
                [f"{where(f)} ({f.severity} severity, advisory)" for f in unresolved if not f.blocking])

    def _apply_defense(self, report: AssessmentReport, level: int, source_fix: SourceFixResult,
                       source_gaps: list[str], emit: Callable[[dict], None], advisories: list[str] = (),
                       excluded: frozenset[str] = frozenset(), announce: bool = True) -> dict:
        """Build and attach the defense; ``announce=False`` for a probe of it that is not itself a verdict pass."""
        report.defense = Defender(self._profile, self._facts, review_queue=self._review_queue,
                                  escalation=level, exclude=excluded).select_all(report.findings)
        # A patch left out because it was proven to break legitimate work is not a gap: the verifier must
        # still prove the attack held without it, or the narrower defense is not kept.
        applied = set(report.defense.patch_ids) | excluded
        # Runtime guards answer findings that name a tool; a source-level finding names a line, resolved only by a
        # real edit (handled by source_gaps), never by a guard on tool "". A dynamic breach tied to no tool can be
        # scoped by no guard either, so unless something global covers its kind it is an unresolved gap too -- an
        # unpatched breach must never pass as "held" and ship.
        gaps: dict[str, list[str]] = {}
        for finding in report.findings:
            if not (finding.tool or finding.source == "dynamic"):
                continue
            if missing := missing_patches(finding.kind, applied, has_tool=bool(finding.tool)):
                gaps[finding.kind] = missing
        patch_event = {"patch_ids": report.defense.patch_ids, "patches": report.defense.applied,
                       "rationale": report.defense.rationale, "escalation": level, "escalation_note": ESCALATIONS[level],
                       "scopes": patch_scopes(report.findings, report.defense.patch_ids),
                       "source_changes": [{key: change[key] for key in ("kind", "path", "line", "sha256",
                                                                         "verified_by", "approval")}
                                          for change in source_fix.changes],
                       "source_gaps": source_gaps, "advisories": list(advisories), "excluded": sorted(excluded)}
        if "P11" in report.defense.patch_ids:  # an inferred manifest only forbids what an agent does not already hold
            patch_event["manifest"] = "declared" if self._manifest is not None else "inferred"
        if gaps:
            patch_event["unpatched"] = sorted(gaps)  # the kind
            patch_event["unpatched_detail"] = gaps  # kind -> exactly which recommended patch ids did not apply
        if announce:
            self._ledger.append("defender", "patch", patch_event)  # paths and hashes only, never source text
            emit({"type": "patch_applied", **patch_event})
        return gaps

    def _replay(self, report: AssessmentReport, attacks: list[tuple[str, str]],
                emit: Callable[[dict], None], *, scopes: list[tuple[str, str, str]] | None = None,
                control: RunControl | None = None) -> ProbeLog:
        """Re-send each (breaching attack id, payload) against the patched agent; each event names the attack.
        ``scopes`` re-tests each payload against its own original breach (see verifier.verify)."""
        payloads = [payload for _, payload in attacks]

        def _replays(result_id: str) -> str:  # "reverify:<n>" is the n-th attack, counted from 1
            return attacks[int(result_id.rsplit(":", 1)[1]) - 1][0]

        def _on_reverify_start(result_id: str, payload: str) -> None:
            emit({"type": "attack_start", "id": result_id, "payload": payload, "technique": "reverify",
                  "replays": _replays(result_id)})

        def _on_reverify_result(replay: Replay) -> None:
            emit({"type": "attack_result", "id": replay.id, "technique": "reverify", "replays": _replays(replay.id),
                  "breached": not replay.blocked,
                 "outcome": "held" if replay.blocked else "breached",
                 "detail": f"the exact payload that breached, re-sent {replay.trials}x against the patched "
                           f"agent — the original breach held {replay.held} of {replay.trials}"
                           + (f"; still breached: {replay.proof}" if replay.proof else "")
                           + (f"; a different breach appeared: {replay.off_scope_proof}" if replay.off_scope else "")
                           + (f"; in {replay.persuaded} {replay.persuasion}" if replay.persuaded else ""),
                 "kind": "", "tool": "", "agent": "", "upper_bound": replay.upper_bound, "trials": replay.trials,
                 "conclusive": replay.trials, "seconds": replay.seconds, "reply": replay.reply,
                 "off_scope": replay.off_scope, "persuaded": replay.persuaded})

        guard, probes = report.defense.guard, ProbeLog()

        def controlled(factory):
            if control is None:
                return factory
            return lambda: _ControlledTarget(factory(), control)

        # Each replay and legit check on its own fresh, identically-patched copy, so they run in parallel;
        # each copy's guard records the inputs of every decision it makes (purpleteam.decisions).
        report.verification = verify(None, self._oracle, attacks=payloads, legit=self._legit,
                                     trials=self._verify_trials, max_residual=self._max_residual,
                                     on_attack_start=_on_reverify_start, on_attack_result=_on_reverify_result,
                                     factory=controlled(lambda: self._factory(DecisionRecorder(guard, probes, ATTACK))),
                                     legit_factory=controlled(lambda: self._factory(DecisionRecorder(guard, probes, LEGIT))))
        return probes

    def _finish_verdict(self, report: AssessmentReport, source_fix: SourceFixResult, gaps: dict,
                        source_gaps: list[str], emit: Callable[[dict], None], *, final: bool = False) -> None:
        if source_fix.changes and self._reload_target is None:
            report.verification.errored = True
            report.verification.errors.append(
                "a source file was edited, but this run could not reload the edited target, so the replay "
                "and legit checks ran against the old code")
        if gaps or source_gaps:
            report.verification.errored = True
            report.verification.errors.extend(f"{kind}: {', '.join(missing)}" for kind, missing in gaps.items())
            report.verification.errors.extend(source_gaps)
        loosened = summarize(report.decision_drift)["high"]
        if loosened:
            report.verification.errored = True
            report.verification.errors.append(
                f"policy-decision drift: {loosened} approved decision(s) on verified attack input "
                "(or redaction) would be looser under this run's policy")
        if report.defense.mode == "production" and not self._facts.get("approved"):
            report.verification.errored = True
            report.verification.errors.append(
                "production-mode defense needs explicit human approval before it can ship "
                "(set facts['approved']=True once reviewed)")
        self._ledger.append("verifier", "verdict", {
            **asdict(report.verification), "safe_to_ship": report.verification.safe_to_ship})
        emit({"type": "verified", "attack_blocked": report.verification.attack_blocked,
             "legit_passed": report.verification.legit_passed, "errored": report.verification.errored,
             "safe_to_ship": report.verification.safe_to_ship})

        if self._explainer and final:  # only the authoritative pass is explained: earlier ones are superseded
            report.explanations = parallel_map(lambda f: self._explain(f, report), report.findings)  # one call each

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
