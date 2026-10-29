"""One assessment: attack a target, prove each breach, patch it, verify the fix, seal the evidence.

This is the platform's single entry point. It chains the proven pieces — attack corpus,
proof-based oracle, defender, verifier, signed audit ledger, compliance mapping and (optionally)
the explainer — into one report. Domain-agnostic: the target factory, oracle, discovery profile
and legitimate-behaviour checks are all supplied by the caller.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Callable

from purpleteam.adapter import Target
from purpleteam.assessment_defense import DefensePass
from purpleteam.assessment_evidence import EvidencePass
from purpleteam.assessment_report import AssessmentReport, patchable_identity_findings, surface_findings
from purpleteam.attack.adaptive import run_adaptive
from purpleteam.attack.advanced import multilingual_templates, system_prompt_secrets, system_prompt_templates
from purpleteam.attack.runner import attacker_system_prompt
from purpleteam.attack.targeted import prepare_payloads, run_targeted
from purpleteam.attack.corpus import CANARY_MARK, AttackTemplate, CorpusResult, action_objective, build_corpus, run_corpus
from purpleteam.attack.exposure import run_unpatched
from purpleteam.attack.regressions import record_breaches
from purpleteam.audit.ledger import AuditLedger
from purpleteam.codemods.author import Complete
from purpleteam.codemods.catalog import CodemodCatalog
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.decisions import check_baseline as check_decisions
from purpleteam.sast import Scanner
from purpleteam.source_fix import display
from purpleteam.defender.selector import Defense, Finding
from purpleteam.oversight import ReviewQueue
from purpleteam.patches.base import CompositeGuard
from purpleteam.patches.scanners import warm_injection_backend
from purpleteam.discovery import TargetProfile
from purpleteam.explainer import Explanation
from purpleteam.focus import plan_focus
from purpleteam.identity import PermissionManifest, check_baseline, check_credentials
from purpleteam.oracle import AnyOracle, CANARY_ACCOUNT, LeakOracle, Oracle
from purpleteam.verifier import LegitCheck, VerifyReport

TargetFactory = Callable[[Any], Target]  # guard (or None) -> a fresh target
Explainer = Callable[[Finding, Defense, VerifyReport], Explanation]
Anchorer = Callable[[dict], tuple[dict, list[str]]]  # trust bundle -> (bundle with timestamp anchors, problems)


class Assessment(DefensePass, EvidencePass):
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
        codemod_catalog: CodemodCatalog | None = None,
        repo: str | Path | None = None,
        regressions: str | Path | None = None,
        review_queue: ReviewQueue | None = None,
        codemod_complete: Complete | None = None,
        source_snapshots: SourceSnapshots | None = None,
        reload_target: Callable[[], None] | None = None,
        verify_trials: int = 3,
        max_residual: float = 0.6,
        decision_baseline: dict | None = None,
    ) -> None:
        self._factory = factory
        # Known system prompts are in-memory proof markers for extraction attacks. They are never
        # written into the ledger; LeakOracle records only the channel and marker kind.
        prompt_markers = system_prompt_secrets(profile.agent_info)
        self._oracle = AnyOracle(oracle, LeakOracle(prompt_markers)) if prompt_markers else oracle
        self._profile = profile
        self._ledger = ledger
        self._legit = legit
        self._canary = canary
        # One queue for this whole run: _defend_and_verify builds a fresh Defender on every pass
        # (the incremental one right after a breach, and the final authoritative one), and every
        # P4 hold/approval/rejection must still be visible across all of them, not reset each time.
        self._review_queue = review_queue if review_queue is not None else ReviewQueue(ledger=ledger)
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
        self._codemod_catalog = codemod_catalog  # exact-match approved fixes, plus auto-approved verified drafts
        self._codemod_complete = codemod_complete  # drafts a fix when the catalog has none (purpleteam.source_fix)
        self._snapshots = source_snapshots  # every source edit's original, so it can be restored
        self._reload_target = reload_target  # makes the factory build from the edited source, not the cached one
        self._verify_trials, self._max_residual = verify_trials, max_residual  # the release gate (verifier.py)
        # The last approved policy's decisions: this run's policy must not loosen any of them (purpleteam.decisions).
        self._decision_baseline = None if decision_baseline is None else check_decisions(decision_baseline)
        self._regressions = None if regressions is None else Path(regressions)  # see attack.regressions

    async def run(self, templates: list[AttackTemplate] | None = None, *, focus: list[str] | None = None,
                  agent: str | None = None, disguise_with: list[str] | None = None,
                  place_with: list[str] | None = None, adaptive: str | None = None, targeted: bool = False,
                  timeout: float | None = 120, on_event: Callable[[dict], None] | None = None,
                  untested: list[str] = (), exposure_first: bool = False) -> AssessmentReport:
        """Attack with ``templates``, or only the chosen ``focus`` topics (optionally one ``agent``), or the default
        corpus. Judge a focused run with ``focus_oracle`` so only the oracles that apply to the topic can call a
        breach. ``disguise_with``/``place_with`` additionally run each template disguised or placed inside cover
        text; a breach is verified against the exact variant that caused it, never the plain template alone.
        ``adaptive`` ("redteam", "crescendo", "pair" or "tap") additionally runs one adaptive PyRIT attack
        against the same objective as the default corpus — PyRIT searching for a working phrasing instead of only recalling known templates,
        see ``purpleteam.attack.adaptive``. Off by default: unlike the corpus, it costs real adversarial-model
        calls. ``targeted`` additionally reads each discovered agent's own real prompt for a literal, unverified
        trigger condition and crafts one payload per agent that states it in plain language, with no stated attack
        intent — the corpus's generic objective announces itself outright, which no wrapper disguises, so it holds
        regardless of target strength; see ``purpleteam.attack.targeted``. Off by default: a few cheap extra calls
        per agent with a captured prompt, none for an agent without one. ``timeout`` bounds each attempt — raise it
        for a slow-but-honest target rather than poison the run.

        ``on_event`` is an optional progress hook for a live caller (a web page streaming this run as it happens):
        called with ``{"type": ..., ...}`` dicts as the run progresses — ``attack_start``/``attack_result`` per
        attempt (including the adaptive one, if run), ``finding_detected`` the instant a breach proves out
        (naming the catalog's recommended patch ids for it — instant and free, a lookup, not a build — so a live
        caller can show defense reacting immediately rather than waiting out the rest of the attack campaign in
        silence), ``patch_applied`` once the real, built and verified defense is selected (which dedupes and
        finalizes every finding together, including static/identity ones no single attack result carries), and a
        final ``sealed`` right before this method returns. Every field in each event comes straight from the same
        objects this method already builds and signs into the ledger — nothing is computed twice or invented for
        display. Defaults to ``None``, so an ordinary caller (every existing one) sees no difference at all.

        ``exposure_first`` runs every template against the unpatched agent, side by side, with no live patch in
        between (``purpleteam.attack.exposure``): the breach count is the agent's real exposure, and the one final
        defense is then re-attacked with every breaching payload."""
        def _emit(payload: dict) -> None:
            if on_event:
                on_event(payload)

        detected_findings: set[tuple] = set()  # (kind, tool): one incremental defend per distinct pair, not per breach
        incremental_breaches: list[CorpusResult] = []  # every attack breach seen so far this run, for the live patch
        current_guard: dict[str, Any] = {"value": None}  # the latest applied defense, so the NEXT attempt faces it

        techniques: dict[str, str] = {}  # template id -> technique, so a live caller can group attacks as they start

        def _on_attack_start(result_id: str, payload: str, technique: str = "") -> None:
            key = result_id
            while key and not technique:  # a disguised or placed variant ("<id>:base64") is its template's technique
                technique, key = techniques.get(key, ""), key.rpartition(":")[0]
            _emit({"type": "attack_start", "id": result_id, "payload": payload, "technique": technique})

        def _on_attack_result(result: CorpusResult, seconds: float) -> None:
            _emit({"type": "attack_result", "id": result.id, "technique": result.technique,
                  "breached": result.breached, "outcome": result.outcome, "detail": result.detail,
                  "kind": result.kind, "tool": result.tool, "agent": result.agent,
                  "upper_bound": result.upper_bound, "trials": result.trials, "conclusive": result.conclusive,
                  "seconds": seconds, "reply": result.reply, "persuaded": result.persuaded})
            self._record_attack(result)  # ledger order matches real order: attack/breach before any patch it causes
            if exposure_first:  # no live patch: every attack must meet the agent as it really is
                return
            if result.breached and result.kind and (result.kind, result.tool) not in detected_findings:
                detected_findings.add((result.kind, result.tool))
                incremental_breaches.append(result)
                # Build, apply and verify the real defense for every finding proven so far right now —
                # not queued for later — so a live caller sees the actual patch react the instant a
                # breach proves out, not after the rest of the attack campaign finishes. Written to a
                # scratch report, never the real one: the final call below, once every attack, static
                # and identity finding is known, is what sets the run's own authoritative result. The
                # guard it builds is kept and handed to the factory before the next attempt, so attack,
                # patch, attack again is real: the next attempt genuinely faces the hardened target, not
                # a synthetic re-send of the same payload the way verify()'s own check alone would be.
                scratch = AssessmentReport(self._profile.name, [])
                self._defend_and_verify(scratch, incremental_breaches, emit=_emit)
                if scratch.defense is not None:
                    current_guard["value"] = scratch.defense.guard

        # Independent of every attack: start now, collect when needed. Neither writes the ledger here,
        # so the evidence order is the same as if they had run in turn.
        scan_task = asyncio.create_task(asyncio.to_thread(self._scan))
        asyncio.create_task(asyncio.to_thread(warm_injection_backend))
        scope: dict = {}
        if focus is not None:
            plan = plan_focus(self._profile, focus, agent=agent, secrets=self._facts.get("secrets", ()),
                              manifest=self._manifest)
            templates, scope = plan.templates, {"focus": list(focus), "agent": agent, "skipped": plan.skipped}
        elif templates is None or not templates:  # the default corpus, or none at all: say what did not run
            corpus_ran = templates is None
            if corpus_ran:
                templates = (build_corpus(action_objective(self._profile.dangerous_tools))
                             + multilingual_templates(self._profile)
                             + system_prompt_templates(self._profile.agent_info))
            scope = {"corpus": "default" if corpus_ran else "skipped", "templates": [t.id for t in templates]}
            not_run = [] if corpus_ran else ["the fixed jailbreak corpus (templates=[])"]
            if not adaptive:
                not_run.append("adaptive PyRIT search — pass adaptive='redteam'/'crescendo'/'tap'/'pair', or see "
                               "purpleteam.attack.adaptive, to add it")
            if not targeted:
                not_run.append("targeted trigger-condition attack — pass targeted=True, or see "
                               "purpleteam.attack.targeted, to add it")
            if not place_with:
                not_run.append("disguise/placement variants were not run — pass disguise_with/place_with to add "
                               "them")
            if self._profile.retrieval_tools:
                scope["rag_surface"] = sorted(self._profile.retrieval_tools)
                not_run.append("tool-output injection was not run through a retrieved/tool-returned value; "
                               "plain text placement is not equivalent — use a target adapter that injects into "
                               "the actual retrieval source (the AgentDojo demo is one example)")
                if not place_with:
                    not_run.append(f"{len(self._profile.retrieval_tools)} retrieval-shaped tool(s) found "
                                   f"({', '.join(sorted(self._profile.retrieval_tools))}) but attacks ran as "
                                   "plain text, not placed inside document-shaped content the way a poisoned "
                                   "retrieved chunk would arrive — pass place_with to test that channel")
            if not system_prompt_templates(self._profile.agent_info):
                not_run.append("system-prompt extraction was not run because discovery did not capture an agent prompt")
            if not_run:
                scope["not_run"] = "; ".join(not_run)
        # One attempt at a time, rebuilding the target with whatever defense has landed so far: attack,
        # patch, attack again against the now-hardened target, not N attempts against one unpatched one.
        results: list[CorpusResult] = []
        techniques.update({t.id: t.technique for t in templates})
        corpus_options = dict(canary=self._canary, disguise_with=disguise_with, place_with=place_with,
                              timeout=timeout, on_start=_on_attack_start, on_result=_on_attack_result)
        if exposure_first:
            results = await run_unpatched(lambda: self._factory(None), self._oracle, templates, **corpus_options)
            scope["exposure_first"] = True
        for template in [] if exposure_first else templates:
            results.extend(await run_corpus(self._factory(current_guard["value"]), self._oracle, [template],
                                            **corpus_options))
        if adaptive:
            objective = action_objective(self._profile.dangerous_tools).replace(CANARY_MARK, self._canary)
            _on_attack_start(adaptive, objective, adaptive)
            started = time.monotonic()
            briefing = attacker_system_prompt(self._profile.agent_info)
            adaptive_result = await run_adaptive(self._factory(current_guard["value"]), self._oracle, objective,
                                                 technique=adaptive, system_prompt=briefing, timeout=timeout)
            _on_attack_result(adaptive_result, time.monotonic() - started)
            results.append(adaptive_result)
            scope["adaptive"] = adaptive
        if targeted:
            targeted_results: list[CorpusResult] = []
            payloads = await prepare_payloads(self._profile.agent_info, self._canary)  # all recon at once
            for agent_info in self._profile.agent_info:  # but each attack faces the latest defense
                batch = await run_targeted(self._factory(current_guard["value"]), self._oracle, [agent_info],
                                           canary=self._canary, timeout=timeout, payloads=payloads,
                                           on_start=lambda rid, text: _on_attack_start(rid, text, "trigger-condition"),
                                           on_result=_on_attack_result)
                targeted_results.extend(batch)
            results.extend(targeted_results)
            scope["targeted"] = len(targeted_results)
        report = AssessmentReport(self._profile.name, results, scope=scope)
        self._check_identity(report)
        static_raw, scan_gaps = await scan_task
        report.coverage_gaps.extend(scan_gaps)
        self._log_scan(static_raw, scan_gaps)
        if self._scanner is not None and self._repo is not None:  # "found nothing" only when a scan really ran
            _emit({"type": "static_scan", "gaps": scan_gaps,
                   "findings": [{"kind": f.kind, "file": display(self._repo, f.file), "line": f.line,
                                 "severity": f.severity, "detail": f.detail, "blocking": f.blocking}
                                for f in static_raw]})
        source_fix = await self._fix_sources(static_raw, _emit)
        static = [f.as_finding() for f in static_raw]
        identity_findings = patchable_identity_findings(report.identity) + surface_findings(self._profile)
        self._assess_blast(report, results)
        if untested:  # what the caller chose not to run is said too, never left out
            scope["not_run"] = "; ".join(filter(None, [scope.get("not_run"), *untested]))
        if scope:  # the evidence says what was not tested, so a narrow run is never read as a clean bill
            self._ledger.append("attacker", "scope", scope)

        breaches = [r for r in results if r.breached]
        all_breaches = breaches + self._regression_breaches()
        if all_breaches or static or identity_findings:
            self._defend_and_verify(report, all_breaches, static, identity_findings, _emit,
                                    source_fix=source_fix, static_raw=static_raw, record_decisions=True)
            record_breaches(self._regressions, breaches)  # only this run's own, new breaches
        elif self._decision_baseline is not None:  # nothing found means no defense at all: compare that too
            self._compare_decisions(report, lambda: CompositeGuard([]), _emit)
        self._seal(report)
        _emit({"type": "sealed", "safe_to_ship": report.safe_to_ship, "findings": len(report.findings),
              "chain_ok": report.chain_ok, "merkle_root": report.sealed_root, "blast": report.blast,
              "coverage_gaps": report.coverage_gaps, "not_tested": scope.get("not_run", ""),
              "impacts": report.impacts, "excluded": sorted(report.excluded),
              "coverage": sorted(report.coverage),
              "explanations": [{"text": e.text, "verified": e.verified, "issues": e.issues}
                               for e in report.explanations]})
        return report
