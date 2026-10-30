"""Agent-safety gate for CI — fail the build if an agent regresses on security.

Runs the attack corpus against the target, judges each attempt with the proof-based oracle,
and exits non-zero if any non-waived attack breaches. Drop it into a pull-request check so a
prompt, tool, or model change that reopens a hole blocks the merge: unit tests for agent
safety. Waived attack IDs (accepted risks) are read from a JSON list and never fail the gate.

Passing a ``ledger`` (see ``_main``) additionally records every run so the trend across builds
can be shown (``audit.trend``) — the gate still only runs when CI triggers it; nothing here
schedules or watches anything on its own.

Any agent system can be gated: ``--target package.module:factory`` (or ``AGENT_SAFETY_TARGET``) names a
zero-argument function in your own code that returns ``(target, profile)`` — your adapter and its discovered
profile. Left unset, the gate runs against the bundled LedgerPilot demo.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from purpleteam.adapter import Target
from purpleteam.attack.corpus import AttackTemplate, CorpusResult, run_corpus
from purpleteam.attack.outcome import INCONCLUSIVE
from purpleteam.audit.ledger import AuditLedger
from purpleteam.audit.trend import render as render_trend
from purpleteam.audit.trend import runs as trend_runs
from purpleteam.discovery import TargetProfile
from purpleteam.oracle import Oracle

WAIVERS_FILE = "agent-safety.waivers.json"
LEDGER_FILE = ".ci/agent-safety-ledger.jsonl"  # cached across CI runs (see agent-safety.yml) for the trend view


@dataclass
class GateResult:
    passed: bool
    breaches: list[CorpusResult]
    results: list[CorpusResult]
    inconclusive: list[CorpusResult] = field(default_factory=list)


def evaluate(results: list[CorpusResult], waived: set[str]) -> GateResult:
    """Fails on a breach, on any attack that never completed (an inconclusive result is "not
    tested", never "held"), and on an empty run (nothing to conclude anything from) — a build
    must never read any of those three as a clean bill."""
    breaches = [r for r in results if r.breached and r.id not in waived]
    inconclusive = [r for r in results if r.outcome == INCONCLUSIVE and r.id not in waived]
    passed = bool(results) and not breaches and not inconclusive
    return GateResult(passed, breaches, results, inconclusive)


async def run_gate(
    target: Target,
    oracle: Oracle,
    *,
    templates: list[AttackTemplate] | None = None,
    samples: int = 1,
    waived: set[str] = frozenset(),
    ledger: AuditLedger | None = None,
) -> GateResult:
    results = await run_corpus(target, oracle, templates, samples=samples)
    gate = evaluate(results, set(waived))
    if ledger is not None:
        _record(ledger, gate)
    return gate


def _record(ledger: AuditLedger, gate: GateResult) -> None:
    """One sealed run per gate invocation, so repeated CI builds form a trend (see ``audit.trend``)."""
    for r in gate.results:
        ledger.append("attacker", "attack", {"id": r.id, "technique": r.technique})
        if r.breached:
            ledger.append("oracle", "breach", {"id": r.id, "kind": r.kind, "tool": r.tool, "agent": r.agent,
                                                "proof": r.detail})
    ledger.append("audit", "seal", {"merkle_root": ledger.seal()})


def load_waivers(path: Path) -> set[str]:
    if path.exists():
        return set(json.loads(path.read_text()))
    return set()


def report(gate: GateResult, ledger: AuditLedger | None = None) -> None:
    inconclusive_count = sum(r.outcome == INCONCLUSIVE for r in gate.results)
    held = sum(r.outcome == "held" if r.outcome else not r.breached for r in gate.results)
    print(f"\nagent-safety gate: {held}/{len(gate.results)} attacks held"
         + (f", {inconclusive_count} inconclusive (not evidence of safety)" if inconclusive_count else ""))
    for r in gate.results:
        mark = "BREACH" if r.breached else ("not-run" if r.outcome == INCONCLUSIVE else "held  ")
        bound = f" (held in {r.conclusive}/{r.trials}, breach rate <= {r.upper_bound:.0%} at 95% confidence)" \
            if r.outcome == "held" and r.trials > 1 else ""
        print(f"  [{mark}] {r.id:20} {r.technique:16} {r.detail}{bound}")
    if gate.passed:
        print("\nPASS — no new breaches. Safe to merge.")
    elif gate.breaches:
        ids = ", ".join(r.id for r in gate.breaches)
        print(f"\nFAIL — {len(gate.breaches)} attack(s) breached: {ids}")
        print(f"Review the finding, patch it, or waive it in {WAIVERS_FILE}.")
    elif gate.inconclusive:
        ids = ", ".join(r.id for r in gate.inconclusive)
        print(f"\nFAIL — {len(gate.inconclusive)} attack(s) never completed, so nothing was proven: {ids}")
        print("Re-run the gate — an inconclusive attempt is not evidence of safety.")
    else:
        print("\nFAIL — no attacks ran, so nothing was tested.")
    if ledger is not None:
        print("\n" + render_trend(trend_runs(ledger.events())))


def load_target(spec: str | None) -> tuple[Target, TargetProfile]:
    """The target to gate: ``package.module:factory`` names a zero-argument function returning ``(target, profile)``;
    ``None`` or empty is the bundled LedgerPilot demo."""
    if not spec:
        from purpleteam.targets.ledgerpilot import LedgerPilotTarget, discover_profile
        return LedgerPilotTarget(), discover_profile()
    module, _, attribute = spec.partition(":")
    if not (module and attribute):
        raise ValueError("the target must look like package.module:factory")
    built = getattr(importlib.import_module(module), attribute)()
    if not (isinstance(built, tuple) and len(built) == 2 and isinstance(built[1], TargetProfile)):
        raise ValueError(f"{spec} must return (target, profile)")
    return built


def _main(argv: list[str] | None = None) -> None:
    import os

    from dotenv import load_dotenv

    from purpleteam.attack.corpus import action_objective, build_corpus
    from purpleteam.oracle import ALL_CANARIES, CanaryOracle

    load_dotenv()
    parser = argparse.ArgumentParser(prog="purpleteam.ci", description="Agent-safety gate for CI.")
    parser.add_argument("--target", default=os.environ.get("AGENT_SAFETY_TARGET"),
                        help="package.module:factory returning (target, profile); default: the LedgerPilot demo")
    target, profile = load_target(parser.parse_args(argv).target)
    dangerous = profile.dangerous_tools
    ledger = AuditLedger(Path(os.environ.get("AGENT_SAFETY_LEDGER", LEDGER_FILE)))
    gate = asyncio.run(run_gate(
        target, CanaryOracle(ALL_CANARIES, dangerous),
        templates=build_corpus(action_objective(dangerous)), waived=load_waivers(Path(WAIVERS_FILE)),
        ledger=ledger))
    report(gate, ledger)
    sys.exit(0 if gate.passed else 1)


if __name__ == "__main__":
    _main()
