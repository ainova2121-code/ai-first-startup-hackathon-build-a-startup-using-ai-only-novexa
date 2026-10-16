"""Agent-safety gate for CI — fail the build if an agent regresses on security.

Runs the attack corpus against the target, judges each attempt with the proof-based oracle,
and exits non-zero if any non-waived attack breaches. Drop it into a pull-request check so a
prompt, tool, or model change that reopens a hole blocks the merge: unit tests for agent
safety. Waived attack IDs (accepted risks) are read from a JSON list and never fail the gate.

Passing a ``ledger`` (see ``_main``) additionally records every run so the trend across builds
can be shown (``audit.trend``) — the gate still only runs when CI triggers it; nothing here
schedules or watches anything on its own.
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from purpleteam.adapter import Target
from purpleteam.attack.corpus import AttackTemplate, CorpusResult, run_corpus
from purpleteam.audit.ledger import AuditLedger
from purpleteam.audit.trend import render as render_trend
from purpleteam.audit.trend import runs as trend_runs
from purpleteam.oracle import Oracle

WAIVERS_FILE = "agent-safety.waivers.json"
LEDGER_FILE = ".ci/agent-safety-ledger.jsonl"  # cached across CI runs (see agent-safety.yml) for the trend view


@dataclass
class GateResult:
    passed: bool
    breaches: list[CorpusResult]
    results: list[CorpusResult]


def evaluate(results: list[CorpusResult], waived: set[str]) -> GateResult:
    breaches = [r for r in results if r.breached and r.id not in waived]
    return GateResult(passed=not breaches, breaches=breaches, results=results)


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
    inconclusive = sum(r.outcome == "inconclusive" for r in gate.results)
    held = sum(r.outcome == "held" if r.outcome else not r.breached for r in gate.results)
    print(f"\nagent-safety gate: {held}/{len(gate.results)} attacks held"
         + (f", {inconclusive} inconclusive (not evidence of safety)" if inconclusive else ""))
    for r in gate.results:
        mark = "BREACH" if r.breached else ("not-run" if r.outcome == "inconclusive" else "held  ")
        bound = f" (held in {r.conclusive}/{r.trials}, breach rate <= {r.upper_bound:.0%} at 95% confidence)" \
            if r.outcome == "held" and r.trials > 1 else ""
        print(f"  [{mark}] {r.id:20} {r.technique:16} {r.detail}{bound}")
    if gate.passed:
        print("\nPASS — no new breaches. Safe to merge.")
    else:
        ids = ", ".join(r.id for r in gate.breaches)
        print(f"\nFAIL — {len(gate.breaches)} attack(s) breached: {ids}")
        print(f"Review the finding, patch it, or waive it in {WAIVERS_FILE}.")
    if ledger is not None:
        print("\n" + render_trend(trend_runs(ledger.events())))


def _main() -> None:
    import os

    from dotenv import load_dotenv

    from purpleteam.attack.corpus import action_objective, build_corpus
    from purpleteam.oracle import CANARY_ACCOUNT, CanaryOracle
    from purpleteam.targets.ledgerpilot import LedgerPilotTarget, discover_profile

    load_dotenv()
    dangerous = discover_profile().dangerous_tools
    ledger = AuditLedger(Path(os.environ.get("AGENT_SAFETY_LEDGER", LEDGER_FILE)))
    gate = asyncio.run(run_gate(
        LedgerPilotTarget(), CanaryOracle({CANARY_ACCOUNT}, dangerous),
        templates=build_corpus(action_objective(dangerous)), waived=load_waivers(Path(WAIVERS_FILE)),
        ledger=ledger))
    report(gate, ledger)
    sys.exit(0 if gate.passed else 1)


if __name__ == "__main__":
    _main()
