"""Assess any Python agent project in one command -- attack, patch its source, re-attack, verdict:

    uv run python -m purpleteam.assess <git-url-or-local-path> [--entry module:attr] [--legit "a normal request"]

The project is cloned (or used in place) and set up in its own environment (``targets.workspace``); its
entry point is found by reading its source (``targets.entry``); it runs in its own interpreter with the
platform's shim inside it (``targets.process``), so none of its code changes and its dependencies never
meet the platform's. The run is recorded in the operator's run folder, so the live console shows it.

It executes the project's code on this machine, in a separate process but not in a container: assess only
code you would run yourself, or run this inside a VM or container.

Model access for the target is the operator's choice: ``--model-url``/``--model`` with the key in the
``PURPLETEAM_TARGET_MODEL_KEY`` environment variable (never on the command line) are handed to it under
the names OpenAI-compatible projects read. Without ``--legit`` the run cannot prove legitimate work still
works, and says so in its verdict rather than claiming it.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

from dotenv import find_dotenv, load_dotenv

from purpleteam.assessment import Assessment
from purpleteam.attack.claims import MODEL_ATTACKS_OFF, ONLY_STATIC, model_free_attacks
from purpleteam.audit.ledger import AuditLedger
from purpleteam.codemods.author import groq_complete
from purpleteam.codemods.catalog import CodemodCatalog
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.oracle import ALL_CANARIES, HONEYTOKEN, AnyOracle, CanaryOracle, LeakOracle, LoopOracle, not_hijacked
from purpleteam.run_history import RunStore
from purpleteam.sast import BanditScanner
from purpleteam.targets.entry import find_entries
from purpleteam.targets.process import ProcessTarget, TargetFailed
from purpleteam.targets.workspace import prepare, python_for

OPERATOR_DIR = Path.cwd() / ".purpleteam"


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="purpleteam.assess", description=__doc__.split("\n\n")[0])
    parser.add_argument("source", help="a git URL to clone, or a local project folder")
    parser.add_argument("--entry", help="module:attribute to run (default: the best candidate found)")
    parser.add_argument("--legit", action="append", default=[], help="a normal request that must keep working")
    parser.add_argument("--model-url", help="OpenAI-compatible base URL for the target's model")
    parser.add_argument("--model", help="model name for the target")
    parser.add_argument("--timeout", type=float, default=300, help="seconds one request may take")
    parser.add_argument("--restore", action="store_true", help="put every file a run edited back, then exit")
    parser.add_argument("--corpus", action="store_true", help="also run the fixed attack corpus (always run when "
                                                              "no agent prompt was discovered to target)")
    return parser.parse_args(argv)


def _target_env(args: argparse.Namespace) -> dict[str, str]:
    env = {}
    if args.model_url:
        env |= {"OPENAI_BASE_URL": args.model_url, "OPENAI_API_BASE": args.model_url}
    if args.model:
        env |= {"OPENAI_MODEL_NAME": args.model, "MODEL": args.model}
    key = os.environ.get("PURPLETEAM_TARGET_MODEL_KEY")
    if key:
        env["OPENAI_API_KEY"] = key
    return env


def _choose_entry(repo: Path, chosen: str | None) -> str:
    if chosen:
        return chosen
    candidates = find_entries(repo)
    if not candidates:
        sys.exit("No entry point found (no CrewAI crew, LangGraph graph, agent, or request-taking function). "
                 "Name one with --entry module:attribute.")
    for c in candidates[:5]:
        print(f"  entry candidate: {c.ref}  ({c.kind}, {c.file}:{c.line})")
    if candidates[0].kind == "function":  # only a guess from a parameter name: never attack a guess
        sys.exit("No crew, graph or agent was found, only functions that take a text argument. "
                 "Name the one that runs the agent with --entry module:attribute.")
    print(f"Using {candidates[0].ref} -- pass --entry to pick another.")
    return candidates[0].ref


def _show(event: dict) -> None:
    kind = event.get("type")
    if kind == "attack_result":
        print(f"  {event['id']}: {event['outcome']}  {event.get('detail', '')[:120]}")
    elif kind == "patch_applied":
        print(f"  defense: {', '.join(event['patch_ids']) or 'no runtime guard'} (escalation {event['escalation']})")
    elif kind in ("source_patch", "source_patch_skipped"):
        verb = "fixed" if kind == "source_patch" else "not fixed"
        print(f"  source {verb}: {event['path']}:{event['line']} {event.get('reason', '')[:120]}")
    elif kind == "decision_drift":
        print(f"  decision drift vs approved run: {event['counts']}")


async def assess(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    load_dotenv(find_dotenv(usecwd=True))
    repo = prepare(args.source, OPERATOR_DIR / "targets")
    snapshots = SourceSnapshots(OPERATOR_DIR / "targets" / f"{repo.name}.snapshots.json")
    if args.restore:
        for result in snapshots.restore_all(repo):
            print(f"  {result['path']}: {result['status']} {result.get('reason', '')}")
        return 0
    entry = _choose_entry(repo, args.entry)
    python, env = python_for(repo), _target_env(args)

    def target(guard=None) -> ProcessTarget:
        return ProcessTarget(repo.name, python, repo, entry, guard, env=env, timeout=args.timeout)

    print("Discovering agents and tools (running the project in its own process)...")
    try:
        profile = target().profile()
    except (TargetFailed, TimeoutError) as error:  # its own bug or environment, never patched over here
        print(f"\nNOT ASSESSED: the project could not start in its own environment.\n  {error}\n"
              "Fix the project (or its environment) and run again; no verdict is given for a target that never ran.")
        return 2
    print(f"  {len(profile.agent_info)} agent(s), {len(profile.tools)} tool(s); dangerous: "
          f"{', '.join(sorted(profile.dangerous_tools)) or 'none'}")
    runs = RunStore(OPERATOR_DIR / "runs")
    run = runs.new()
    run.write_meta(target=profile.name)
    approved = runs.last_approved(profile.name)
    oracle = AnyOracle(CanaryOracle(ALL_CANARIES, profile.dangerous_tools), LeakOracle({HONEYTOKEN}),
                       LoopOracle(profile.dangerous_tools))
    assessment = Assessment(
        target, oracle, profile, AuditLedger(run.ledger_path), legit=[(text, not_hijacked) for text in args.legit],
        scanner=BanditScanner(), repo=repo, codemod_catalog=CodemodCatalog(OPERATOR_DIR / "codemods"),
        codemod_complete=groq_complete, source_snapshots=snapshots,
        reload_target=lambda: None,  # every request starts a fresh process, which imports the edited files
        decision_baseline={**approved.read_json("decisions"), "run": approved.id} if approved else None)

    def on_event(event: dict) -> None:
        run.record(event)
        _show(event)

    if ONLY_STATIC:  # no attacker model: rule-written claims and PyRIT's templates (purpleteam.attack.claims)
        templates, targeted, untested = model_free_attacks(profile), False, [MODEL_ATTACKS_OFF]
    else:
        targeted = any(agent.prompt for agent in profile.agent_info)  # recon needs a prompt to read
        templates, untested = None if args.corpus or not targeted else [], []  # None: the default corpus
    # Exposure first: every attack meets the unpatched project, then one defense, then every breach re-attacked.
    report = await assessment.run(templates, timeout=args.timeout, targeted=targeted, untested=untested,
                                  exposure_first=True, on_event=on_event)
    run.write_trust(report.trust)
    for name, data in (("decisions", report.decisions), ("policy", report.policy)):
        if data:
            run.write_json(name, data)
    run.write_meta(status="done", finished_at=time.time(), safe_to_ship=report.safe_to_ship, findings=len(report.findings))
    run.record({"type": "done", "safe_to_ship": report.safe_to_ship, "run_id": run.id, "gate": report.blockers(),
                "residual": report.verification.residual if report.verification else None,
                "modified": [f"{repo.name}/{path}" for path in snapshots.modified()]})
    print(f"\n{'SAFE TO SHIP' if report.safe_to_ship else 'NOT SAFE TO SHIP'}  (run {run.id})")
    for reason in report.blockers():
        print(f"  - {reason}")
    if snapshots.modified():
        print(f"Edited {', '.join(snapshots.modified())}; undo with: uv run python -m purpleteam.assess {args.source} --restore")
    print("Open the live console and pick this run to see every attack, fix and decision.")
    return 0 if report.safe_to_ship else 1


def main() -> None:
    sys.exit(asyncio.run(assess()))


if __name__ == "__main__":
    main()
