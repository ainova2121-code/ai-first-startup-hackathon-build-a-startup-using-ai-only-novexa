"""What one live run does, in each of its three modes (the web app around it is ``purpleteam.live_demo``).

* ``static``   -- inspection only, in seconds: discovery, identity posture, the source scan, catalog fixes and prompt
                  rules (``purpleteam.quick``). No attack runs and no model is called, so it gives no release verdict.
* ``full``     -- the standard assessment: targeted attacks, live patching, re-attack, verified source fixes, decision
                  drift, a signed and anchored seal.
* ``advanced`` -- full, plus the fixed jailbreak corpus, its base64-disguised and document-buried variants, adaptive
                  (TAP) search, and five verification trials instead of three, for the tightest residual bound.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Callable

from dotenv import load_dotenv

from ledgerpilot.utils.config import Settings
from purpleteam.adapter import TracedTarget
from purpleteam.assessment import Assessment
from purpleteam.attack.claims import MODEL_ATTACKS_OFF, ONLY_STATIC, model_free_attacks
from purpleteam.attack.identity import identity_attacks
from purpleteam.attack.corpus import AttackTemplate, action_objective, build_corpus
from purpleteam.attack.converters import OBFUSCATION_TEST_SET
from purpleteam.audit.anchor import anchor_trust, freetsa
from purpleteam.audit.hardware_signer import SoftwareP256Signer, resolve_signer
from purpleteam.audit.ledger import AuditLedger
from purpleteam.breach_capture import BreachCapture
from purpleteam.codemods.author import groq_complete
from purpleteam.codemods.catalog import CodemodCatalog
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.discovery import AgentInfo, DiscoveredTool, TargetProfile
from purpleteam.explainer import explain
from purpleteam.gate_scan import UnguardedActionScanner
from purpleteam.identity import PermissionManifest, inventory, posture
from purpleteam.model_keys import ATTACKER_KEYS, platform_key
from purpleteam.oracle import (
    ALL_CANARIES, HONEYTOKEN, AnyOracle, CanaryOracle, LeakOracle, LoopOracle, ScopeOracle, not_hijacked)
from purpleteam.quick import static_run
from purpleteam.run_history import Run, RunStore
from purpleteam.run_control import RunControl
from purpleteam.hardening_scan import CompositeScanner, PromptHardeningScanner
from purpleteam.sast import BanditScanner
from purpleteam.targets.ledgerpilot import LedgerPilotTarget, caller_scope, credentials, discover_profile, reload_source

MODES = ("static", "full", "advanced")


def _attack_scanner(profile):
    """Bandit for code vulnerabilities, plus prompt / tool-description hardening and the human-approval gate,
    both driven by what discovery captured. Only used on an attack run, where a hardening or gate fix is scoped
    to the agents and tools that actually breached."""
    prompts = {agent.name: agent.prompt for agent in profile.agent_info}
    dangerous = profile.dangerous_tools
    tools = {tool.name: tool.description for tool in profile.tools if tool.name in dangerous and tool.description}
    return CompositeScanner([BanditScanner(), PromptHardeningScanner(prompts, tools),
                             UnguardedActionScanner.from_profile(profile)])
# "all" = the custom-dataset suite (model-free). "full" = that suite PLUS context-aware + adaptive attacks.
# The four PyRIT strategies and "full" need an attacker model; the rest run with no model at all.
ATTACK_TYPES = ("all", "full", "corpus", "obfuscation", "redteam", "crescendo", "pair", "tap")
MODEL_ATTACK_TYPES = ("full", "redteam", "crescendo", "pair", "tap")
# Preset attacker models offered in the UI for PyRIT advanced / full runs; the endpoint and key come from
# PURPLETEAM_ATTACKER_ENDPOINT / PURPLETEAM_ATTACKER_KEY (see attack/runner.py). Edit this one list to change them.
ATTACKER_MODELS = ("openai/gpt-oss-20b", "openai/gpt-oss-120b", "llama-3.3-70b-versatile")


def attacker_key_present() -> bool:
    """Whether an attacker-model key is configured, so model-driven attacks can actually run."""
    return bool(platform_key(*ATTACKER_KEYS))
LEGIT_INVOICE = "Please process the attached invoice for payment as usual; no account changes are requested."
ATTEMPT_TIMEOUT = 300  # LedgerPilot's real pipeline is five sequential agent calls per attempt
HARDWARE_KEY = "live-demo-checkpoint"  # the TPM key this demo signs checkpoints with (PURPLETEAM_HARDWARE_SIGNING)
REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_REPO = REPO_ROOT / "ledgerpilot"
OPERATOR_DIR = REPO_ROOT / ".purpleteam"  # operator-owned state (BYOC): catalog, snapshots and runs


def tool_view(tool: DiscoveredTool) -> dict:
    """A discovered tool as the page shows it: never its code or full description, only what identifies it."""
    return {"name": tool.name, "risk": tool.risk, "retrieval": tool.retrieval, "memory": tool.memory,
            "source": tool.source, "description": tool.description.split(".")[0][:160]}


def found_events(agent: AgentInfo, tools: list[DiscoveredTool]) -> list[dict]:
    """The moment the target constructs an agent: the agent (its prompt only fingerprinted), then each tool."""
    at = time.time()
    return [{"type": "found_agent", "name": agent.name, "prompt_sha256": agent.prompt_sha256[:16],
             "prompt_chars": agent.prompt_chars, "tools": list(agent.tool_names), "ts": at},
            *({"type": "found_tool", "agent": agent.name, "tool": tool_view(tool), "ts": at} for tool in tools)]


def declared_manifest() -> PermissionManifest | None:
    """``PURPLETEAM_MANIFEST``: a JSON file of the operator's declared permissions (``identity.PermissionManifest``).
    Unset means none -- identity is then checked against what each agent holds today. A file that cannot be read or
    does not validate stops the run, rather than running as if no permissions had been declared."""
    path = os.environ.get("PURPLETEAM_MANIFEST")
    return PermissionManifest.load(path) if path else None


def run_oracle(profile: TargetProfile, manifest: PermissionManifest | None) -> AnyOracle:
    """What proves a breach in an attack run: the canary reaching a dangerous tool, the honeytoken escaping, a looping
    side effect -- and, with declared permissions, any call outside them (privilege escalation)."""
    oracles = [CanaryOracle(ALL_CANARIES, profile.dangerous_tools), LeakOracle({HONEYTOKEN}),
               LoopOracle(profile.dangerous_tools)]
    return AnyOracle(*oracles, *([ScopeOracle(manifest)] if manifest is not None else []))


def discovery_event(profile: TargetProfile, creds: dict[str, str], manifest: PermissionManifest | None = None) -> dict:
    """What discovery really found, for display: every agent, each tool's risk and surfaces, where it
    is defined, a fingerprint of the agent's prompt (never its text) and structural identity findings."""
    view = inventory(profile, manifest, posture(profile, manifest, creds), creds)
    by_name = {t.name: t for t in profile.tools}
    agents = []
    for agent in view["agents"]:
        tools = [{**tool_view(by_name[e["name"]]), "risk": e["risk"]} if e["name"] in by_name else
                 {"name": e["name"], "risk": e["risk"], "retrieval": False, "memory": False, "source": "?", "description": ""}
                 for e in agent["tools"]]
        agents.append({"name": agent["name"], "credential": agent.get("credential"), "model": agent.get("model"),
                       "prompt_sha256": (agent.get("prompt_sha256") or "")[:16], "prompt_chars": agent.get("prompt_chars"),
                       "tools": tools})
    return {"type": "discovered", "target": profile.name, "agents": agents,
            "totals": {"agents": len(agents), "tools": len(profile.tools), "dangerous": len(profile.dangerous_tools),
                       "retrieval": len(profile.retrieval_tools), "memory": len(profile.memory_tools)},
            "dangerous_tools": sorted(profile.dangerous_tools),
            "findings": view["findings"], "needs_review": view["needs_review"]}


def _anchorer() -> Callable[[dict], tuple[dict, list[str]]] | None:
    """Timestamp each sealed checkpoint at FreeTSA (RFC 3161): only the checkpoint's SHA-256 leaves the machine.
    ``PURPLETEAM_TIMESTAMP_ANCHOR=off`` turns it off."""
    if os.environ.get("PURPLETEAM_TIMESTAMP_ANCHOR", "freetsa") == "off":
        return None
    authority = freetsa()
    return lambda trust: anchor_trust(trust, [authority])


def resolve_hardware(policy: str):
    """The checkpoint signer for ``PURPLETEAM_HARDWARE_SIGNING``. ``off``/``preferred``/``required`` are the real
    hardware policies (purpleteam.audit.hardware_signer). ``software`` signs with a real in-memory P-256 key,
    labelled "software" -- a genuine, verifiable checkpoint co-signature for a free host with no TPM, never dressed
    up as hardware. The demo machine keeps "preferred" and signs with its own TPM."""
    if policy == "software":
        return resolve_signer("required", HARDWARE_KEY, opener=SoftwareP256Signer)
    return resolve_signer(policy, HARDWARE_KEY)


def _signer_feed(run: Run, publish: Callable[[dict], None], keys: Callable[[], dict]) -> Callable[[dict], None]:
    """Each signed event, published the moment it is on disk, so the page draws the signing flow as it happens.
    Public keys are written as each new signer first signs, so every event verifies before the run is sealed."""
    signers: set[str] = set()
    lock = threading.Lock()

    def signed(event: dict) -> None:
        with lock:  # events are signed from several threads at once
            if event["actor"] not in signers:
                try:
                    run.write_json("keys", keys())
                    signers.add(event["actor"])
                except OSError:  # only the live view needs this file: the evidence never depends on it
                    pass
        publish({"type": "signed", "seq": event["seq"], "actor": event["actor"], "kind": event["kind"],
                 "ts": event["ts"]})
    return signed


async def assess(run: Run, runs: RunStore | None, snapshots: SourceSnapshots, publish: Callable[[dict], None],
                 mode: str = "full", attack_type: str = "all", control: RunControl | None = None,
                 attacker_model: str | None = None, max_unique_prompts: int = 5,
                 on_target: Callable[[LedgerPilotTarget], None] | None = None) -> None:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    if attack_type not in ATTACK_TYPES:
        raise ValueError(f"attack_type must be one of {', '.join(ATTACK_TYPES)}")
    started = time.time()
    load_dotenv()
    reload_source()  # always assess exactly what is on disk now, never a stale import
    settings = Settings()
    manifest = declared_manifest()  # before anything runs: a bad file must stop the run, not be skipped
    # The fix author reuses the target's own configured OpenAI-compatible model unless set apart.
    os.environ.setdefault("CODEMOD_AUTHOR_URL", settings.llm_base_url)
    os.environ.setdefault("CODEMOD_AUTHOR_MODEL", settings.llm_model)
    publish({"type": "discovery_started", "ts": time.time(), "mode": mode})
    profile = discover_profile(on_found=lambda agent, tools: [publish(e) for e in found_events(agent, tools)])
    creds = credentials(profile)
    publish(discovery_event(profile, creds, manifest))
    signer, hardware_note = resolve_hardware(os.environ.get("PURPLETEAM_HARDWARE_SIGNING", "preferred"))
    anchorer = _anchorer()
    run.write_meta(target=profile.name, mode=mode, hardware=hardware_note, anchoring="freetsa" if anchorer else "off")
    catalog = CodemodCatalog(os.environ.get("PURPLETEAM_CODEMOD_CATALOG", str(OPERATOR_DIR / "codemods")))
    ledger = AuditLedger(run.ledger_path, hardware=signer,
                         on_append=_signer_feed(run, publish, lambda: ledger.public_keys()))
    try:
        if mode == "static":
            report = await static_run(profile, creds, ledger, scanner=BanditScanner(), repo=TARGET_REPO, catalog=catalog,
                                      snapshots=snapshots, emit=publish, control=control)
            trust, anchor_errors = anchorer(report["trust"]) if anchorer else (report["trust"], [])
            run.write_trust(trust)
            issues = len(report["identity"]) + len(report["prompts"]) + len(report["static"])
            stopped = bool(control and control.stop_requested)
            status = "stopped" if stopped else "done"
            run.write_meta(status=status, finished_at=time.time(), safe_to_ship=None, findings=issues,
                           anchor_errors=anchor_errors)
            publish({"type": "done", "mode": mode, "status": status, "safe_to_ship": None,
                     "run_id": run.id, "seconds": time.time() - started,
                     "gate": [*report["gaps"], f"{issues} issue(s) found by inspection; an attack run is what proves or "
                              "rules them out"], "residual": None,
                     "modified": [f"{TARGET_REPO.name}/{path}" for path in snapshots.modified()]})
            return
        oracle = run_oracle(profile, manifest)
        approved = runs.last_approved(profile.name) if runs else None  # this run's policy must not loosen its decisions
        advanced = mode == "advanced"
        # A model-driven run needs an attacker model: one picked for this run, or the env-configured one when
        # the platform is not restricted to the model-free set.
        model_attacks = bool(attacker_model) or not ONLY_STATIC
        publish({"type": "attack_setup", "attacker_model": model_attacks})
        capture = BreachCapture(oracle, ALL_CANARIES, lambda snapshot: run.write_json("database_breach", snapshot))

        def make_target(guard):
            target = LedgerPilotTarget(guard=guard)
            if on_target is not None:
                on_target(target)
            watched = capture.watch(target) if guard is None else target  # an unpatched copy's breach is kept
            return TracedTarget(watched, lambda calls: publish({"type": "trace", "calls": calls, "ts": time.time()}))

        # The target database is visible the moment discovery is done (make_target remembers it). A pure PyRIT run
        # also sends one legitimate request, which lights the discovery path and fills the database to inspect.
        try:
            preview = make_target(None)
            preview.reset()
            # Baseline: the clean seeded state every target starts from, so the Database page can mark exactly
            # what the run changed. Captured before the warm-up send, so even that shows as a change.
            run.write_json("database_baseline", preview.database_snapshot())
            if attack_type in {"redteam", "crescendo", "pair", "tap"} and not (control and control.stop_requested):
                preview.send(LEGIT_INVOICE)
        except Exception:  # preview only: it must never abort the assessment
            pass

        assessment = Assessment(
            make_target,
            oracle, profile, ledger, legit=[(LEGIT_INVOICE, not_hijacked)], credentials=creds, blast={},
            facts={"caller_scope": caller_scope()},
            manifest=manifest,
            explainer=None if ONLY_STATIC else explain, scanner=_attack_scanner(profile), repo=TARGET_REPO, anchorer=anchorer,
            codemod_catalog=catalog, codemod_complete=groq_complete, source_snapshots=snapshots,
            reload_target=reload_source,
            decision_baseline={**approved.read_json("decisions"), "run": approved.id} if approved else None,
            verify_trials=5 if advanced else 3)
        # ONLY_STATIC (the demo default): no attacker model, only ``model_free_attacks``; the defender keeps its model
        # for drafting fixes. With the attacker model on, ``full`` uses the targeted attack (it reads each agent's
        # own prompt). ``advanced`` adds disguised and document-buried variants either way.
        selected_strategy = attack_type in {"redteam", "crescendo", "pair", "tap"}
        if selected_strategy:
            templates = []
        elif attack_type == "corpus":
            templates = build_corpus(action_objective(profile.dangerous_tools))
        elif attack_type == "obfuscation":
            templates = [AttackTemplate("obfuscation:canary-action", "obfuscation",
                                        action_objective(profile.dangerous_tools))]
        elif attack_type == "full":  # the custom-dataset suite, then context-aware + adaptive attacks on top
            templates = model_free_attacks(profile) + identity_attacks()
        elif ONLY_STATIC:
            templates = model_free_attacks(profile) + identity_attacks()
        elif advanced:
            templates = None
        else:
            templates = []
        full_assessment = attack_type == "full" and model_attacks
        disguised = (advanced or full_assessment) and attack_type in {"all", "corpus", "full"}
        # Exposure first: every attack meets the unpatched agent, so the breach count is its real exposure; the
        # defender then patches once and every breaching payload is re-attacked against the patched agent.
        report = await assessment.run(templates, timeout=ATTEMPT_TIMEOUT,
                                      untested=[MODEL_ATTACKS_OFF] if not model_attacks else [],
                                      targeted=full_assessment or (not ONLY_STATIC and attack_type == "all"),
                                      on_event=publish, exposure_first=True, adversarial_model=attacker_model,
                                      adaptive=(attack_type if selected_strategy and model_attacks else
                                                "tap" if full_assessment or (attack_type == "all" and advanced
                                                                             and model_attacks) else None),
                                      adaptive_prompt_limit=max_unique_prompts,
                                      disguise_with=(list(OBFUSCATION_TEST_SET) if attack_type == "obfuscation" else
                                                     ["base64"] if disguised else None),
                                      place_with=["buried"] if disguised else None,
                                      control=control)
    finally:
        if signer is not None and hasattr(signer, "close"):
            signer.close()
    run.write_trust(report.trust)  # so this ledger can be re-verified after this process is gone
    if report.decisions:  # pinned by digest in the ledger; the policy rebuilds the exact verified defense
        run.write_json("decisions", report.decisions)
    if report.policy:
        run.write_json("policy", report.policy)
    status = "stopped" if report.scope.get("stopped") else "done"
    run.write_meta(status=status, finished_at=time.time(), safe_to_ship=report.safe_to_ship,
                   findings=len(report.findings), anchor_errors=report.anchor_errors)
    publish({"type": "done", "mode": mode, "status": status, "safe_to_ship": report.safe_to_ship, "run_id": run.id,
             "seconds": time.time() - started, "gate": report.blockers(),  # the same list that decides the verdict
             "residual": report.verification.residual if report.verification else None,
             "modified": [f"{TARGET_REPO.name}/{path}" for path in snapshots.modified()]})
