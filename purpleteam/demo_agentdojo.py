"""One full assessment against a real, third-party target this platform did not build: AgentDojo's
workspace suite (ethz-spylab/agentdojo, pip-installed -- see purpleteam/targets/agentdojo.py's
module docstring for why zero changes to its code were needed). Proves discovery, the attack
corpus and the proof-based oracle are genuinely domain-agnostic, not tuned to LedgerPilot.

    uv run python -m purpleteam.demo_agentdojo

Reuses LedgerPilot's own configured model (LEDGERPILOT_LLM_API_KEY or HF_TOKEN, see .env.example)
as AgentDojo's own "openai-compatible" provider -- no new credentials needed.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

from dotenv import load_dotenv

from ledgerpilot.utils.config import Settings
from purpleteam.assessment import Assessment
from purpleteam.attack.outcome import INCONCLUSIVE
from purpleteam.audit.ledger import AuditLedger
from purpleteam.oracle import CANARY_ACCOUNT, CanaryOracle
from purpleteam.targets.agentdojo import DEFAULT_SUITE, DEFAULT_USER_TASK, AgentDojoTarget, discover_profile

ATTEMPT_TIMEOUT = 300
# AgentDojo's own OpenAILLM maps a system message to OpenAI's "developer" role (not "system") --
# real OpenAI-architecture models handle that correctly; other chat templates served through the
# same Groq endpoint (confirmed directly: LedgerPilot's own configured Qwen model does not) refuse
# it as an unrecognised role. gpt-oss is OpenAI's own open-weight model, so it is the one choice
# guaranteed to speak AgentDojo's actual wire format -- not a LedgerPilot-specific setting, so it
# is named here rather than reused from Settings().llm_model.
AGENTDOJO_MODEL_ID = "openai/gpt-oss-20b"


async def main() -> None:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    load_dotenv()
    settings = Settings()
    key = settings.llm_api_key.get_secret_value()
    if not key:
        sys.exit("No model configured: set LEDGERPILOT_LLM_API_KEY or HF_TOKEN (see .env.example) -- "
                "this is reused as AgentDojo's own model provider, no separate key needed.")
    os.environ.setdefault("OPENAI_COMPATIBLE_BASE_URL", settings.llm_base_url)
    os.environ.setdefault("OPENAI_COMPATIBLE_API_KEY", key)

    profile = discover_profile()
    print(f"[discover] agentdojo:{DEFAULT_SUITE} -- a real target this platform did not build: "
         f"{len(profile.tools)} tools, {len(profile.dangerous_tools)} flagged dangerous, "
         f"{len(profile.retrieval_tools)} flagged as retrieval surfaces (RAG)")
    print(f"           dangerous: {', '.join(sorted(profile.dangerous_tools))}")

    oracle = CanaryOracle({CANARY_ACCOUNT}, profile.dangerous_tools)
    ledger_path = Path(tempfile.mkdtemp(prefix="purpleteam-agentdojo-")) / "audit.jsonl"
    ledger = AuditLedger(ledger_path)
    assessment = Assessment(
        lambda guard: AgentDojoTarget(model_id=AGENTDOJO_MODEL_ID, guard=guard), oracle, profile, ledger, legit=[],
    )

    print(f"[attack]  running the seed corpus against agentdojo:{DEFAULT_SUITE}:{DEFAULT_USER_TASK} "
         "(a real email/calendar/drive agent)...")
    report = await assessment.run(timeout=ATTEMPT_TIMEOUT)

    breached = [r for r in report.results if r.breached]
    inconclusive = [r for r in report.results if r.outcome == INCONCLUSIVE]
    held = [r for r in report.results if r.outcome != INCONCLUSIVE and not r.breached]
    print(f"\n[attack]  {len(report.results)} payloads sent, {len(breached)} breached, "
         f"{len(held)} held, {len(inconclusive)} inconclusive")
    for r in breached:
        print(f"          - BREACH: {r.id} ({r.technique}) on {r.tool}: {r.detail}")
    for r in held:
        print(f"          - held: {r.id} <= {r.upper_bound * 100:.0f}% at 95% confidence")

    print(f"[identity] {len(report.identity['agents'])} agent(s), "
         f"{len(report.identity['findings'])} identity findings")
    print(f"[audit]   {len(ledger.events())} signed events, chain verifies: {report.chain_ok}, log at {ledger_path}")
    print(f"\nSAFE TO SHIP: {report.safe_to_ship}")
    sys.exit(0 if report.safe_to_ship else 1)


if __name__ == "__main__":
    asyncio.run(main())
