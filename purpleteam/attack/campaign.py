"""Run one adaptive attack campaign against the LedgerPilot demo target and print the verdict.

    uv run python -m purpleteam.attack.campaign

Uses the real target model and a Groq-hosted attacker, so it consumes tokens. Keep
max_turns small on free tiers.
"""

import asyncio

from dotenv import load_dotenv

from purpleteam.attack.corpus import CANARY_MARK, action_objective
from purpleteam.attack.runner import run_campaign
from purpleteam.oracle import CANARY_ACCOUNT
from purpleteam.targets.ledgerpilot import LedgerPilotTarget, discover_profile


async def main() -> None:
    load_dotenv()
    dangerous = discover_profile().dangerous_tools
    result = await run_campaign(
        LedgerPilotTarget(), objective=action_objective(dangerous).replace(CANARY_MARK, CANARY_ACCOUNT),
        strategy="redteam", dangerous_tools=dangerous, max_turns=3,
    )
    print(f"\n{result.outcome.upper()} — {result.detail}")
    for i, attempt in enumerate(result.attempts, 1):
        print(f"  attempt {i}: {attempt[:160].strip()}")


if __name__ == "__main__":
    asyncio.run(main())
