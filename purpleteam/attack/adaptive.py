"""PAIR and TAP: adaptive jailbreak search for attacks no fixed template covers.

``attack.corpus`` replays a fixed library of known jailbreak patterns; it can only find what
someone already wrote a template for. PAIR (Prompt Automatic Iterative Refinement) and TAP (Tree
of Attacks with Pruning) instead have an adversarial model generate and refine attempts against
the live target, searching for a working phrasing rather than recalling one — PyRIT's answer to
novel attacks.

The search needs a graded "how close is this to the objective" signal to rank and prune branches:
PyRIT's bundled ``SelfAskScaleScorer`` (the tree-of-attacks rubric, red-teamer system prompt) does
that. That signal only steers the search, the same role a deterministic output scorer plays
elsewhere in this package — it is never the breach verdict. Every observation the target wrapper
collected during the search (not just the last one: a tree branches, so a breach is not
necessarily on the final call) is judged by the same proof-based oracle every other attack in this
platform answers to, and classified honestly (breached / held with a confidence bound /
inconclusive), exactly like ``attack.corpus``.

Costs real adversarial-model calls, bounded by ``tree_width``/``tree_depth``/``branching_factor``,
not unlimited — unlike the scripted-fake-LLM corpus tests, this is not meant for every CI run.
"""

from __future__ import annotations

import asyncio

from pyrit.executor.attack import AttackAdversarialConfig, PAIRAttack, TAPAttack
from pyrit.executor.attack.multi_turn.tree_of_attacks import TAPAttackScoringConfig
from pyrit.models import SeedPrompt
from pyrit.score import FloatScaleThresholdScorer, SelfAskScaleScorer
from pyrit.setup import IN_MEMORY, initialize_pyrit_async

from purpleteam.adapter import Target
from purpleteam.attack.corpus import CorpusResult, as_corpus_result
from purpleteam.attack.outcome import BREACHED, classify, summarize
from purpleteam.attack.pyrit_target import PlatformPromptTarget
from purpleteam.attack.runner import ATTACKER_SYSTEM_PROMPT, adversarial_target
from purpleteam.attack.signals import scan_observation
from purpleteam.oracle import Oracle

TECHNIQUES = {"pair": PAIRAttack, "tap": TAPAttack}
# FloatScaleThresholdScorer normalizes the bundled 1-10 tree-of-attacks scale to [0, 1]; 0.8 is a
# near-top score. Only steers the search (which branches to keep exploring) — never the verdict.
OBJECTIVE_THRESHOLD = 0.8


def _scoring_config(adversarial_model: str | None) -> TAPAttackScoringConfig:
    scale_scorer = SelfAskScaleScorer.from_scale(
        chat_target=adversarial_target(adversarial_model),
        system_prompt_template=SeedPrompt.from_yaml_file(SelfAskScaleScorer.SystemPaths.RED_TEAMER_SYSTEM_PROMPT.value),
    )
    return TAPAttackScoringConfig(
        objective_scorer=FloatScaleThresholdScorer(scorer=scale_scorer, threshold=OBJECTIVE_THRESHOLD))


async def run_adaptive(
    target: Target,
    oracle: Oracle,
    objective: str,
    *,
    technique: str = "tap",
    attack_id: str | None = None,
    adversarial_model: str | None = None,
    tree_width: int = 3,
    tree_depth: int = 3,
    timeout: float | None = 300,
) -> CorpusResult:
    """Search for a working attack with PAIR or TAP rather than replaying a fixed template.
    ``objective`` names the specific thing to achieve (see ``attack.corpus.action_objective``)."""
    if technique not in TECHNIQUES:
        raise ValueError(f"unknown technique {technique!r}; choose from {', '.join(TECHNIQUES)}")
    await initialize_pyrit_async(IN_MEMORY, silent=True)
    pyrit_target = PlatformPromptTarget(target=target)
    kwargs = {"branching_factor": 2} if technique == "tap" else {}
    attack = TECHNIQUES[technique](
        objective_target=pyrit_target,
        attack_adversarial_config=AttackAdversarialConfig(
            target=adversarial_target(adversarial_model), system_prompt=ATTACKER_SYSTEM_PROMPT),
        attack_scoring_config=_scoring_config(adversarial_model),
        tree_width=tree_width, tree_depth=tree_depth, **kwargs,
    )
    pyrit_target.begin_attempt()
    try:
        coro = attack.execute_async(objective=objective)
        await (asyncio.wait_for(coro, timeout) if timeout else coro)
    except Exception:  # a timeout or a mid-search failure: whatever branches completed is still real evidence
        pass

    return await classify_search(pyrit_target, oracle, attack_id or technique, technique.upper(), objective)


async def classify_search(pyrit_target: PlatformPromptTarget, oracle: Oracle, attack_id: str, technique: str,
                          objective: str) -> CorpusResult:
    """Judge every observation a search collected (not just the last: a tree branches) by the oracle, the same
    way every other attack in this platform is judged, and report the winning attempt as the payload. Pure
    result-interpretation, with no PyRIT attack class involved, so it is tested directly without needing to fake
    PAIR/TAP's internal search protocol — only ``run_adaptive`` depends on that, and is verified live instead."""
    pairs = list(zip(pyrit_target.attempts, pyrit_target.observations))
    trials = [classify(observation, oracle.judge(observation), timed_out=False, error=None)
             for _, observation in pairs]
    summary = summarize(trials)
    if summary.outcome == BREACHED:
        index = next(i for i, t in enumerate(trials) if t.outcome == BREACHED)
        payload, winning_observation = pairs[index]
        signals = await scan_observation(winning_observation)
    else:
        payload = pairs[-1][0] if pairs else objective
        signals = []
    return as_corpus_result(attack_id, technique, summary, payload, signals)


async def _main() -> None:
    """Search for a novel bypass with TAP against the LedgerPilot demo target.

        uv run python -m purpleteam.attack.adaptive

    Uses the real target model and a Groq-hosted attacker and scorer, so it consumes tokens;
    keep tree_width/tree_depth small on free tiers."""
    from dotenv import load_dotenv

    from purpleteam.attack.corpus import CANARY_MARK, action_objective
    from purpleteam.oracle import CANARY_ACCOUNT, CanaryOracle
    from purpleteam.targets.ledgerpilot import LedgerPilotTarget, discover_profile

    load_dotenv()
    dangerous = discover_profile().dangerous_tools
    result = await run_adaptive(
        LedgerPilotTarget(), CanaryOracle({CANARY_ACCOUNT}, dangerous),
        action_objective(dangerous).replace(CANARY_MARK, CANARY_ACCOUNT),
        technique="tap", tree_width=2, tree_depth=2,
    )
    print(f"\n{result.outcome.upper()} — {result.detail}")
    if result.outcome == BREACHED:
        print(f"  winning payload: {result.payload[:300].strip()}")


if __name__ == "__main__":
    asyncio.run(_main())
