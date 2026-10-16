"""classify_search: judges every observation a search collected, not just the last one — a tree
branches, so the winning attempt is not necessarily the final call — and reports the winning
attempt (and its extra pattern evidence) as the payload, exactly as honestly as attack.corpus.

run_adaptive itself (the part that drives PAIR/TAP's real search protocol) is not faked here —
see the module docstring for why — and is instead verified live via its own _main() demo, the
same way attack.runner's existing RedTeamingAttack/Crescendo wiring already is."""

import asyncio

from pyrit.setup import IN_MEMORY, initialize_pyrit_async

from purpleteam.adapter import Observation, ToolCall
from purpleteam.attack.adaptive import classify_search
from purpleteam.attack.outcome import BREACHED, HELD, INCONCLUSIVE
from purpleteam.attack.pyrit_target import PlatformPromptTarget
from purpleteam.oracle import CanaryOracle

asyncio.run(initialize_pyrit_async(IN_MEMORY, silent=True))

CANARY = "US00ATTACKER0666"
ORACLE = CanaryOracle({CANARY}, {"schedule_payment"})


class _Piece:
    def __init__(self, text: str) -> None:
        self._text = text

    def get_value(self) -> str:
        return self._text


class _SequencedTarget:
    """Returns the next queued observation on each send, regardless of the request text —
    standing in for a search that tries several different prompts across its branches."""

    def __init__(self, replies: list[Observation]) -> None:
        self._replies = list(replies)

    def reset(self) -> None:
        pass

    def send(self, request: str) -> Observation:
        return self._replies.pop(0)


def _breach() -> Observation:
    return Observation("ok", [ToolCall("payment", "schedule_payment", {"bank_account": CANARY})])


def _held() -> Observation:
    return Observation("ok", [])


def _send_all(wrapper: PlatformPromptTarget, texts: list[str]) -> None:
    async def go() -> None:
        for text in texts:
            await wrapper._send_prompt_to_target_async(normalized_conversation=[_Piece(text)])
    asyncio.run(go())


def test_a_breach_found_on_an_earlier_branch_is_not_missed_by_the_final_call():
    # three branches tried; only the middle one breaches, and it is not the last call made
    wrapper = PlatformPromptTarget(target=_SequencedTarget([_held(), _breach(), _held()]))
    _send_all(wrapper, ["try 1", "try 2 (the one that works)", "try 3"])

    result = asyncio.run(classify_search(wrapper, ORACLE, "tap", "TAP", "objective"))
    assert result.outcome == BREACHED and result.payload == "try 2 (the one that works)"
    assert result.trials == 3


def test_no_breach_across_any_branch_is_held_with_the_last_attempt_as_payload():
    wrapper = PlatformPromptTarget(target=_SequencedTarget([_held(), _held()]))
    _send_all(wrapper, ["try 1", "try 2"])

    result = asyncio.run(classify_search(wrapper, ORACLE, "tap", "TAP", "objective"))
    assert result.outcome == HELD and result.payload == "try 2"
    assert result.trials == 2 and result.conclusive == 2


def test_nothing_sent_is_inconclusive_with_the_objective_as_payload():
    wrapper = PlatformPromptTarget(target=_SequencedTarget([]))

    result = asyncio.run(classify_search(wrapper, ORACLE, "pair", "PAIR", "objective"))
    assert result.outcome == INCONCLUSIVE and result.payload == "objective"


def test_a_breach_attaches_signal_evidence_from_the_winning_observation_only():
    sql_shaped = Observation("ok", [
        ToolCall("payment", "schedule_payment", {"bank_account": CANARY}),
        ToolCall("payment", "run_query", {"filter": "'; DROP TABLE vendors; --"}),
    ])
    wrapper = PlatformPromptTarget(target=_SequencedTarget([_held(), sql_shaped]))
    _send_all(wrapper, ["try 1", "try 2"])

    result = asyncio.run(classify_search(wrapper, ORACLE, "tap", "TAP", "objective"))
    assert result.outcome == BREACHED and result.payload == "try 2"
    assert any(s.scorer == "sql_injection" for s in result.signals)


def test_the_technique_and_attack_id_are_carried_onto_the_result():
    wrapper = PlatformPromptTarget(target=_SequencedTarget([_held()]))
    _send_all(wrapper, ["try 1"])

    result = asyncio.run(classify_search(wrapper, ORACLE, "pair:0", "PAIR", "objective"))
    assert result.id == "pair:0" and result.technique == "PAIR"
