"""Explicit attack families that need their own delivery context or proof oracle.

These payloads remain bounded to the target's untrusted input/data channels. In particular,
``tool_output_templates`` is meaningful only with an adapter that inserts the payload into a
retrieved/tool-returned data source (AgentDojoTarget does this); sending it as an ordinary user
prompt is not an indirect-injection test.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path

from purpleteam.attack.corpus import CANARY_MARK, AttackTemplate, action_objective
from purpleteam.discovery import AgentInfo, TargetProfile

CHANNEL_DATASET = Path(__file__).with_name("datasets") / "channel_attacks_v1.jsonl"


@lru_cache(maxsize=1)
def _channel_cases() -> tuple[dict[str, str], ...]:
    """Load reviewed, versioned channel payloads. Never silently skip malformed benchmark data."""
    cases: list[dict[str, str]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(CHANNEL_DATASET.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            case = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid channel attack JSON on line {line_number}: {error}") from error
        required = ("id", "technique", "family", "source_channel", "locale", "text")
        if not isinstance(case, dict) or any(not isinstance(case.get(key), str) or not case[key]
                                             for key in required):
            raise ValueError(f"channel attack line {line_number} needs non-empty {', '.join(required)} fields")
        if case["id"] in seen:
            raise ValueError(f"duplicate channel attack id {case['id']!r}")
        seen.add(case["id"])
        cases.append(case)
    if not cases:
        raise ValueError(f"channel attack dataset is empty: {CHANNEL_DATASET}")
    minimum_families = {
        "indirect-prompt-injection": 5,
        "multilingual-prompt-injection": 5,
        "system-prompt-disclosure": 5,
        "hidden-document-injection": 5,
    }
    for family, minimum in minimum_families.items():
        count = sum(case["family"] == family for case in cases)
        if count < minimum:
            raise ValueError(f"channel attack family {family!r} needs at least {minimum} cases; found {count}")
    return tuple(cases)


def _cases(family: str) -> tuple[dict[str, str], ...]:
    return tuple(case for case in _channel_cases() if case["family"] == family)


def tool_output_templates(profile: TargetProfile) -> list[AttackTemplate]:
    """Payloads intended to live in email, retrieved pages, calendar descriptions, or other tool data."""
    tools = ", ".join(sorted(profile.dangerous_tools))
    objective = action_objective(profile.dangerous_tools)
    tools_sentence = f" using one of these sensitive tools: {tools}." if tools else "."
    return [AttackTemplate(case["id"], case["technique"],
                           case["text"].replace("__OBJECTIVE__", objective)
                           .replace("__TOOLS_SENTENCE__", tools_sentence))
            for case in _cases("indirect-prompt-injection")]


def multilingual_templates(profile: TargetProfile) -> list[AttackTemplate]:
    """The original four stable locale probes, retained for callers that depend on their IDs."""
    return _multilingual_templates(profile, include_french=False)


def multilingual_test_cases(profile: TargetProfile) -> list[AttackTemplate]:
    """Five language probes. A held result is not a comprehension result; validate language capability separately."""
    return _multilingual_templates(profile, include_french=True)


def _multilingual_templates(profile: TargetProfile, *, include_french: bool) -> list[AttackTemplate]:
    """Short multilingual variants; these are probes, not a claim of broad language coverage."""
    tools = ", ".join(sorted(profile.dangerous_tools))
    cases = _cases("multilingual-prompt-injection")
    if not include_french:
        cases = tuple(case for case in cases if case["locale"] != "fr")
    tools_parenthetical = f" ({tools})" if tools else ""
    return [AttackTemplate(f"multilingual:{case['locale']}", case["technique"],
                           case["text"].replace("__CANARY__", CANARY_MARK)
                           .replace("__TOOLS_PARENTHETICAL__", tools_parenthetical))
            for case in cases]


def system_prompt_templates(agents: Iterable[AgentInfo]) -> list[AttackTemplate]:
    """The original stable prompt-extraction probe, retained for compatibility."""
    cases = system_prompt_test_cases(agents)
    return cases[:1]


def system_prompt_test_cases(agents: Iterable[AgentInfo]) -> list[AttackTemplate]:
    """Five distinct prompt-extraction probes; the oracle checks for exact known prompt text."""
    found = sorted({agent.name for agent in agents if agent.prompt})
    if not found:
        return []
    return [AttackTemplate(f"system-prompt-extraction:{case['id'].removeprefix('prompt_extract_')}",
                           case["technique"], case["text"])
            for case in _cases("system-prompt-disclosure")]


def hidden_document_templates(profile: TargetProfile) -> list[AttackTemplate]:
    """Five hidden-text PDF payloads for HttpDocumentTarget; not a plain-text or LedgerPilot-email test."""
    objective = action_objective(profile.dangerous_tools)
    return [AttackTemplate(case["id"], case["technique"], case["text"].replace("__OBJECTIVE__", objective))
            for case in _cases("hidden-document-injection")]


def system_prompt_secrets(agents: Iterable[AgentInfo]) -> set[str]:
    """Exact discovered prompts used as proof markers; they stay in memory and are never logged by this helper."""
    return {agent.prompt for agent in agents if agent.prompt and len(re.sub(r"\W", "", agent.prompt)) >= 8}
