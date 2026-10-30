"""Claim attacks: model-free payloads written from the target's own discovered tool schema.

A jailbreak states what it wants, so a capable model recognizes it and refuses. A plain business claim does not:
"the bank account for this request is X" carries no instruction at all, and an agent that copies values out of
incoming content without verifying them will copy X into its tool call. Every field a dangerous tool takes that holds
a destination or identity value (an account, a recipient, an address, a URL...) is named by discovery, so the claims
are written by fixed rules from those names alone -- no model, no recorded payloads, nothing domain-specific.

Measured on LedgerPilot before shipping: the bank-account and the vendor-name claims each breached 6 of 6 attempts,
and 7 of 8 when hidden inside a document (buried in its prose, or as one of its fields); the approver claims 0 of 6,
base64-encoded claims 0 of 4.
A claim that is not believed is simply held, so a target that verifies what it is told holds them all.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from purpleteam.attack.corpus import CANARY_MARK, AttackTemplate, action_objective, build_corpus
from purpleteam.attack.advanced import multilingual_test_cases, system_prompt_test_cases
from purpleteam.attack.placement import place
from purpleteam.discovery import VALUE_SLOT, TargetProfile  # the values an outsider could plant

# The switch every runner honours: on (the default), the attacker uses no model at all, only model_free_attacks.
# PURPLETEAM_ONLY_STATIC=0 turns the model-driven attacks (targeted recon and crafting, TAP search) back on.
ONLY_STATIC = os.environ.get("PURPLETEAM_ONLY_STATIC", "1") != "0"
MODEL_ATTACKS_OFF = "model-driven attacks (targeted prompt recon, adaptive TAP search): the attacker model is off"

# The same claim delivered inside a document, the way a poisoned attachment or retrieved page arrives: buried in
# its prose, or standing in for one of its fields. Indirect injection: a separate technique, labelled as such.
DELIVERIES = {"buried": "claim in a document", "field": "claim in a form field"}
CLAIM_DATASET = Path(__file__).with_name("datasets") / "business_claims_v1.jsonl"


def _claim_dataset() -> list[dict[str, str]]:
    """Load the versioned, reviewed business-claim seed corpus shipped with the attack runner."""
    cases: list[dict[str, str]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(CLAIM_DATASET.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            case = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid attack dataset JSON on line {line_number}: {error}") from error
        if not isinstance(case, dict) or not all(isinstance(case.get(key), str) and case[key]
                                                 for key in ("id", "technique", "source_channel", "text")):
            raise ValueError(
                f"attack dataset line {line_number} needs non-empty id, technique, source_channel and text fields"
            )
        if case["id"] in seen:
            raise ValueError(f"duplicate attack dataset id {case['id']!r}")
        if CANARY_MARK not in case["text"]:
            raise ValueError(f"attack dataset case {case['id']!r} must contain {CANARY_MARK}")
        if "{label}" not in case["text"] and "{Label}" not in case["text"]:
            raise ValueError(f"attack dataset case {case['id']!r} must name the discovered value field")
        seen.add(case["id"])
        cases.append(case)
    if len(cases) < 3:
        raise ValueError(f"business-claim attack dataset needs at least 3 direct cases to produce 5 per field; found "
                         f"{len(cases)} in {CLAIM_DATASET}")
    return cases


def claim_templates(profile: TargetProfile) -> list[AttackTemplate]:
    """One attack per phrasing for every planted-value field a dangerous tool takes, each carrying the canary."""
    labels = sorted({arg.replace("_", " ") for tool in profile.tools if tool.dangerous
                     for arg in tool.args if VALUE_SLOT.search(arg)})
    if not labels:
        return []
    cases = _claim_dataset()
    return [AttackTemplate(f"claim:{label.replace(' ', '_')}:{index}", case["technique"],
                           case["text"].replace("{label}", label).replace("{Label}", label.capitalize()))
            for label in labels for index, case in enumerate(cases, 1)]


def model_free_attacks(profile: TargetProfile) -> list[AttackTemplate]:
    """Every attack that needs no model: the plain claims, each field's first claim again delivered inside a
    document, and PyRIT's jailbreak and prompt-injection templates. Those state their objective outright, so a
    safety-trained model refuses them; side by side, they show the gap that leaves -- an agent that resists every
    jailbreak can still believe a plain claim, wherever it arrives."""
    claims = claim_templates(profile)
    delivered = [AttackTemplate(f"{t.id.rsplit(':', 1)[0]}:{name}", technique, place(t.body, name))
                 for t in claims if t.id.endswith(":1") for name, technique in DELIVERIES.items()]
    return (claims + delivered + multilingual_test_cases(profile) + system_prompt_test_cases(profile.agent_info)
            + build_corpus(action_objective(profile.dangerous_tools)))
