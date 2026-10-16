"""Explainer: an LLM writes the plain-language account, a deterministic verifier proves it.

The model (default openai/gpt-oss-20b, configurable) phrases the explanation from the
engagement's facts — what the attack did, why it matters, which patch stopped it, which
regulation it satisfies. Because an audit explanation must never hallucinate, every generated
explanation is checked against the facts before it is accepted: it must state the required
facts, must not mention a patch or clause that was not applied, and must not leak a secret. If
it cannot be verified after retries, only the structured facts are kept — never unverified prose.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from purpleteam.audit.compliance import controls_for
from purpleteam.oracle import CANARY_ACCOUNT, HONEYTOKEN
from purpleteam.patches.catalog import PATCH_SUMMARY

DEFAULT_MODEL = "openai/gpt-oss-20b"
DEFAULT_ENDPOINT = "https://api.groq.com/openai/v1"

_PATCH_RE = re.compile(r"\bP\d+\b")
_CLAUSE_RE = re.compile(r"Art\.?\s*\d+|LLM\d+")

_SYSTEM = (
    "You explain an AI-agent security finding for a compliance report. Use ONLY the facts in "
    "the JSON. Do not invent tools, patches, regulations, numbers, or account values. Write four "
    "short labelled lines — What happened, Why it matters, What stops it, Regulation. Refer to "
    "the tool, agent, patch IDs and regulation labels EXACTLY as written in the facts. Never "
    "output an account number or secret value."
)


@dataclass
class Explanation:
    facts: dict
    text: str = ""
    verified: bool = False
    issues: list[str] = field(default_factory=list)


def gather_facts(finding: Any, defense: Any = None, verdict: Any = None) -> dict:
    patch_ids = list(getattr(defense, "patch_ids", []) or [])
    clauses = ([f"{c.framework} {c.clause}" for c in
                controls_for({"kind": "patch", "payload": {"patch_ids": patch_ids}})]
               if patch_ids else [])
    facts = {
        "agent": finding.agent,
        "tool": finding.tool,
        "kind": finding.kind,
        "proof": finding.detail,
        "patches": [{"id": p, "does": PATCH_SUMMARY.get(p, "")} for p in patch_ids],
        "regulation": clauses,
    }
    if verdict is not None:
        facts["verdict"] = {"attack_blocked": verdict.attack_blocked, "safe_to_ship": verdict.safe_to_ship}
    return facts


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _required_tokens(facts: dict) -> list[str]:
    tokens = [facts["tool"], facts["agent"], *[p["id"] for p in facts["patches"]]]
    for clause in facts["regulation"]:
        match = _CLAUSE_RE.search(clause)
        if match:
            tokens.append(match.group(0))
    return tokens


def _allowed_codes(facts: dict) -> set[str]:
    codes = {p["id"] for p in facts["patches"]}
    for clause in facts["regulation"]:
        codes.update(_CLAUSE_RE.findall(clause))
    return {_norm(c) for c in codes}


def verify_explanation(text: str, facts: dict) -> tuple[bool, list[str]]:
    issues: list[str] = []
    normalized = _norm(text)
    for token in _required_tokens(facts):
        if _norm(token) not in normalized:
            issues.append(f"missing fact: {token}")
    allowed = _allowed_codes(facts)
    for entity in _PATCH_RE.findall(text) + _CLAUSE_RE.findall(text):
        if _norm(entity) not in allowed:
            issues.append(f"unsupported claim: {entity}")
    for secret in (CANARY_ACCOUNT, HONEYTOKEN):
        if secret in text:
            issues.append("leaked a sensitive value")
    return (not issues, issues)


def _llm_generate(facts: dict, issues: list[str]) -> str:
    from openai import OpenAI

    key = (os.environ.get("PURPLETEAM_EXPLAINER_KEY") or os.environ.get("GROQ_API_KEY")
           or os.environ.get("LEDGERPILOT_LLM_API_KEY"))
    if not key:
        raise RuntimeError("Set PURPLETEAM_EXPLAINER_KEY / GROQ_API_KEY / LEDGERPILOT_LLM_API_KEY.")
    client = OpenAI(base_url=os.environ.get("PURPLETEAM_EXPLAINER_ENDPOINT", DEFAULT_ENDPOINT), api_key=key)
    user = "Facts:\n" + json.dumps(facts, indent=2)
    if issues:
        user += "\n\nYour previous attempt had these problems; fix them and use the exact labels:\n- " \
            + "\n- ".join(issues)
    response = client.chat.completions.create(
        model=os.environ.get("PURPLETEAM_EXPLAINER_MODEL", DEFAULT_MODEL),
        temperature=0.2, max_tokens=300,
        messages=[{"role": "system", "content": _SYSTEM}, {"role": "user", "content": user}],
    )
    return (response.choices[0].message.content or "").strip()


def explain(finding: Any, defense: Any = None, verdict: Any = None, *,
            generate: Callable[[dict, list[str]], str] | None = None, max_retries: int = 2) -> Explanation:
    facts = gather_facts(finding, defense, verdict)
    generate = generate or _llm_generate
    issues: list[str] = []
    for _ in range(max(1, max_retries + 1)):
        text = generate(facts, issues)
        ok, issues = verify_explanation(text, facts)
        if ok:
            return Explanation(facts=facts, text=text, verified=True)
    return Explanation(facts=facts, text="", verified=False, issues=issues)
