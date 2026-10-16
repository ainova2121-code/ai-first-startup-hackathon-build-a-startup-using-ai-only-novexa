"""Deterministic PyRIT output scorers, run over a proven breach's tool traffic as extra, specific evidence of
what kind of exploit pattern was present — never as a judge of whether a breach happened. The proof-based
oracle (``purpleteam.oracle``) is the only thing that decides a breach; these only describe one more precisely
once it is already proven, by pattern-matching text with no model call.

Six scorers, all already in PyRIT and all regex-based: SQL injection, SSRF (cloud-metadata and internal-address
probes), path traversal, shell command injection, credential leakage, and server-side template injection. A
``Signal`` names which pattern matched (e.g. "Destructive SQL", "Cloud Metadata Endpoint") and where (a tool
argument, a tool result, or the final reply) — sharper evidence for a report than "a canary reached a tool"
alone, and each maps to its own OWASP/CWE category.

Needs ``initialize_pyrit_async`` to have run first, same as every other PyRIT-backed module here; the caller
that already runs the corpus (``attack.corpus.run_corpus``) has always done this before a signal is scanned.
"""

from __future__ import annotations

from dataclasses import dataclass

from pyrit.score import (
    CredentialLeakScorer, PathTraversalOutputScorer, SQLInjectionOutputScorer, SSRFOutputScorer,
    SSTIOutputScorer, ShellCommandOutputScorer)

from purpleteam.adapter import Observation

SCORERS = {
    "sql_injection": SQLInjectionOutputScorer(),
    "ssrf": SSRFOutputScorer(),
    "path_traversal": PathTraversalOutputScorer(),
    "shell_command": ShellCommandOutputScorer(),
    "credential_leak": CredentialLeakScorer(),
    "template_injection": SSTIOutputScorer(),
}


@dataclass(frozen=True)
class Signal:
    scorer: str   # which named scorer matched, e.g. "sql_injection" (a key of SCORERS)
    pattern: str  # the specific sub-pattern that matched, e.g. "Destructive SQL"
    where: str    # "argument" | "result" | "reply"
    tool: str = ""
    agent: str = ""


async def scan_observation(observation: Observation) -> list[Signal]:
    """Every deterministic signal found across a breach's tool arguments, tool results and final reply."""
    signals: list[Signal] = []
    for call in observation.tool_calls:
        for value in call.args.values():
            signals += await _scan_text(str(value), "argument", call.tool, call.agent)
        if call.result:
            signals += await _scan_text(call.result, "result", call.tool, call.agent)
    signals += await _scan_text(observation.reply, "reply")
    return signals


async def _scan_text(text: str, where: str, tool: str = "", agent: str = "") -> list[Signal]:
    if not text:
        return []
    found: list[Signal] = []
    for name, scorer in SCORERS.items():
        for score in await scorer.score_text_async(text=text):
            if score.score_value == "true":
                pattern = (score.score_rationale or "").removeprefix("Matched: ") or name
                found.append(Signal(name, pattern, where, tool, agent))
    return found
