"""The deterministic source fix for an unguarded dangerous tool: replace its first statement with a return
of a gate-marked "held for human approval" message, so the action no longer runs on the model's say-so.

No model drafts this -- it is a fixed transform -- yet it is still proven by the same rescan and independent
invariant as every other codemod before it is written (``source_fix``), and it is exact-match and reversible
like all the rest. It adds no name, call or import: only a return of a string literal.
"""

from __future__ import annotations

import ast
import textwrap

from purpleteam.codemods.base import CodemodCandidate
from purpleteam.gate_scan import GATE_KIND, GATE_TAG
from purpleteam.sast import StaticFinding


def gate_message(tool: str) -> str:
    return f"{GATE_TAG} Held for out-of-band human verification and approval before this action runs: {tool}."


def gate_candidate(finding: StaticFinding, original_statement: str) -> CodemodCandidate | None:
    """A codemod that swaps the one simple statement in ``original_statement`` for the gate return. None when
    it is not exactly one simple statement (a compound header, say) -- then nothing malformed is offered."""
    if finding.kind != GATE_KIND or not finding.subject or not _one_simple_statement(original_statement):
        return None
    indent = original_statement[:len(original_statement) - len(original_statement.lstrip())]
    replacement = f"{indent}return {gate_message(finding.subject)!r}"  # repr: a tool name can never break out
    return CodemodCandidate(GATE_KIND, original_statement, replacement,
                            f"Hold '{finding.subject}' for out-of-band human approval instead of acting directly.")


def _one_simple_statement(statement: str) -> bool:
    try:
        tree = ast.parse(textwrap.dedent(statement))
    except SyntaxError:
        return False
    return len(tree.body) == 1 and not hasattr(tree.body[0], "body")
