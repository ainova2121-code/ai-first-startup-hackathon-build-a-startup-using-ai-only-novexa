"""The deterministic source fix for an unhardened prompt or tool description: append a fixed hardening
clause as an adjacent string literal, so the text that reaches the model frames untrusted input as data.

No model drafts this -- it is a fixed transform -- yet it is still proven by the same rescan and
independent invariant as every other codemod before it is written (``source_fix``), and it is exact-match
and reversible like all the rest. The runtime P15 guard stays on; this bakes the same protection into code.
"""

from __future__ import annotations

import ast
import textwrap

from purpleteam.codemods.base import CodemodCandidate
from purpleteam.hardening_scan import HARDENING_CLAUSE, HARDENING_KINDS, PROMPT_KIND
from purpleteam.sast import StaticFinding


def _adjacent_literal() -> str:
    """A Python source token for a string literal whose value is two newlines then the clause. Placed next
    to the existing literal, Python concatenates the two at parse time -- so the fix adds no name, call or
    import, only text. The clause has no quote or backslash of its own, so no further escaping is needed."""
    return '"\\n\\n' + HARDENING_CLAUSE + '"'


def hardening_candidate(finding: StaticFinding, original_statement: str) -> CodemodCandidate | None:
    """A codemod that appends the hardening clause to the one string literal in ``original_statement``.
    None when the statement does not end in a string literal the clause can attach to -- then nothing is
    offered rather than something malformed (``source_fix`` would reject it on verification anyway)."""
    if finding.kind not in HARDENING_KINDS or not _ends_in_string(original_statement):
        return None
    what = "system prompt" if finding.kind == PROMPT_KIND else "tool description"
    replacement = f"{original_statement} {_adjacent_literal()}"
    return CodemodCandidate(finding.kind, original_statement, replacement,
                            f"Append a fixed injection-hardening clause to the {what}.")


def _ends_in_string(statement: str) -> bool:
    """True when the statement's last expression is a string literal (a constant assignment or a bare
    docstring), so an adjacent literal attaches to it and to nothing else."""
    try:
        tree = ast.parse(textwrap.dedent(statement))
    except SyntaxError:
        return False
    if not tree.body:
        return False
    node = tree.body[-1]
    value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Expr)) else None
    return isinstance(value, ast.Constant) and isinstance(value.value, str)
