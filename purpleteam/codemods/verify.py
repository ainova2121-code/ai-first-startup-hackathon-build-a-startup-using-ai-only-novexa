"""Re-verify a drafted candidate against the same scanner that found the original issue.

Never trust the model's claim that it fixed something — prove it the same way every other claim
in this platform is proven: re-check with an independent, deterministic tool, on a throwaway
scratch copy, never the target's real file.
"""

from __future__ import annotations

import ast
import builtins
import tempfile
import textwrap
from collections import Counter
from pathlib import Path

from purpleteam.codemods.base import CodemodCandidate, VerificationFailed, VerifiedCodemod
from purpleteam.codemods.context import occurrence
from purpleteam.codemods.invariants import INVARIANTS
from purpleteam.sast import ScanFailed, Scanner, StaticFinding


def verify(candidate: CodemodCandidate, finding: StaticFinding, file_path: Path, scanner: Scanner) -> VerifiedCodemod:
    """Raises VerificationFailed (never returns a half-checked result) unless: the patched file
    still parses, no finding of this kind is left on the replaced lines, the fix introduced no new
    finding (a finding is identified by its kind and the source text of its line, so a pre-existing,
    unrelated issue elsewhere in the file -- even one of the same kind -- is never blamed on this
    fix), and -- when one exists for this kind (``codemods.invariants``) -- an independent,
    differently-implemented check of the replacement itself also passes; a clean re-scan alone is
    never presented as more than it is."""
    original_text = file_path.read_text(encoding="utf-8")
    at = occurrence(original_text, candidate.original, finding.line)
    if at < 0:
        raise VerificationFailed("the original line(s) no longer match the file; stale finding")
    patched_text = original_text[:at] + candidate.replacement + original_text[at + len(candidate.original):]
    try:
        ast.parse(patched_text)
    except SyntaxError as error:
        raise VerificationFailed(f"the candidate does not parse: {error}") from error
    _no_new_capabilities(candidate, original_text)

    first = original_text[:at].count("\n") + 1
    last = first + candidate.replacement.count("\n")
    before = _scan_text(scanner, file_path.name, original_text)
    after = _scan_text(scanner, file_path.name, patched_text)
    if any(f.kind == finding.kind and first <= f.line <= last for f in after):
        raise VerificationFailed("the finding is still reported after the fix")
    introduced = Counter(_identity(f, patched_text) for f in after) - Counter(_identity(f, original_text) for f in before)
    if introduced:
        kinds = sorted({kind for kind, _ in introduced})
        raise VerificationFailed(f"the fix introduced new finding kind(s): {', '.join(kinds)}")

    verified_by = ["rescan"]
    checker = INVARIANTS.get(finding.kind)
    if checker is not None:
        problem = checker(textwrap.dedent(candidate.replacement))
        if problem is not None:
            raise VerificationFailed(f"independent security invariant failed: {problem}")
        if _discriminates(checker, candidate.original):
            verified_by.append("invariant")
    return VerifiedCodemod(finding.kind, candidate.original, candidate.replacement, candidate.explanation,
                           verified_by=tuple(verified_by))


def _called_names(tree: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            names.add(func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", ""))
    return names


def _no_new_capabilities(candidate: CodemodCandidate, original_text: str) -> None:
    """A model-written fix stays a local fix: no new imports and no sprawl (see ``new_calls`` for the
    stricter bar an auto-applied fix must also meet)."""
    if candidate.replacement.count("\n") > candidate.original.count("\n") + _MAX_ADDED_LINES:
        raise VerificationFailed(f"the fix adds more than {_MAX_ADDED_LINES} lines; too broad to apply")
    try:
        replacement, known = ast.parse(textwrap.dedent(candidate.replacement)), _known(original_text)
    except SyntaxError as error:
        raise VerificationFailed(f"the fix cannot be checked on its own: {error}") from error
    if any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(replacement)):
        raise VerificationFailed("the fix adds an import")
    undefined = _loaded(replacement) - known - _stored(replacement) - set(dir(builtins))
    if undefined:  # e.g. ast.literal_eval in a file that never imports ast: clean on every check, broken at runtime
        raise VerificationFailed(f"the fix uses names its file never defines: {', '.join(sorted(undefined))}")


def _loaded(tree: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _stored(tree: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and not isinstance(n.ctx, ast.Load)}


def _known(text: str) -> set[str]:
    """Every name the file mentions, binds or imports (a deliberately generous notion of "defined")."""
    names = set()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.alias):
            names.add((node.asname or node.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return names


def new_calls(original_text: str, replacement: str) -> set[str]:
    """Calls a fix makes that its file never did (beyond raising a standard error or converting a
    value). Every security check can pass while a fix quietly adds behaviour -- a network call, a file
    write -- so a fix that adds any call is never auto-applied, only offered for human review."""
    try:
        added = _called_names(ast.parse(textwrap.dedent(replacement)))
        return added - _called_names(ast.parse(original_text)) - _SAFE_CALLS
    except SyntaxError:
        return {"<unparseable>"}


_MAX_ADDED_LINES = 12
_SAFE_CALLS = {"ValueError", "KeyError", "TypeError", "LookupError", "PermissionError", "tuple", "list", "dict",
               "set", "frozenset", "str", "int", "float", "bool", "len", "isinstance", "get",
               # strictly narrower stand-ins for what the scanner flags: they can only do less
               "safe_load", "safe_load_all", "literal_eval", "sha256", "sha384", "sha512", "sha3_256", "blake2b"}


def _discriminates(checker, original: str) -> bool:
    """An invariant is evidence for a fix only if it also rejects the code being replaced: one the
    vulnerable original already satisfies (it looks for a shape this code does not have) proves nothing
    about the fix, so the fix is left for human review rather than labelled independently verified."""
    snippet = textwrap.dedent(original)
    try:
        ast.parse(snippet)
    except SyntaxError:
        return False
    return checker(snippet) is not None


def _identity(finding: StaticFinding, text: str) -> tuple[str, str]:
    """A finding is the same finding before and after an edit if its kind and the source text of its
    line match -- line numbers alone shift whenever the fix changes how many lines it spans."""
    lines = text.splitlines()
    source = lines[finding.line - 1].strip() if 1 <= finding.line <= len(lines) else ""
    return finding.kind, source


def _scan_text(scanner: Scanner, filename: str, text: str) -> list[StaticFinding]:
    with tempfile.TemporaryDirectory(prefix="codemod-verify-") as scratch:
        (Path(scratch) / filename).write_text(text, encoding="utf-8")
        try:
            return scanner.scan(Path(scratch))
        except ScanFailed as error:  # an unproven fix is a rejected fix, never an applied one
            raise VerificationFailed(f"the rescan did not complete: {error}") from error
