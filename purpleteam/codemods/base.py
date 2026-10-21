"""Shared shapes for codemod authoring: draft once per new pattern, verify against the same
scanner that found it, persist only what verification actually proved.

A VerifiedCodemod is the only thing ever eligible to become a permanent catalog entry or to be
shown to a human for approval — a CodemodCandidate (the model's raw, unverified claim) never is.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CodemodCandidate:
    """An LLM-drafted fix for one StaticFinding. Not yet proven; never applied as-is."""

    kind: str
    original: str      # the exact source line(s) the finding pointed at
    replacement: str   # the model's proposed replacement
    explanation: str


@dataclass(frozen=True)
class VerifiedCodemod:
    """A candidate proven, by re-running the original scanner on a scratch copy, to actually
    resolve the finding without introducing a new one or breaking the file's syntax.

    ``verified_by`` names every check that actually passed: always ``"rescan"`` (the scanner that
    found it, re-run), plus ``"invariant"`` when an independent, differently-implemented check of
    the same property (``codemods.invariants``) also passed. A rescan alone is real but narrower
    evidence than it looks — this makes which kind a reader is getting explicit rather than implied."""

    kind: str
    original: str
    replacement: str
    explanation: str
    verified_by: tuple[str, ...] = ("rescan",)


class VerificationFailed(Exception):
    """A candidate did not survive re-verification. Never shown to a human, never persisted."""
