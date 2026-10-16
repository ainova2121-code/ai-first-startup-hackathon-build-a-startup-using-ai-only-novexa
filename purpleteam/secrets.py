"""Secret detection shared by the leak oracle and the defender's redaction and egress patches.

Three kinds of evidence, strongest first: *known* secrets (planted decoys or secrets the owner
supplies), well-known credential *formats* (cloud keys, tokens, private keys, URL credentials),
and high-entropy values assigned to secret-like names. Text is normalised first (invisible
characters and combining marks removed) and also searched after decoding base64, hex and
percent-encoded runs, up to two layers deep, both as written and with whitespace removed, so a
leak does not escape by being encoded, wrapped, spaced out or padded with invisible characters.
Known secrets are matched with every non-alphanumeric character ignored, read both as written and
with JSON escapes decoded (tool results are serialised before they are screened).

Redaction favours safety over tidiness: where a whitespace-stripped match runs into neighbouring
words it removes those too, because trying to trim it would let a decoy placed next to a real
secret hide it. Limits, stated plainly: ciphers, compression, reversal and custom encodings are
not undone; credential-*format* secrets split by punctuation (``ghp_AAAA-BBBB``) or, for the
whitespace-bearing formats (Bearer, PEM headers, URL credentials), by whitespace are not
reassembled, though known secrets survive both; and a secret split across separate requests is
not seen; and a real AWS key ID containing no digit (about 1 in 100) is missed when whitespace or
invisible padding also hides it. Input beyond ``MAX_SCAN_CHARS`` (or too much decoding work) raises ``ScanTooLarge``:
callers must fail closed. Match objects carry positions and kinds only, never the secret itself.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Iterable, Iterator

from purpleteam.secret_formats import (
    ASSIGNMENT, ASSIGNMENT_TAIL, FORMATS, NEEDS_DIGIT_WHEN_COMPACT, STRUCTURAL_FORMATS, TAILS,
)
from purpleteam.secret_text import (
    Budget, ScanTooLarge, clean_text, compact, decodings, locate, overlapping, squash, strings,
)

__all__ = ["MAX_SCAN_CHARS", "MIN_KNOWN_LENGTH", "REDACTED", "Match", "ScanTooLarge", "SecretFinder", "clean_text",
           "looks_random"]

MAX_SCAN_CHARS = 1_000_000
MAX_DECODE_DEPTH = 2
MIN_KNOWN_LENGTH = 8            # shorter secrets would match ordinary text
REDACTED = "[redacted]"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)


@dataclass(frozen=True)
class Match:
    kind: str
    start: int
    end: int
    via: str = "plain"   # plain | base64 | hex | url


def _entropy(value: str) -> float:
    return -sum(n / len(value) * math.log2(n / len(value)) for n in (value.count(c) for c in set(value)))


def looks_random(value: str) -> bool:
    if _UUID.fullmatch(value) or len(set(value)) < 6:
        return False
    return _entropy(value) >= (3.0 if re.fullmatch(r"[0-9a-fA-F]+", value) else 3.5)


class SecretFinder:
    def __init__(self, known: Iterable[str] = (), extra_patterns: Iterable[re.Pattern[str]] = (), *,
                 formats: bool = True, entropy: bool = True) -> None:
        self._known: list[tuple[bool, str]] = []  # (JSON escapes decoded?, squashed secret)
        for secret in known:
            cleaned = clean_text(secret)
            if len(squash(cleaned, False)[0]) < MIN_KNOWN_LENGTH:
                raise ValueError(f"a known secret needs at least {MIN_KNOWN_LENGTH} letters or digits to be detectable")
            for escapes in (False, True):
                squashed = squash(cleaned, escapes)[0]
                if len(squashed) >= MIN_KNOWN_LENGTH and (escapes, squashed) not in self._known:
                    self._known.append((escapes, squashed))
        self._patterns = dict(FORMATS) if formats else {}
        self._patterns.update({f"custom{i}": p for i, p in enumerate(extra_patterns)})
        self._entropy = entropy

    def find(self, text: str) -> list[Match]:
        if len(text) > MAX_SCAN_CHARS:
            raise ScanTooLarge("text is too large to scan")
        found = self._matches(clean_text(text), None, "plain", 0, Budget())
        return sorted(set(found), key=lambda m: (m.start, m.end))

    def find_in(self, value: Any) -> list[Match]:
        """Matches anywhere in strings, bytes, numbers or nested containers (keys included)."""
        parts = list(strings(value))
        matches = [m for s in parts for m in self.find(s)]
        if len(parts) > 1:  # a secret split across several arguments is still a secret
            matches += self.find(" ".join(parts))
            values = list(strings(value, keys=False))  # argument names between the pieces must not break the join
            if 1 < len(values) < len(parts):
                matches += self.find(" ".join(values))
        return matches

    def contains(self, text: str) -> bool:
        return bool(self.find(text))

    def redact(self, text: str) -> str:
        """The text with every match (decoded carriers included) replaced; unchanged if nothing matched."""
        matches = self.find(text)
        if not matches:
            return text
        cleaned, last, parts = clean_text(text), 0, []
        for start, end in _merge([(m.start, m.end) for m in matches]):
            parts += [cleaned[last:start], REDACTED]
            last = end
        return "".join(parts) + cleaned[last:]

    def _matches(self, text: str, carrier: tuple[int, int] | None, via: str, depth: int,
                 budget: Budget) -> Iterator[Match]:
        """Matches in ``text``; those found after decoding are located by their outermost carrier."""
        yield from self._formats(text, None, carrier, via)
        yield from self._context_and_known(text, carrier, via)
        stripped, index = compact(text)
        views: list[tuple[str, list[int] | None]] = [(text, None)]
        if len(stripped) < len(text):  # whitespace or invisible marks may have been hiding something
            views.append((stripped, index))
            yield from self._formats(stripped, index, carrier, via)
        if depth < MAX_DECODE_DEPTH:
            for view, mapping in views:
                for span, decoded, how in decodings(view, budget):
                    yield from self._matches(clean_text(decoded), carrier or locate(span, mapping),
                                             how, depth + 1, budget)

    def _formats(self, text: str, mapping: list[int] | None, carrier: tuple[int, int] | None,
                 via: str) -> Iterator[Match]:
        """Credential formats; ``mapping`` is set when ``text`` is a whitespace-stripped copy."""
        for kind, pattern in self._patterns.items():
            if mapping is not None and kind in STRUCTURAL_FORMATS:  # whitespace is part of these formats
                continue
            tail = TAILS.get(kind)
            for m in overlapping(pattern, text):
                if mapping is not None and kind in NEEDS_DIGIT_WHEN_COMPACT and not any(c.isdigit() for c in m.group()):
                    continue
                end = tail.match(text, m.end()).end() if tail else m.end()
                yield Match(kind, *(carrier or locate((m.start(), end), mapping)), via)

    def _context_and_known(self, text: str, carrier: tuple[int, int] | None, via: str) -> Iterator[Match]:
        if self._entropy:
            for m in overlapping(ASSIGNMENT, text):
                if looks_random(m.group(1)):
                    yield Match("high_entropy_secret",
                                *(carrier or (m.start(1), ASSIGNMENT_TAIL.match(text, m.end(1)).end())), via)
        squashes = {escapes: squash(text, escapes) for escapes in {e for e, _ in self._known}}
        for escapes, secret in self._known:
            squashed, starts, ends = squashes[escapes]
            at = squashed.find(secret)
            while at != -1:
                yield Match("known_secret", *(carrier or (starts[at], ends[at + len(secret) - 1])), via)
                at = squashed.find(secret, at + len(secret))


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged
