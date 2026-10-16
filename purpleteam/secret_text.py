"""Text transforms behind the secret finder: normalising, squashing, compacting and decoding.

``clean_text`` removes what attackers use to pad a secret invisibly: format characters and
combining marks (after decomposing, so ``c`` + an accent cannot recompose into a letter that no
longer matches). ``squash`` keeps only letters and digits, optionally reading JSON escapes the way
a serialised tool result would write them. ``compact`` also drops whitespace. The decoders undo
base64, hex and percent-encoding. Every transform keeps a map back to positions in the text it was
given, so a match found in a transformed copy can be located (and redacted) in the original.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from typing import Any, Iterator

MAX_DECODED_CHARS = 4_000_000   # total decoded text across one scan
MAX_ARG_DEPTH = 20
MIN_BASE64_RUN = 11             # the base64 of an 8-byte secret is 11 characters

_BASE64_RUN = re.compile(rf"[A-Za-z0-9+/]{{{MIN_BASE64_RUN},}}={{0,2}}")
_BASE64URL_RUN = re.compile(rf"[A-Za-z0-9_-]{{{MIN_BASE64_RUN},}}={{0,2}}")
_HEX_RUN = re.compile(r"[0-9a-fA-F]{16,}")
_TOKEN = re.compile(r"\S+")
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_HEX4 = re.compile(r"[0-9a-fA-F]{4}")
_FILLERS = frozenset("\u3164\u115f\u1160\uffa0")  # blank-looking letters (category Lo, so not "invisible")
_DROPPED = ("Cf", "Mn", "Me")


class ScanTooLarge(ValueError):
    """The text is too large to scan safely; callers must block, not skip."""


def clean_text(text: str) -> str:
    """Decompose (NFKD), drop invisible format characters, blank-looking fillers and combining marks, recompose (NFC)."""
    kept = "".join(ch for ch in unicodedata.normalize("NFKD", text)
                   if unicodedata.category(ch) not in _DROPPED and ch not in _FILLERS)
    return unicodedata.normalize("NFC", kept)


def squash(text: str, escapes: bool) -> tuple[str, list[int], list[int]]:
    """Lower-cased alphanumerics only, with the source span of each emitted character.

    With ``escapes`` the JSON escapes a serialised tool result carries (``\\n``, ``\\t``,
    ``\\uXXXX``) are skipped or decoded; without it a backslash is just a character, so a reply
    that really contains ``\\n`` is read as written. Callers check both. Every emitted character
    has its own start and end, so one that lowercases to several (U+0130) cannot shift later spans.
    """
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    position, size = 0, len(text)
    while position < size:
        piece, width = text[position], 1
        if escapes and piece == "\\" and position + 1 < size:
            following = text[position + 1]
            if following in "nrtbf\"\\/":
                position += 2
                continue
            if following == "u" and _HEX4.fullmatch(text[position + 2:position + 6]):
                code, width = int(text[position + 2:position + 6], 16), 6
                if (0xD800 <= code <= 0xDBFF and text[position + 6:position + 8] == "\\u"
                        and _HEX4.fullmatch(text[position + 8:position + 12])):
                    low = int(text[position + 8:position + 12], 16)  # json.dumps writes non-BMP letters as a pair
                    if 0xDC00 <= low <= 0xDFFF:
                        code, width = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00), 12
                piece = clean_text(chr(code))
        for ch in piece:
            if ch.isalnum():
                for lowered in ch.lower():
                    chars.append(lowered)
                    starts.append(position)
                    ends.append(position + width)
        position += width
    return "".join(chars), starts, ends


def compact(text: str) -> tuple[str, list[int]]:
    """``text`` without whitespace and invisible characters, with each kept character's source index."""
    chars, index = [], []
    skip_next = False
    for position, ch in enumerate(text):
        if skip_next:  # the "n" of a serialised newline
            skip_next = False
            continue
        if ch == "\\" and text[position + 1:position + 2] in ("n", "r", "t"):
            skip_next = True  # a tool result serialises a wrapped encoding's line breaks as \n
            continue
        if ch.isspace() or ch in _FILLERS or unicodedata.category(ch) in _DROPPED:
            continue
        chars.append(ch)
        index.append(position)
    return "".join(chars), index


def overlapping(pattern: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """Every match, including ones that start inside an earlier match (finditer would skip those).

    A decoy that consumes the first characters of a real fixed-length key must not hide the key.
    """
    position = 0
    while (match := pattern.search(text, position)) is not None:
        yield match
        position = match.start() + 1


def locate(span: tuple[int, int], mapping: list[int] | None) -> tuple[int, int]:
    return span if mapping is None else (mapping[span[0]], mapping[span[1] - 1] + 1)


class Budget:
    def __init__(self) -> None:
        self._left = MAX_DECODED_CHARS

    def spend(self, chars: int) -> None:
        self._left -= chars
        if self._left < 0:
            raise ScanTooLarge("too much encoded content to decode safely")


def _worth_decoding(run: str) -> bool:
    """Skip plain lower- or upper-case words: base64 of real data is a mix of cases and digits."""
    return not (run.isalpha() and (run.islower() or run.isupper()))


def _decode_base64(run: str, urlsafe: bool) -> Iterator[str]:
    body = run.rstrip("=")
    for offset in range(4):  # a blob glued to preceding characters decodes at one of four alignments
        piece = body[offset:]
        if len(piece) % 4 == 1:  # one stray trailing character (text glued on) makes the rest undecodable
            piece = piece[:-1]
        if len(piece) < MIN_BASE64_RUN:
            return
        try:
            data = (base64.urlsafe_b64decode if urlsafe else base64.b64decode)(piece + "=" * (-len(piece) % 4))
        except (ValueError, binascii.Error):
            continue
        yield data.decode("utf-8", "ignore")


def decodings(text: str, budget: Budget) -> Iterator[tuple[tuple[int, int], str, str]]:
    """(span in ``text``, decoded text, encoding name) for each base64, hex and percent-encoded run."""
    for pattern, urlsafe in ((_BASE64_RUN, False), (_BASE64URL_RUN, True)):
        for match in pattern.finditer(text):
            if not _worth_decoding(match.group()):
                continue
            for decoded in _decode_base64(match.group(), urlsafe):
                budget.spend(len(decoded))
                yield match.span(), decoded, "base64"
    for match in _HEX_RUN.finditer(text):
        for offset in (0, 1):  # a stray hex digit in front would otherwise shift every byte
            run = match.group()[offset:]
            run = run[: len(run) - len(run) % 2]
            if len(run) >= 16:
                budget.spend(len(run) // 2)
                yield match.span(), bytes.fromhex(run).decode("utf-8", "ignore"), "hex"
    for match in _TOKEN.finditer(text):  # a plain scan: a "\S*%..." regex would backtrack quadratically
        if "%" in match.group() and _PERCENT_ESCAPE.search(match.group()):
            budget.spend(len(match.group()))
            yield match.span(), urllib.parse.unquote(match.group()), "url"


def strings(value: Any, depth: int = 0, keys: bool = True) -> Iterator[str]:
    """Every string in a value: strings, bytes, numbers and nested containers (dict keys too, unless ``keys`` is off)."""
    if depth > MAX_ARG_DEPTH:
        raise ScanTooLarge("arguments are nested too deeply to scan")
    if isinstance(value, str):
        yield value
    elif isinstance(value, (bytes, bytearray)):
        yield bytes(value).decode("utf-8", "replace")
    elif isinstance(value, dict):
        for key, item in value.items():
            if keys:
                yield from strings(key, depth + 1)
            yield from strings(item, depth + 1, keys)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from strings(item, depth + 1, keys)
    else:
        try:
            yield str(value)
        except ValueError as error:  # e.g. an integer with thousands of digits
            raise ScanTooLarge("a value is too large to render and scan") from error
