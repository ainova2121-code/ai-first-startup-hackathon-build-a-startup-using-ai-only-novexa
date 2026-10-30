"""Redact sensitive values from audit payloads before they are chained.

Instead of logging raw bank accounts, emails or PII, the ledger stores a keyed HMAC commitment
of each sensitive value. The hash chain still proves integrity, and the owner can later prove a
specific value matches (selective disclosure) by revealing it — but the raw data never sits in
the log, so erasure requests and data-minimisation (GDPR / DPDP) are satisfied. The HMAC secret
is kept by the owner and is never needed to verify the chain, only to prove a value.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

SENSITIVE_KEYS = {"bank_account", "account", "iban", "amount", "ssn", "email", "password",
                  "token", "card", "phone", "secret", "address", "dob"}
SENSITIVE_PATTERNS = [
    re.compile(r"\b[A-Z]{2}\d{8,}\b"),            # account / IBAN-like
    re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+"),       # email
    re.compile(r"\bHTK-[A-Z0-9-]+\b"),            # honeytoken
]


class Redactor:
    def __init__(self, secret: bytes, sensitive_keys: set[str] = SENSITIVE_KEYS,
                 patterns: list[re.Pattern[str]] = SENSITIVE_PATTERNS) -> None:
        self._secret = secret
        self._keys = {k.lower() for k in sensitive_keys}
        self._patterns = patterns

    def commit(self, value: Any) -> str:
        return "hmac:" + hmac.new(self._secret, str(value).encode(), hashlib.sha256).hexdigest()[:24]

    def proves(self, value: Any, token: str) -> bool:
        return hmac.compare_digest(self.commit(value), token)

    def _is_sensitive_value(self, value: Any) -> bool:
        return isinstance(value, str) and any(p.search(value) for p in self._patterns)

    def redact(self, obj: Any, key: str | None = None) -> Any:
        if isinstance(obj, dict):
            return {k: self.redact(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.redact(v, key) for v in obj]
        if (key and key.lower() in self._keys) or self._is_sensitive_value(obj):
            return self.commit(obj)
        return obj


MAX_EXTRA_PATTERNS = 64


def configured(secret: bytes, extra_keys: str = "", patterns_file: str | None = None) -> Redactor:
    """The default redactor plus an operator's own field names (comma-separated) and value patterns (a file, one
    regular expression per line), so a domain's own identifiers are committed too, with no code change. A pattern that
    does not compile stops startup rather than being dropped: a redaction silently skipped is a leak."""
    keys = SENSITIVE_KEYS | {key.strip().lower() for key in extra_keys.split(",") if key.strip()}
    lines = []
    if patterns_file:
        with open(patterns_file, encoding="utf-8") as stream:
            lines = [line.strip() for line in stream if line.strip() and not line.lstrip().startswith("#")]
    if len(lines) > MAX_EXTRA_PATTERNS:
        raise ValueError(f"at most {MAX_EXTRA_PATTERNS} redaction patterns")
    try:
        extra = [re.compile(line) for line in lines]
    except re.error as error:
        raise ValueError(f"invalid redaction pattern in {patterns_file}: {error}") from error
    return Redactor(secret, keys, SENSITIVE_PATTERNS + extra)
