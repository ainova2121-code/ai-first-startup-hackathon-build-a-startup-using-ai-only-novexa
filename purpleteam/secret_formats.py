"""Credential formats and secret-name patterns used by the secret finder.

Every quantifier is bounded, and possessive where it can be (Python 3.11+), so no input can drive
matching quadratic. Prefixes are deliberately not word-anchored: "x" + a token is still a token.
The bounds only limit how much a *failed* attempt can cost; once a token matches, ``TAILS``
extends the span over whatever token characters follow, so a token longer than its bound is
still redacted whole.
"""

import re

FORMATS: dict[str, re.Pattern[str]] = {name: re.compile(pattern) for name, pattern in {
    "aws_access_key": r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}",
    "github_token": r"(?:gh[pousr]_[A-Za-z0-9]{36,255}+|github_pat_[A-Za-z0-9_]{22,255}+)",
    "sk_api_key": r"(?:sk-(?:ant-|proj-|svcacct-)[A-Za-z0-9_-]{20,512}+|sk-[A-Za-z0-9]{32,512}+)",
    "slack_token": r"xox[abprs]-[A-Za-z0-9-]{10,256}+",
    "stripe_key": r"[rs]k_(?:live|test)_[A-Za-z0-9]{16,128}+",
    "google_api_key": r"AIza[0-9A-Za-z_-]{35}",
    "groq_key": r"gsk_[A-Za-z0-9]{20,128}+",
    "huggingface_token": r"hf_[A-Za-z0-9]{30,128}+",
    "jwt": r"eyJ[A-Za-z0-9_-]{8,2048}+\.eyJ[A-Za-z0-9_-]{8,2048}+\.[A-Za-z0-9_-]{8,2048}+",
    # the whole key, header to END line; a key whose END line is missing is redacted for 4096 characters
    "private_key": (r"-----BEGIN (?:[A-Z]{2,12} ){0,3}PRIVATE KEY-----"
                    r"(?:[\s\S]{0,16384}?-----END (?:[A-Z]{2,12} ){0,3}PRIVATE KEY-----|[\s\S]{0,4096}+)"),
    "url_credentials": r"(?i)\b[a-z][a-z0-9+.-]{0,31}://[^\s/:@]{1,256}+:[^\s/@]{1,256}+@[^\s/]{1,253}+",
    "bearer_token": r"(?i)\bbearer\s{1,8}+[A-Za-z0-9._~+/-]{20,2048}+=*",
}.items()}

# NAME = value, where NAME contains a secret-like word anywhere (AWS_SECRET_ACCESS_KEY, db_password).
ASSIGNMENT = re.compile(
    r"""(?i)(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|auth|credential)s?[A-Za-z0-9_-]{0,40}["']?\s{0,16}+"""
    r"""[:=]\s{0,16}+["']?([A-Za-z0-9+/_\-=.]{16,512}+)""")
ASSIGNMENT_TAIL = re.compile(r"[A-Za-z0-9+/_\-=.]*+")

# Characters that may continue a token after its bounded match.
TAILS: dict[str, re.Pattern[str]] = {kind: re.compile(chars + "*+") for kind, chars in {
    "github_token": r"[A-Za-z0-9_]", "sk_api_key": r"[A-Za-z0-9_-]", "slack_token": r"[A-Za-z0-9-]",
    "stripe_key": r"[A-Za-z0-9]", "groq_key": r"[A-Za-z0-9]", "huggingface_token": r"[A-Za-z0-9]",
    "jwt": r"[A-Za-z0-9_-]", "bearer_token": r"[A-Za-z0-9._~+/=-]",
}.items()}

# Whitespace is part of these formats, so they are not searched in whitespace-stripped text.
STRUCTURAL_FORMATS = frozenset({"url_credentials", "bearer_token", "private_key"})
# Without whitespace, all-caps words such as "ASIAN PACIFIC TRADING" would look like key IDs; real ones carry digits.
NEEDS_DIGIT_WHEN_COMPACT = frozenset({"aws_access_key"})
