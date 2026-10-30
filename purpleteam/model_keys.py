"""Which API key each of the platform's own models uses (the attacker, the explainer, the codemod author).

Each role reads its own variables first, then ``PURPLETEAM_LLM_API_KEY``, the one shared platform key. The demo
target's ``LEDGERPILOT_LLM_API_KEY`` is read last, only so an existing demo setup keeps working: the platform never
needs a target's own configuration to run.
"""

from __future__ import annotations

import os

SHARED = "PURPLETEAM_LLM_API_KEY"
LEGACY = "LEDGERPILOT_LLM_API_KEY"
ATTACKER_KEYS = ("PURPLETEAM_ATTACKER_KEY", "GROQ_API_KEY")  # the adversarial model's own variables


def platform_key(*role: str) -> str:
    """The first non-empty of the role's own variables, the shared platform key, then the legacy demo one; "" if none."""
    return next((value for name in (*role, SHARED, LEGACY) if (value := os.environ.get(name))), "")


def missing_key(what: str, *role: str) -> str:
    """The error message naming every variable ``platform_key(*role)`` would have read."""
    return f"No {what} key found. Set {' or '.join((*role, SHARED))} in the environment or .env."
