"""The fixed patch catalog the defender chooses from.

Each finding kind maps to the patch IDs that answer it. The LLM selector (optional) is
constrained to these IDs; the deterministic selector reads this map directly. The patches are
built with target-specific parameters by the Defender, never generated.
"""

# finding kind -> patch IDs, most important first
FINDING_PATCHES: dict[str, list[str]] = {
    "injection_action": ["P2", "P4", "P5"],
    "jailbreak": ["P2", "P4"],
    "sql_injection": ["P8"],
    "exfiltration": ["P2", "P8", "P9"],
    "prompt_leak": ["P2", "P9"],
    "egress_leak": ["P10", "P2"],
    "privilege_escalation": ["P11", "P2"],
}

PATCH_SUMMARY: dict[str, str] = {
    "P2": "scan untrusted text for prompt injection / jailbreak",
    "P4": "hold a dangerous tool for human verification",
    "P5": "allow only verified values for a sensitive argument",
    "P8": "allow only safe read-only SQL (sqlglot firewall)",
    "P9": "redact secrets from outputs",
    "P10": "block tool calls whose arguments carry a secret",
    "P11": "allow each agent only the tools its permissions list",
}

CATALOG_IDS = tuple(PATCH_SUMMARY)

# Patches that screen text for the whole target; the rest are scoped to the tool that breached.
GLOBAL_PATCHES = frozenset({"P2", "P9", "P10", "P11"})
