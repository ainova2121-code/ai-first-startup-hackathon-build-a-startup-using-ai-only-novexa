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
    # Structural identity findings (purpleteam.identity) the catalog can actually answer — see
    # assessment_report.patchable_identity_findings. Every other identity finding kind (shared_credential,
    # unauthenticated_agent, a prompt or model change...) has no sensible runtime guard and stays
    # report-only: claiming a patch for those would assert a fix that does not exist.
    "excess_privilege": ["P11"],
    "undeclared_agent": ["P11"],
    # P8 first: a surgical fix (the tool keeps working for reads, only a write is ever blocked,
    # deterministically, regardless of what the model is persuaded to try) beats P4's blunt
    # full-tool hold for a finding that is specifically about an unscoped *write* capability.
    "unscoped_execution": ["P8", "P4"],
    # Structural: a memory-write tool exists, so anything planted there outlives the conversation.
    "memory_write_surface": ["P12"],
    # Observed: an agent repeated the same tool call (LoopOracle).
    "agent_loop": ["P13"],
    # Structural: outside content reaches an agent that holds a tool taking a destination or identity value.
    "untrusted_value_flow": ["P14"],
}

PATCH_SUMMARY: dict[str, str] = {
    "P2": "scan untrusted text for prompt injection / jailbreak",
    "P4": "hold a dangerous tool for human verification",
    "P5": "allow only verified values for a sensitive argument",
    "P8": "allow only safe read-only SQL (sqlglot firewall)",
    "P9": "redact secrets from outputs",
    "P10": "block tool calls whose arguments carry a secret",
    "P11": "allow each agent only the tools its permissions list",
    "P12": "quarantine memory writes that carry an instruction or a secret",
    "P13": "cap each agent's tool-call budget and stop repeated identical calls",
    "P14": "refuse a destination or identity value that only outside content supplied, unconfirmed by any record",
}

CATALOG_IDS = tuple(PATCH_SUMMARY)

# Patches that screen text for the whole target; the rest are scoped to the tool that breached.
GLOBAL_PATCHES = frozenset({"P2", "P9", "P10", "P11", "P12", "P13", "P14"})

# Recommended but never counted as a coverage gap when absent: P5 only builds when the operator
# supplies business-specific facts (which verified values are legitimate for an argument) that
# cannot be inferred, unlike every other patch here, which either always builds or fails only for
# a genuine environment reason (P2 with no ML backend available) worth flagging as a real gap.
OPTIONAL_PATCHES = frozenset({"P5"})


def catalog_digest() -> str:
    """A fingerprint of which patches answer which finding kinds -- a saved policy pins it, so an
    upgrade that changes that mapping cannot silently change what an old approval enforces."""
    import hashlib
    import json

    blob = json.dumps({"patches": FINDING_PATCHES, "summary": PATCH_SUMMARY}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def missing_patches(kind: str, applied: set[str]) -> list[str]:
    """Catalog-recommended patch ids for ``kind`` that did not actually get applied — a patch that
    silently failed to build (P2 with no ML backend available, say) is a real gap, not "patched
    enough" just because something else for the same kind happened to succeed. A kind with no
    catalog entry at all is reported the same way, via its own name as the one missing answer."""
    recommended = FINDING_PATCHES.get(kind)
    if recommended is None:
        return ["no catalog entry"]
    required = set(recommended) - OPTIONAL_PATCHES
    return sorted(required - applied)
