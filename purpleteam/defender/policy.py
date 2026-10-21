"""Persist a reviewed Defense's inputs, not the live guard itself, so a gateway can rebuild and
enforce the exact same decision a completed assessment produced.

``Defender.select_all()`` is a deterministic function of (profile, facts, findings): saving those
three and replaying the same call later reproduces the identical ``CompositeGuard``, with no need
to introspect the live ``Patch`` objects themselves — several of which (``SecretFinder`` in
particular) deliberately do not keep their original constructor inputs around once built, so they
could not be read back out of a live guard even if that were otherwise the right approach.

Nothing here decides to enforce anything. A human reviews ``report.findings``/``report.defense``
and calls ``save_policy`` only once they approve it — signing with their own keyring, never the
gateway's, so a policy edited after approval is detected rather than silently loaded: ordinary JSON
on disk has no integrity of its own, and this file exists only to drive live enforcement, so there
is no legitimate reason to ever load one unsigned. Loading is likewise a deliberate, separate step
(``gateway_main``'s ``GATEWAY_ENFORCE``/``GATEWAY_POLICY_FILE``/``GATEWAY_POLICY_TRUST_FILE``),
never automatic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from purpleteam.audit.hashing import canonical
from purpleteam.audit.keys import AgentKeyring, verify_pq, verify_signature
from purpleteam.defender.selector import Defender, Finding
from purpleteam.discovery import EXECUTE, WRITE, DiscoveredTool, TargetProfile
from purpleteam.identity import PermissionManifest
from purpleteam.patches.base import CompositeGuard

POLICY_CONTEXT = b"purpleteam.defender.policy.v1"
POLICY_ACTOR = "defender"
_FACT_FIELDS = ("secrets", "tables", "verified_values", "verified_arg", "mode")


@dataclass(frozen=True)
class LoadedPolicy:
    guard: CompositeGuard
    manifest: PermissionManifest | None  # the declared manifest the policy was built from, if any


def save_policy(path: Path, findings: list[Finding], profile: TargetProfile, facts: dict | None,
                keyring: AgentKeyring) -> None:
    """Everything ``Defender(profile, facts).select_all(findings)`` would need to reproduce its
    guard: the findings themselves, the profile facts it actually reads (dangerous tools, which of
    them are execute-risk), and the business facts it reads (never the whole, possibly larger,
    facts dict — only the keys the catalog's patches use). Signed with ``keyring``'s ``"defender"``
    key (the same hybrid Ed25519 + ML-DSA scheme the audit ledger and release provenance use) and
    written atomically — call this only once a human has reviewed and approved the policy."""
    facts = facts or {}
    execute_tools = sorted(t.name for t in profile.tools if t.risk == EXECUTE)
    saved_facts = {k: facts[k] for k in _FACT_FIELDS if k in facts}
    manifest = facts.get("manifest")
    if isinstance(manifest, PermissionManifest):
        saved_facts["manifest"] = manifest.to_dict()
    data = {
        "findings": [{"kind": f.kind, "tool": f.tool, "agent": f.agent, "detail": f.detail,
                      "source": f.source} for f in findings],
        "dangerous_tools": sorted(profile.dangerous_tools),
        "execute_tools": execute_tools,
        "facts": saved_facts,
    }
    kid = keyring.kid(POLICY_ACTOR)
    signature = keyring.sign(POLICY_ACTOR, canonical(data), POLICY_CONTEXT, kid=kid)
    envelope = {"policy": data, "kid": kid, "sig": signature.ed25519}
    if signature.mldsa65:
        envelope["pqsig"] = signature.mldsa65
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f"{path.suffix}.tmp")
    tmp.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    tmp.replace(path)  # atomic on POSIX and Windows alike


def load_guard(path: Path, public_keys: dict) -> LoadedPolicy:
    """Rebuild the exact ``CompositeGuard`` a saved, signed policy produced, plus the declared
    manifest it was built from (for live containment — ``purpleteam.gateway_containment`` — to
    narrow within, never beyond). ``public_keys`` is the approver's pinned ``{kid: public key}``
    (an ``AgentKeyring.public_keys()["defender"]`` shape) — never the gateway's own keyring, which
    has no business approving its own enforcement. Raises ``ValueError`` on anything unsigned,
    signed by an unknown key, or malformed, rather than silently building a weaker or empty guard:
    a policy that cannot be verified must never be read as "no patches needed"."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not {"policy", "kid", "sig"} <= set(raw):
        raise ValueError(f"the policy file at {path} is not signed, or not in the expected shape")
    entry = public_keys.get(raw["kid"])
    if entry is None:
        raise ValueError(f"the policy file at {path} is signed by a key that is not trusted")
    message = canonical(raw["policy"])
    public_ed = entry if isinstance(entry, str) else entry.get("ed25519", "")
    if not verify_signature(public_ed, message, raw.get("sig", "")):
        raise ValueError(f"the policy file at {path} has an invalid signature")
    if isinstance(entry, dict) and "mldsa65" in entry:
        if "pqsig" not in raw or not verify_pq(entry["mldsa65"], message, raw["pqsig"], POLICY_CONTEXT):
            raise ValueError(f"the policy file at {path} is missing, or fails, its post-quantum signature")
    data = raw["policy"]
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError(f"the policy file at {path} does not hold the expected object")
    findings = [Finding(f["kind"], f["tool"], f["agent"], f["detail"], source=f["source"])
               for f in data["findings"]]
    execute_tools = set(data.get("execute_tools", []))
    tools = [DiscoveredTool(name, "", {}, "policy", EXECUTE, "") for name in execute_tools]
    tools += [DiscoveredTool(name, "", {}, "policy", WRITE, "")
             for name in data.get("dangerous_tools", []) if name not in execute_tools]
    profile = TargetProfile("policy", tools)
    facts = dict(data.get("facts", {}))
    manifest = PermissionManifest.from_dict(facts["manifest"]) if "manifest" in facts else None
    if manifest is not None:
        facts["manifest"] = manifest
    guard = Defender(profile, facts).select_all(findings).guard
    return LoadedPolicy(guard, manifest)
