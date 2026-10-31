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

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from purpleteam.audit.hashing import canonical
from purpleteam.audit.keys import AgentKeyring, verify_pq, verify_signature
from purpleteam.defender.selector import Defender, Finding
from purpleteam.discovery import EXECUTE, WRITE, DiscoveredTool, TargetProfile
from purpleteam.identity import PermissionManifest
from purpleteam.oversight import ReviewQueue
from purpleteam.patches.base import CompositeGuard
from purpleteam.patches.catalog import catalog_digest

POLICY_CONTEXT = b"purpleteam.defender.policy.v1"
POLICY_ACTOR = "defender"
_FACT_FIELDS = ("secrets", "tables", "verified_values", "verified_arg", "mode", "redact_patterns",
                "caller_scope")


@dataclass(frozen=True)
class LoadedPolicy:
    guard: CompositeGuard
    manifest: PermissionManifest | None  # the declared manifest the policy was built from, if any


def _fernet(secrets_key: str) -> Fernet:
    """An operator-chosen secret (``GATEWAY_POLICY_SECRETS_KEY``), reduced to the key Fernet needs."""
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secrets_key.encode("utf-8")).digest()))


def _applied(profile: TargetProfile, facts: dict, findings: list[Finding], escalation: int = 0,
             exclude: frozenset[str] = frozenset()) -> list[list[str]]:
    """The exact patch implementations a policy enforces, as sorted ``[id, code hash]`` pairs."""
    defense = Defender(profile, facts, escalation=escalation, exclude=exclude).select_all(findings)
    return sorted([e["id"], e["hash"]] for e in defense.applied)


def save_policy(path: Path, findings: list[Finding], profile: TargetProfile, facts: dict | None,
                keyring: AgentKeyring, *, secrets_key: str | None = None, escalation: int = 0,
                exclude: frozenset[str] = frozenset()) -> None:
    """``policy_data``, signed with ``keyring``'s ``"defender"`` key (the same hybrid Ed25519 + ML-DSA
    scheme the audit ledger and release provenance use) and written atomically — call this only once a
    human has reviewed and approved the policy."""
    data = policy_data(findings, profile, facts, secrets_key=secrets_key, escalation=escalation, exclude=exclude)
    kid = keyring.kid(POLICY_ACTOR)
    signature = keyring.sign(POLICY_ACTOR, canonical(data), POLICY_CONTEXT, kid=kid)
    envelope = {"policy": data, "kid": kid, "sig": signature.ed25519}
    if signature.mldsa65:
        envelope["pqsig"] = signature.mldsa65
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f"{path.suffix}.tmp")
    tmp.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    tmp.replace(path)  # atomic on POSIX and Windows alike


def policy_data(findings: list[Finding], profile: TargetProfile, facts: dict | None, *,
                secrets_key: str | None = None, escalation: int = 0, exclude: frozenset[str] = frozenset()) -> dict:
    """Everything ``Defender(profile, facts, escalation=...).select_all(findings)`` needs to reproduce its
    guard: the findings themselves, the profile facts it actually reads (dangerous tools, which of
    them are execute-risk), the business facts it reads (never the whole, possibly larger, facts dict —
    only the keys the catalog's patches use) and the escalation level the verified defense reached.

    Known secret values are stored only Fernet-encrypted under ``secrets_key``, and saving them without
    one is refused. Each patch's code hash and the catalog digest are pinned, so a later upgrade that
    would rebuild it into different behaviour fails to load instead of silently enforcing something
    unapproved."""
    facts = facts or {}
    execute_tools = sorted(t.name for t in profile.tools if t.risk == EXECUTE)
    saved_facts = {k: facts[k] for k in _FACT_FIELDS if k in facts}
    if "secrets" in saved_facts:
        if not secrets_key:
            raise ValueError("refusing to write known secret values into a policy file in plaintext -- "
                             "pass secrets_key (GATEWAY_POLICY_SECRETS_KEY) to encrypt them")
        plain = json.dumps(sorted(saved_facts["secrets"])).encode("utf-8")
        saved_facts["secrets"] = {"fernet": _fernet(secrets_key).encrypt(plain).decode("ascii")}
    manifest = facts.get("manifest")
    if isinstance(manifest, PermissionManifest):
        saved_facts["manifest"] = manifest.to_dict()
    data = {
        "findings": [{"kind": f.kind, "tool": f.tool, "agent": f.agent, "detail": f.detail,
                      "source": f.source} for f in findings],
        "dangerous_tools": sorted(profile.dangerous_tools),
        "execute_tools": execute_tools,
        "facts": saved_facts,
        "patches": _applied(profile, facts, findings, escalation, exclude),
        "catalog": catalog_digest(),
    }
    if escalation:  # absent means level 0, so a policy saved before escalation existed loads unchanged
        data["escalation"] = escalation
    if exclude:  # patches a verified replay proved break legitimate work; absent means none
        data["exclude"] = sorted(exclude)
    # Which agent holds which tool: an escalated defense reads it (widened review scope, the inferred manifest a
    # denial narrows), so without it a rebuild would enforce less than was verified.
    data["holdings"] = sorted([t.agent, t.name, t.risk] for t in profile.tools)
    # Which arguments carry a destination or identity value: P14 checks exactly these, and the defender relies on it
    # in place of a hold, so a rebuild without them would enforce less than was verified.
    data["value_args"] = {tool: sorted(args) for tool, args in sorted(profile.value_args.items())}
    return data


def load_guard(path: Path, public_keys: dict, review_queue: ReviewQueue | None = None, *,
               secrets_key: str | None = None) -> LoadedPolicy:
    """Rebuild the exact ``CompositeGuard`` a saved, signed policy produced, plus the declared
    manifest it was built from (for live containment — ``purpleteam.gateway_containment`` — to
    narrow within, never beyond). ``public_keys`` is the approver's pinned ``{kid: public key}``
    (an ``AgentKeyring.public_keys()["defender"]`` shape) — never the gateway's own keyring, which
    has no business approving its own enforcement. Raises ``ValueError`` on anything unsigned,
    signed by an unknown key, or malformed, rather than silently building a weaker or empty guard:
    a policy that cannot be verified must never be read as "no patches needed". ``review_queue``
    backs every P4 hold this guard produces — pass a durable one (a real path) so a gateway
    restart does not forget a pending or already-decided human review."""
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
    return rebuild(raw["policy"], review_queue, secrets_key=secrets_key, where=f"the policy file at {path}")


def rebuild(data: dict, review_queue: ReviewQueue | None = None, *, secrets_key: str | None = None,
            where: str = "the policy") -> LoadedPolicy:
    """The guard ``policy_data`` describes, refusing anything that would rebuild differently from what was
    approved. Signature checks are the caller's (``load_guard``); this is the deterministic rebuild."""
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError(f"{where} does not hold the expected object")
    escalation, exclude = data.get("escalation", 0), data.get("exclude", [])
    if not isinstance(escalation, int) or not (isinstance(exclude, list) and all(isinstance(p, str) for p in exclude)):
        raise ValueError(f"{where} has an invalid escalation level or exclusion list")
    exclude = frozenset(exclude)
    findings = [Finding(f["kind"], f["tool"], f["agent"], f["detail"], source=f["source"])
               for f in data["findings"]]
    execute_tools = set(data.get("execute_tools", []))
    if "holdings" in data:
        value_args = data.get("value_args", {})
        tools = [DiscoveredTool(name, "", {arg: {} for arg in value_args.get(name, ())}, "policy", risk, "",
                                agent_name=agent) for agent, name, risk in data["holdings"]]
    else:
        tools = [DiscoveredTool(name, "", {}, "policy", EXECUTE, "") for name in execute_tools]
        tools += [DiscoveredTool(name, "", {}, "policy", WRITE, "")
                  for name in data.get("dangerous_tools", []) if name not in execute_tools]
    profile = TargetProfile("policy", tools)
    facts = dict(data.get("facts", {}))
    if "secrets" in facts:
        if not secrets_key:
            raise ValueError(f"{where} holds encrypted secrets; set GATEWAY_POLICY_SECRETS_KEY")
        try:
            facts["secrets"] = json.loads(_fernet(secrets_key).decrypt(facts["secrets"]["fernet"].encode("ascii")))
        except (InvalidToken, KeyError, TypeError) as error:
            raise ValueError(f"{where} has secrets this key cannot decrypt") from error
    manifest = PermissionManifest.from_dict(facts["manifest"]) if "manifest" in facts else None
    if manifest is not None:
        facts["manifest"] = manifest
    if data.get("catalog") != catalog_digest() or data.get("patches") != _applied(profile, facts, findings, escalation,
                                                                                  exclude):
        raise ValueError(f"{where} was approved against a different patch catalog or patch code than this "
                         "installation would build -- re-run and re-approve the assessment")
    guard = Defender(profile, facts, review_queue=review_queue, escalation=escalation,
                     exclude=exclude).select_all(findings).guard
    return LoadedPolicy(guard, manifest)
