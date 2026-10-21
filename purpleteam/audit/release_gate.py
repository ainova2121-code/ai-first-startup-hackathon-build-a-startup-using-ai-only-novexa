"""The release gate: before a build ships, prove its audit evidence is actually hardware-signed
and actually covers that exact build — never read a bare ``ok=True`` from the general-purpose
verifier as either.

``AuditLedger.verify()``/``verify_log`` return ``ok=True`` for a log with no checkpoint pinned at
all (a correct, narrower claim: "nothing here looks broken", not "this is tamper-evident"), and
``require_hardware=True`` only even applies once a checkpoint exists. A release gate that only
checked ``.ok`` would silently accept a log with no checkpoint, or one covered only by the
software hybrid signature — the two gaps this module closes explicitly.

Hardware *signing* is still not hardware *attestation*: a checkpoint's ``kind`` (``tpm2``, ``hsm``,
``kms``...) is a label the signer claims, not something verified here. Proving a key really lives
in the hardware it claims (TPM quote + manufacturer AIK chain, or equivalent) is a real enrollment
process this module does not implement — see the module docstring of ``audit.hardware_signer``.

``require_no_containment_escalations`` is the pre-deployment framing of live enforcement: point a
candidate release at the gateway in staging or canary with ``GATEWAY_ENFORCE``/
``GATEWAY_LIVE_CONTAINMENT`` on, let real traffic run through it for a bounded window, then ask
this one question of the signed evidence — did anything in that window need proof-gated
containment (``purpleteam.gateway_containment``)? A clean window is evidence the release is safe
to promote; this is a validation pass a build must survive, not a standing bodyguard watching
production forever."""

from __future__ import annotations

import re
from dataclasses import dataclass

from purpleteam.audit.hardware_signer import HARDWARE_KINDS
from purpleteam.audit.ledger import AuditLedger

_REVISION = re.compile(r"[\w.+-]{1,256}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ReleaseGateResult:
    ok: bool
    reason: str = ""
    hardware: str = ""  # the protection that signed the checkpoint, once ok


def bind_release(ledger: AuditLedger, revision: str, digest: str) -> dict:
    """Record which exact build (a source revision, e.g. a git commit, and a content digest) this
    assessment's findings apply to, so a release gate can refuse a checkpoint that does not cover
    it — proven safe for one build must never be read as proof for a different one."""
    if not _REVISION.fullmatch(revision):
        raise ValueError("revision must be a plain name (e.g. a git commit SHA)")
    if not _DIGEST.fullmatch(digest):
        raise ValueError("digest must be a lowercase SHA-256 hex string")
    return ledger.append("release", "build", {"revision": revision, "digest": digest})


def require_hardware_backed_checkpoint(ledger: AuditLedger, trust: dict, **policy) -> ReleaseGateResult:
    """Fails unless the log verifies against a checkpoint that was actually present, actually
    matched the log (``anchored``), and is signed by a hardware-protected key — each checked
    explicitly rather than inferred from ``ok=True`` alone."""
    if not (trust or {}).get("checkpoint"):
        return ReleaseGateResult(False, "no checkpoint in the trust bundle to verify against")
    result = ledger.verify(trust, require_hardware=True, **policy)
    if not result.ok:
        return ReleaseGateResult(False, result.reason or "the log did not verify")
    if not result.anchored or result.hardware not in HARDWARE_KINDS:
        return ReleaseGateResult(False, "the checkpoint did not anchor the log with a hardware signature")
    return ReleaseGateResult(True, hardware=result.hardware)


def require_build_covered(ledger: AuditLedger, trust: dict, *, revision: str, digest: str,
                          **policy) -> ReleaseGateResult:
    """Everything ``require_hardware_backed_checkpoint`` checks, plus: the checkpoint must cover a
    ``release``/``build`` event (see ``bind_release``) recording exactly this ``revision`` and
    ``digest`` — so a hardware-signed checkpoint proven for one build can never stand in for another."""
    result = require_hardware_backed_checkpoint(ledger, trust, **policy)
    if not result.ok:
        return result
    covered = ledger.events()[: trust["checkpoint"]["size"]]
    bound = any(e.get("actor") == "release" and e.get("kind") == "build"
               and e.get("payload", {}).get("revision") == revision
               and e.get("payload", {}).get("digest") == digest for e in covered)
    if not bound:
        return ReleaseGateResult(False, f"no checkpointed release event covers revision {revision!r}")
    return result


def require_no_containment_escalations(ledger: AuditLedger, trust: dict, *, revision: str, digest: str,
                                       min_decisions: int = 1, **policy) -> ReleaseGateResult:
    """Everything ``require_build_covered`` checks, plus: no ``gateway``/``containment`` event
    (``purpleteam.gateway_containment``) was logged after this build was bound — proof, not
    inference, that real traffic run through the gateway during this validation window never
    needed a proof-gated escalation. ``min_decisions`` guards against a vacuous pass: a window with
    no gateway decisions in it proved nothing, the same reason an assessment that attacked nothing
    is never read as safe to ship (``AssessmentReport.safe_to_ship``)."""
    result = require_build_covered(ledger, trust, revision=revision, digest=digest, **policy)
    if not result.ok:
        return result
    covered = ledger.events()[: trust["checkpoint"]["size"]]
    bound_at = next(i for i, e in enumerate(covered) if e.get("actor") == "release" and e.get("kind") == "build"
                    and e.get("payload", {}).get("revision") == revision
                    and e.get("payload", {}).get("digest") == digest)
    window = covered[bound_at + 1:]
    decisions = [e for e in window if e.get("actor") == "gateway" and e.get("kind") == "decision"]
    if len(decisions) < min_decisions:
        return ReleaseGateResult(False, f"only {len(decisions)} gateway decision(s) logged since this build "
                                        f"was bound (need at least {min_decisions}) — an untested window "
                                        "proves nothing")
    escalations = [e for e in window if e.get("actor") == "gateway" and e.get("kind") == "containment"]
    if escalations:
        worst = escalations[0]["payload"]
        return ReleaseGateResult(False, "containment escalated during this build's validation window: "
                                        f"{worst.get('level')} for {worst.get('agent')}/{worst.get('tool')}")
    return result
