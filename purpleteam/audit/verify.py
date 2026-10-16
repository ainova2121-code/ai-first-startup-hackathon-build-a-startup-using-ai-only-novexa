"""Independent verification of an audit log, its checkpoints and single-event proofs.

A log can only prove it was not altered against something the attacker could not rewrite, so
verification takes a *trust bundle* the verifier pinned out of band: the public keys
(``{"keys": {actor: {kid: public}}}``, where ``public`` is an Ed25519 hex string or a hybrid
``{"ed25519": hex, "mldsa65": hex}``), optionally revoked keys (``{"revoked": {kid:
first_untrusted_seq}}``) and, to catch tail truncation or a wholesale rewrite, a signed
checkpoint (``{"checkpoint": {size, root, ts, kid, log, sig[, pqsig]}}``) published earlier. Keys
or checkpoints read from beside the log prove nothing and must not be used.

A hybrid key needs *both* signatures (Ed25519 ``sig`` and ML-DSA-65 ``pqsig``) to verify, so a
signature missing its post-quantum half is a failure, never a downgrade. A classical-only key is
accepted unless the verifier passes ``require_pq=True``.

A checkpoint may carry a third signature from a hardware key (``hwkid``, ``hwsig``: ECDSA P-256 made by a TPM
or similar), whose public key is pinned in ``{"hardware": {hwkid: {"public": hex, "kind": ...}}}``. ``hwkid`` is
part of the message the software keys sign, so stripping the hardware signature breaks the software ones: it
cannot be downgraded away. ``kind`` (``tpm2``, ``secure_enclave``, ``hsm``, ``kms`` or ``software``) is the pinned bundle's *claim*
about how the key is protected; nothing here attests it. ``require_hardware=True`` rejects a checkpoint not
signed by a ``tpm2``, ``secure_enclave``, ``hsm`` or ``kms`` key, and the result names the protection that signed.

Verification never trusts the log's own claims: events and checkpoints must match an exact
schema (no extra fields, lowercase hex only), every hash is recomputed and every signature
checked, and any malformed input is a failure rather than an exception.
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass
from typing import Any

from purpleteam.audit.hashing import GENESIS, canonical, event_hash, merkle_root, verify_inclusion
from purpleteam.audit.hardware_signer import HARDWARE_KINDS, PROTECTIONS, key_id, verify_p256
from purpleteam.audit.keys import (
    CHECKPOINT_CONTEXT, EVENT_CONTEXT, HARDWARE_CHECKPOINT_CONTEXT, kid_of, valid_actor, verify_pq, verify_signature)

CORE_FIELDS = ("seq", "ts", "actor", "kid", "kind", "payload", "prev", "log")
_EVENT_BASE = frozenset(CORE_FIELDS) | {"hash", "sig"}
_CHECKPOINT_FIELDS = ("size", "root", "ts", "kid", "log")
# lengths in hex characters: Ed25519 key 32 B and signature 64 B; ML-DSA-65 key 1952 B and signature 3309 B
_HEX = {name: re.compile(f"[0-9a-f]{{{n}}}") for name, n in
        (("kid", 16), ("log", 32), ("hash", 64), ("sig", 128), ("public", 64), ("mldsa_public", 3904),
         ("pqsig", 6618), ("hwsig", 128), ("hwpublic", 130))}


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    count: int
    broken_at: int | None = None
    reason: str = ""
    anchored: bool = False  # True only when a pinned, signed checkpoint matched the log
    anchored_at: float | None = None  # epoch seconds an outside timestamp authority vouched for (see audit.anchor)
    hardware: str = ""  # the claimed protection of the hardware key that signed the pinned checkpoint, if one did


def checkpoint_message(checkpoint: dict) -> bytes:
    """What every signature on a checkpoint covers, including the hardware key's id when there is one."""
    fields = _CHECKPOINT_FIELDS + (("hwkid",) if "hwkid" in checkpoint else ())
    return canonical({k: checkpoint[k] for k in fields})


def is_hex(kind: str, value: object) -> bool:
    return isinstance(value, str) and _HEX[kind].fullmatch(value) is not None


def _is_count(value: object) -> bool:
    return type(value) is int and value >= 0


_MAX_TIME = 1e15  # seconds; far beyond any real timestamp, and small enough that arithmetic on it cannot overflow


def _is_time(value: object) -> bool:
    return type(value) in (int, float) and abs(value) <= _MAX_TIME  # NaN and infinity compare False


def _fields_ok(value: dict, base: frozenset[str] | set[str]) -> bool:
    """Exactly the base fields, plus a well-formed ``pqsig`` when one is present."""
    fields = set(value)
    return fields == set(base) or (fields == set(base) | {"pqsig"} and is_hex("pqsig", value["pqsig"]))


def _valid_event(e: object) -> bool:
    return (isinstance(e, dict) and _fields_ok(e, _EVENT_BASE) and _is_count(e["seq"]) and _is_time(e["ts"])
            and valid_actor(e["actor"]) and isinstance(e["kind"], str) and isinstance(e["payload"], dict)
            and is_hex("kid", e["kid"]) and is_hex("log", e["log"]) and is_hex("hash", e["prev"])
            and is_hex("hash", e["hash"]) and is_hex("sig", e["sig"]))


def _valid_checkpoint(c: object) -> bool:
    if not isinstance(c, dict):
        return False
    hardware = {"hwkid", "hwsig"} & set(c)
    if hardware and hardware != {"hwkid", "hwsig"}:  # both or neither: a lone half is a stripped signature
        return False
    shape = _fields_ok({k: v for k, v in c.items() if k not in hardware}, set(_CHECKPOINT_FIELDS) | {"sig"})
    return (shape and _is_count(c["size"]) and _is_time(c["ts"]) and is_hex("kid", c["kid"])
            and is_hex("log", c["log"]) and is_hex("hash", c["root"]) and is_hex("sig", c["sig"])
            and (not hardware or (is_hex("kid", c["hwkid"]) and is_hex("hwsig", c["hwsig"]))))


def _valid_public(public: object) -> bool:
    if isinstance(public, str):  # a classical-only key
        return is_hex("public", public)
    return (isinstance(public, dict) and set(public) == {"ed25519", "mldsa65"}
            and is_hex("public", public["ed25519"]) and is_hex("mldsa_public", public["mldsa65"]))


def _trust(trust: dict) -> tuple[dict[str, dict[str, Any]], dict[str, int], dict[str, dict[str, str]]]:
    keys, revoked, hardware = trust.get("keys") or {}, trust.get("revoked") or {}, trust.get("hardware") or {}
    for actor, by_kid in keys.items():
        if not valid_actor(actor):
            raise ValueError("invalid actor in trust bundle")
        for kid, public in by_kid.items():
            if not (_valid_public(public) and kid_of(public) == kid):
                raise ValueError("trust bundle key does not match its id")
    if not all(is_hex("kid", kid) and _is_count(seq) for kid, seq in revoked.items()):
        raise ValueError("invalid revocation list")
    for hwkid, entry in hardware.items():
        if not (is_hex("kid", hwkid) and isinstance(entry, dict) and set(entry) == {"public", "kind"}
                and is_hex("hwpublic", entry["public"]) and entry["kind"] in PROTECTIONS
                and key_id(bytes.fromhex(entry["public"])) == hwkid):
            raise ValueError("trust bundle hardware key does not match its id")
    return keys, revoked, hardware


def _signed_by(keys: dict, revoked: dict, actor: str, kid: str, seq: int, data: bytes, signed: dict,
               context: bytes, require_pq: bool) -> bool:
    """A valid signature (``signed["sig"]``, and ``signed["pqsig"]`` when present) from a pinned key
    that was not revoked at ``seq``. A hybrid key needs both halves; no half can stand in for the other."""
    if kid in revoked and seq >= revoked[kid]:
        return False
    entry, pqsig = keys.get(actor, {}).get(kid), signed.get("pqsig")
    if isinstance(entry, str):  # classical-only key: fine unless post-quantum is demanded, and never with a stray pqsig
        return not require_pq and pqsig is None and verify_signature(entry, data, signed["sig"])
    if isinstance(entry, dict):
        return (pqsig is not None and verify_signature(entry["ed25519"], data, signed["sig"])
                and verify_pq(entry["mldsa65"], data, pqsig, context))
    return False


def _event_ok(event: dict, keys: dict, revoked: dict, require_pq: bool) -> bool:
    return (event_hash(event["prev"], {k: event[k] for k in CORE_FIELDS}) == event["hash"]
            and _signed_by(keys, revoked, event["actor"], event["kid"], event["seq"],
                           event["hash"].encode(), event, EVENT_CONTEXT, require_pq))


def _protection(checkpoint: dict, keys: dict, revoked: dict, require_pq: bool, hardware: dict) -> str | None:
    """None if the checkpoint is not authentic. ``""`` if only software keys signed it. Otherwise the protection
    claimed for the pinned hardware key that signed it too (whose signature must then verify, never be skipped)."""
    if not _valid_checkpoint(checkpoint):
        return None
    seq = checkpoint["size"] - 1
    if not _signed_by(keys, revoked, "ledger", checkpoint["kid"], seq, checkpoint_message(checkpoint), checkpoint,
                      CHECKPOINT_CONTEXT, require_pq):
        return None
    if "hwkid" not in checkpoint:
        return ""
    hwkid = checkpoint["hwkid"]
    entry = hardware.get(hwkid)
    if entry is None or (hwkid in revoked and seq >= revoked[hwkid]):
        return None
    signed = verify_p256(bytes.fromhex(entry["public"]), HARDWARE_CHECKPOINT_CONTEXT, checkpoint_message(checkpoint),
                         bytes.fromhex(checkpoint["hwsig"]))
    return entry["kind"] if signed else None


def verify_log(events: list[dict], trust: dict, *, min_checkpoint_size: int = 0,
               max_checkpoint_age: float | None = None, now: float | None = None,
               max_clock_skew: float = 60.0, require_pq: bool = False, require_hardware: bool = False) -> VerifyResult:
    """``anchored`` needs a pinned checkpoint of at least ``min_checkpoint_size`` events, no older than
    ``max_checkpoint_age`` seconds. ``require_pq`` rejects any classical-only signing key, and
    ``require_hardware`` any checkpoint not also signed by a hardware-protected key (not ``software``)."""
    try:
        return _verify_log(events, trust, min_checkpoint_size, max_checkpoint_age,
                           time.time() if now is None else now, max_clock_skew, require_pq, require_hardware)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return VerifyResult(False, len(events), None, "malformed log or trust bundle")


def _verify_log(events: list[dict], trust: dict, min_size: int, max_age: float | None,
                now: float, skew: float, require_pq: bool, require_hardware: bool) -> VerifyResult:
    keys, revoked, hardware = _trust(trust)
    heads: dict[str, str] = {}
    hashes: list[str] = []
    latest = -math.inf
    for index, event in enumerate(events):
        def fail(reason: str, at: int = index) -> VerifyResult:
            return VerifyResult(False, len(events), at, reason)

        if not _valid_event(event):
            return fail("malformed event")
        if event["seq"] != index:
            return fail("sequence gap or reorder")
        if event["log"] != events[0]["log"]:
            return fail("event belongs to a different log")
        if event["prev"] != heads.get(event["actor"], GENESIS):
            return fail("chain link broken")
        if event_hash(event["prev"], {k: event[k] for k in CORE_FIELDS}) != event["hash"]:
            return fail("content altered")
        if event["kid"] in revoked and index >= revoked[event["kid"]]:
            return fail("signing key revoked")
        if not _signed_by(keys, revoked, event["actor"], event["kid"], index, event["hash"].encode(), event,
                          EVENT_CONTEXT, require_pq):
            return fail("invalid signature or unknown key")
        if event["kind"] == "seal" and event["payload"].get("merkle_root") != merkle_root(hashes):
            return fail("seal does not match the log before it")
        if event["ts"] < latest - skew:
            return fail("timestamp goes backwards")
        latest = max(latest, event["ts"])
        heads[event["actor"]] = event["hash"]
        hashes.append(event["hash"])

    checkpoint = trust.get("checkpoint")
    if not checkpoint:
        return VerifyResult(True, len(events))
    protection = _protection(checkpoint, keys, revoked, require_pq, hardware)
    if protection is None:
        return VerifyResult(False, len(events), None, "checkpoint invalid, unsigned or key revoked")
    if require_hardware and protection not in HARDWARE_KINDS:
        return VerifyResult(False, len(events), None, "checkpoint is not signed by a hardware-protected key")
    if events and checkpoint["log"] != events[0]["log"]:
        return VerifyResult(False, len(events), None, "checkpoint belongs to a different log")
    if checkpoint["size"] > len(events):
        return VerifyResult(False, len(events), len(events), "log truncated since the checkpoint")
    if merkle_root(hashes[: checkpoint["size"]]) != checkpoint["root"]:
        return VerifyResult(False, len(events), None, "log rewritten since the checkpoint")
    if checkpoint["size"] < min_size:
        return VerifyResult(False, len(events), None, "checkpoint covers too little of the log")
    if max_age is not None and now - checkpoint["ts"] > max_age:
        return VerifyResult(False, len(events), None, "checkpoint is too old")
    return VerifyResult(True, len(events), anchored=True, hardware=protection)


def _member(event: object, path: object, size: int, keys: dict, revoked: dict, checkpoint: dict,
            require_pq: bool) -> bool:
    return (_valid_event(event) and event["log"] == checkpoint["log"] and _event_ok(event, keys, revoked, require_pq)
            and verify_inclusion(event["hash"], event["seq"], size, path, checkpoint["root"]))


def verify_proof(proof: dict[str, Any], trust: dict, *, require_pq: bool = False,
                 require_hardware: bool = False) -> bool:
    """One event is authentic, in the pinned checkpoint, and links to its actor's previous event.

    The proof carries the previous event of the same actor (with its own inclusion path), which
    shows the event's place one step back in its actor's chain. Proving the whole chain needs
    the neighbouring events, which a full ``verify_log`` covers.
    """
    try:
        keys, revoked, hardware = _trust(trust)
        checkpoint, size = trust["checkpoint"], proof["size"]
        protection = _protection(checkpoint, keys, revoked, require_pq, hardware)
        if protection is None or size != checkpoint["size"] or (require_hardware and protection not in HARDWARE_KINDS):
            return False
        event = proof["event"]
        if not _member(event, proof["path"], size, keys, revoked, checkpoint, require_pq):
            return False
        previous = proof.get("previous")
        if event["prev"] == GENESIS:
            return previous is None
        return (isinstance(previous, dict) and previous["event"]["hash"] == event["prev"]
                and previous["event"]["actor"] == event["actor"] and previous["event"]["seq"] < event["seq"]
                and _member(previous["event"], previous["path"], size, keys, revoked, checkpoint, require_pq))
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return False
