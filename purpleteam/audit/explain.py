"""Every step of a ledger's verification, shown rather than summarised: for each event, the exact bytes that
were hashed, the hash recomputed, the link to its actor's previous event, the key that signed it and each
signature checked; for the checkpoint, the Merkle tree rebuilt from the events and each of its signatures.

Nothing here decides anything new. It runs the same checks with the same primitives as ``audit.verify``
(which stays the authority, and stops at the first failure) but keeps going, so a reader can see what
passed, what did not, and why. Public keys and signatures are public material; the event payloads are what
the run already shows.
"""

from __future__ import annotations

from typing import Any

from purpleteam.audit.anchor import AnchorError, verify_anchor
from purpleteam.audit.hashing import GENESIS, canonical, event_hash, merkle_root, merkle_tree
from purpleteam.audit.hardware_signer import verify_p256
from purpleteam.audit.keys import EVENT_CONTEXT, HARDWARE_CHECKPOINT_CONTEXT, CHECKPOINT_CONTEXT, verify_pq, verify_signature
from purpleteam.audit.verify import CORE_FIELDS, _trust, _valid_checkpoint, _valid_event, checkpoint_message


def _check(name: str, ok: bool | None, detail: str) -> dict:
    return {"check": name, "ok": ok, "detail": detail}


def _signatures(entry: Any, data: bytes, signed: dict, context: bytes) -> list[dict]:
    """Each half of a signature on its own: Ed25519 always, ML-DSA-65 when the key is hybrid."""
    if entry is None:
        return [_check("signing key", False, "no pinned key with this id for this actor")]
    classical = entry if isinstance(entry, str) else entry["ed25519"]
    checks = [_check("Ed25519 signature", verify_signature(classical, data, signed["sig"]),
                     "verified with the actor's pinned Ed25519 public key")]
    if isinstance(entry, dict):
        pq = signed.get("pqsig")
        checks.append(_check("ML-DSA-65 signature", pq is not None and verify_pq(entry["mldsa65"], data, pq, context),
                             "post-quantum half; a hybrid key needs both halves to verify"))
    return checks


def _anchors(trust: dict, authorities: dict) -> list[dict]:
    """Each timestamp token on the checkpoint, verified against its authority's pinned certificates: valid for
    exactly this checkpoint, and stamped no earlier than the checkpoint claims to be (within a minute)."""
    checkpoint, results = trust.get("checkpoint") or {}, []
    for anchor in trust.get("anchors") or []:
        name = anchor.get("authority", "?") if isinstance(anchor, dict) else "?"
        try:
            stamped = verify_anchor(checkpoint, anchor, authorities)
            ok = checkpoint.get("ts", 0) <= stamped.timestamp() + 60
            results.append({"authority": name, "ok": ok, "time": stamped.timestamp(),
                            "detail": "token verified against the authority's pinned certificate" if ok
                            else "the checkpoint claims a time after its own timestamp"})
        except AnchorError as error:
            results.append({"authority": name, "ok": False, "time": None, "detail": str(error)})
    return results


def explain_log(events: list[dict], trust: dict, authorities: dict | None = None) -> dict:
    keys, revoked, hardware = _trust(trust)
    heads: dict[str, tuple[str, int]] = {}
    hashes: list[str] = []
    explained = []
    for index, event in enumerate(events):
        if not _valid_event(event):
            explained.append({"seq": index, "checks": [_check("well-formed", False, "fields or encodings are wrong")]})
            continue
        core = {k: event[k] for k in CORE_FIELDS}
        recomputed = event_hash(event["prev"], core)
        head, head_seq = heads.get(event["actor"], (GENESIS, None))
        entry = keys.get(event["actor"], {}).get(event["kid"])
        checks = [
            _check("in sequence", event["seq"] == index, f"position {index} in the log"),
            _check("chained to its actor's previous event", event["prev"] == head,
                   "first event of this actor (genesis)" if head_seq is None else f"links to event #{head_seq}"),
            _check("content hash", recomputed == event["hash"], "SHA-256 of the previous hash + the canonical event"),
            _check("key not revoked", not (event["kid"] in revoked and index >= revoked[event["kid"]]), event["kid"]),
            *_signatures(entry, event["hash"].encode(), event, EVENT_CONTEXT),
        ]
        if event["kind"] == "seal":
            root = merkle_root(hashes)
            checks.append(_check("seal matches the log before it", event["payload"].get("merkle_root") == root,
                                 f"Merkle root of events #0..#{index - 1} recomputed: {root}"))
        explained.append({
            "seq": index, "actor": event["actor"], "kind": event["kind"], "ts": event["ts"], "kid": event["kid"],
            "prev": event["prev"], "prev_seq": head_seq, "hash": event["hash"], "recomputed": recomputed,
            "hashed": event["prev"] + canonical(core).decode("utf-8"), "signed": event["hash"],
            "context": EVENT_CONTEXT.decode(), "sig": event["sig"], "pqsig": event.get("pqsig"),
            "public": entry, "checks": checks})
        heads[event["actor"]] = (event["hash"], index)
        hashes.append(event["hash"])
    return {"events": explained, "keys": keys, "tree": merkle_tree(hashes),
            "checkpoint": _explain_checkpoint(trust.get("checkpoint"), keys, hardware, events, hashes),
            "anchors": _anchors(trust, authorities or {})}


def _explain_checkpoint(checkpoint: Any, keys: dict, hardware: dict, events: list[dict], hashes: list[str]) -> dict | None:
    if not checkpoint:
        return None
    if not _valid_checkpoint(checkpoint):
        return {"checks": [_check("well-formed", False, "fields or encodings are wrong")]}
    message = checkpoint_message(checkpoint)
    size = checkpoint["size"]
    root = merkle_root(hashes[:size]) if size <= len(hashes) else None
    checks = [
        _check("same log", not events or checkpoint["log"] == events[0]["log"], checkpoint["log"]),
        _check("covers the log", size <= len(hashes), f"signed over the first {size} of {len(hashes)} events"),
        _check("Merkle root", root == checkpoint["root"], f"recomputed from the events: {root}"),
        *_signatures(keys.get("ledger", {}).get(checkpoint["kid"]), message, checkpoint, CHECKPOINT_CONTEXT),
    ]
    hw = None
    if "hwkid" in checkpoint:
        hw = hardware.get(checkpoint["hwkid"])
        ok = hw is not None and verify_p256(bytes.fromhex(hw["public"]), HARDWARE_CHECKPOINT_CONTEXT, message,
                                            bytes.fromhex(checkpoint["hwsig"]))
        checks.append(_check("hardware (ECDSA P-256) signature", ok,
                             f"key claimed to be protected by: {hw['kind']}" if hw else "hardware key is not pinned"))
    return {**checkpoint, "message": message.decode("utf-8"), "context": CHECKPOINT_CONTEXT.decode(),
            "recomputed_root": root, "hardware": hw, "checks": checks}
