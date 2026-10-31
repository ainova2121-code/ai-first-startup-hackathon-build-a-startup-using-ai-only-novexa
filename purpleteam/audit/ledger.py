"""A tamper-evident audit ledger: per-agent Ed25519-signed hash chains with a Merkle root.

Every event (an attack, a breach, a patch, a verdict) is appended to its actor's own hash
chain, bound to the signing key's id, and signed by that actor's key, so altering, reordering or
removing an event breaks the chain and each action is attributable to one agent. ``seal`` folds
all event hashes into a Certificate-Transparency-style Merkle root and ``checkpoint`` signs the
root with the log size, so a published checkpoint exposes later truncation or rewriting.
``verify`` and ``prove`` rely on a trust bundle pinned out of band (see ``audit.verify``).

Appends are serialised by an OS file lock, so several writers can share one log; each writer
resumes from the bytes it has not read yet. A partial trailing record (a crash mid-write) is
refused rather than extended. The file is plain JSONL: its integrity comes from the chain, so
store it somewhere write-once (object lock, WORM volume) if you also need to prevent deletion.

Checkpoints can also be signed by a hardware key (a TPM, via ``hardware=``): a third, ECDSA P-256 signature next
to the Ed25519 and ML-DSA ones, so a stolen log directory still cannot mint checkpoints without the machine
holding that key. The software signatures cover the hardware key's id, so the hardware signature cannot be
stripped off. Once a signer is configured, failing to use it stops the checkpoint: the ledger never quietly
falls back to software. The exported trust bundle states the key's claimed protection (``tpm2``, ``software``...).
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from purpleteam.audit.hashing import GENESIS, canonical, event_hash, inclusion_path, merkle_root
from purpleteam.audit.hardware_signer import PROTECTIONS, HardwareSigner, SignerError, key_id, verify_p256
from purpleteam.audit.keys import CHECKPOINT_CONTEXT, EVENT_CONTEXT, HARDWARE_CHECKPOINT_CONTEXT, AgentKeyring
from purpleteam.audit.verify import CORE_FIELDS, VerifyResult, checkpoint_message, is_hex, verify_log

__all__ = ["AuditLedger", "LedgerCorrupt", "GENESIS", "VerifyResult", "merkle_root"]

CHECKPOINT_ACTOR = "ledger"

if os.name == "nt":
    import msvcrt

    def _lock(handle) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)

    def _unlock(handle) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(handle) -> None:
        fcntl.flock(handle, fcntl.LOCK_EX)

    def _unlock(handle) -> None:
        fcntl.flock(handle, fcntl.LOCK_UN)


class LedgerCorrupt(Exception):
    """The log file cannot be extended safely (partial or unreadable record)."""


class AuditLedger:
    def __init__(self, path: str | Path, keyring: AgentKeyring | None = None, redactor=None, *,
                 log_id: str | None = None, pinned_checkpoint: dict | None = None,
                 hardware: HardwareSigner | None = None, pinned_hardware: dict | None = None,
                 on_append: Callable[[dict], None] | None = None) -> None:
        """``pinned_checkpoint`` (a checkpoint published earlier) makes a restart refuse a truncated or rewritten log;
        if it carries a hardware signature, ``pinned_hardware`` (the ``hardware`` part of its trust bundle) lets a
        machine without that key check it too. ``on_append`` is called with each event once it is signed and on
        disk, so a live viewer can show every signature the moment it happens."""
        self._on_append = on_append
        if log_id is not None and not is_hex("log", log_id):
            raise ValueError("log_id must be 32 lowercase hex characters")
        if hardware is not None and (getattr(hardware, "kind", None) not in PROTECTIONS
                                     or len(hardware.public_key()) != 65):
            raise ValueError("hardware must be a HardwareSigner with a kind and a P-256 public key")
        self._hardware, self._pinned_hardware = hardware, pinned_hardware
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.path.with_suffix(".lock")
        self._keyring = keyring or AgentKeyring()
        self._redactor = redactor
        self._mutex = threading.Lock()
        self._offset = 0                    # bytes of the file already read into the state below
        self._hashes: list[str] = []
        self._heads: dict[str, str] = {}
        self._log_id = log_id               # fixed by the first event; every event and checkpoint carries it
        with self._locked():
            self._sync()
        if pinned_checkpoint is not None:
            if not isinstance(pinned_checkpoint, dict) or not pinned_checkpoint:
                raise ValueError("pinned_checkpoint must be a checkpoint, not an empty value")
            result = verify_log(self.events(), {"keys": self._keyring.public_keys(), "checkpoint": pinned_checkpoint,
                                                "hardware": self._hardware_trust()})
            if not (result.ok and result.anchored):  # a pin that was not actually applied is a failure too
                raise LedgerCorrupt(f"the log fails the pinned checkpoint: {result.reason or 'checkpoint not applied'}")

    def append(self, actor: str, kind: str, payload: dict) -> dict:
        if self._redactor is not None:
            payload = self._redactor.redact(payload)
        with self._locked():
            self._sync()
            if self.path.exists() and self.path.stat().st_size != self._offset:
                raise LedgerCorrupt("incomplete trailing record; repair the log before appending")
            core = {"seq": len(self._hashes), "ts": round(time.time(), 3), "actor": actor,
                    "kid": self._keyring.kid(actor), "kind": kind, "payload": payload,
                    "prev": self._heads.get(actor, GENESIS), "log": self._ensure_log_id()}
            digest = event_hash(core["prev"], core)
            signature = self._keyring.sign(actor, digest.encode(), EVENT_CONTEXT, kid=core["kid"])
            event = {**core, "hash": digest, "sig": signature.ed25519,
                     **({"pqsig": signature.mldsa65} if signature.mldsa65 else {})}
            with self.path.open("ab") as handle:
                handle.write(canonical(event) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._sync()
        if self._on_append is not None:
            self._on_append(event)
        return event

    def public_keys(self) -> dict:
        """Every actor's public signing keys so far: enough to verify each event before the log is sealed."""
        return self._keyring.public_keys()

    def events(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except ValueError as error:
            raise LedgerCorrupt("unreadable record in the log") from error

    def count(self) -> int:
        with self._locked():
            self._sync()
            return len(self._hashes)

    @property
    def log_id(self) -> str | None:
        """This ledger's fixed id (every event and checkpoint carries it); ``None`` until the first append."""
        return self._log_id

    def seal(self) -> str:
        with self._locked():
            self._sync()
            return merkle_root(self._hashes)

    def checkpoint(self) -> dict:
        """A signed statement of the log's size and root, to be published somewhere the log's owner cannot edit."""
        with self._locked():
            self._sync()
            result = verify_log(self.events(), {"keys": self._keyring.public_keys()})
            if not result.ok:  # never vouch for a log that is already broken
                raise LedgerCorrupt(f"refusing to sign a checkpoint: {result.reason}")
            checkpoint = {"size": len(self._hashes), "root": merkle_root(self._hashes),
                          "ts": round(time.time(), 3), "kid": self._keyring.kid(CHECKPOINT_ACTOR),
                          "log": self._ensure_log_id()}
            if self._hardware is not None:
                checkpoint["hwkid"] = key_id(self._hardware.public_key())  # signed by the software keys too
        message = checkpoint_message(checkpoint)
        signature = self._keyring.sign(CHECKPOINT_ACTOR, message, CHECKPOINT_CONTEXT, kid=checkpoint["kid"])
        signed = {**checkpoint, "sig": signature.ed25519, **({"pqsig": signature.mldsa65} if signature.mldsa65 else {})}
        if self._hardware is not None:
            hwsig = self._hardware.sign(message, HARDWARE_CHECKPOINT_CONTEXT)
            if not verify_p256(self._hardware.public_key(), HARDWARE_CHECKPOINT_CONTEXT, message, hwsig):
                raise SignerError("the hardware signer produced a signature that does not verify")
            signed["hwsig"] = hwsig.hex()
        return signed

    def export_trust(self) -> dict:
        """Public keys plus a fresh checkpoint (and the hardware key, if any): pin this somewhere separate from the log."""
        checkpoint = self.checkpoint()
        return {**self.public_trust(), "checkpoint": checkpoint}

    def public_trust(self) -> dict:
        """The public keys (and revocations) a reader verifies events against, with no checkpoint to sign."""
        trust = {"keys": self._keyring.public_keys()}
        if self._hardware is not None:
            trust["hardware"] = self._hardware_trust_own()
        revoked = self._keyring.revoked()
        if revoked:
            trust["revoked"] = revoked
        return trust

    def _hardware_trust_own(self) -> dict:
        public = self._hardware.public_key()
        return {key_id(public): {"public": public.hex(), "kind": self._hardware.kind}}

    def _hardware_trust(self) -> dict:
        return {**(self._pinned_hardware or {}), **(self._hardware_trust_own() if self._hardware is not None else {})}

    def prove(self, seq: int, size: int | None = None) -> dict:
        """Inclusion proof for one event, and for its actor's previous event, against the first ``size`` events."""
        with self._locked():
            self._sync()
            size = len(self._hashes) if size is None else size
            if not 0 <= seq < size <= len(self._hashes):
                raise IndexError("event outside the requested tree size")
            hashes, events = self._hashes[:size], self.events()
        event, previous = events[seq], None
        if event["prev"] != GENESIS:
            prior = next(e for e in events if e["hash"] == event["prev"])
            previous = {"event": prior, "path": inclusion_path(hashes, prior["seq"])}
        return {"event": event, "size": size, "path": inclusion_path(hashes, seq), "previous": previous}

    def verify(self, trust: dict | None = None, **policy) -> VerifyResult:
        """Check the log. Without ``trust`` this only proves internal consistency (``anchored`` is False).

        ``policy`` is passed to ``verify_log`` (minimum checkpoint size, maximum checkpoint age, clock skew).
        """
        trust = trust if trust is not None else {"keys": self._keyring.public_keys()}
        try:
            return verify_log(self.events(), trust, **policy)
        except LedgerCorrupt:
            return VerifyResult(False, 0, None, "unreadable record in the log")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._mutex, self._lock_path.open("a+b") as handle:
            _lock(handle)
            try:
                yield
            finally:
                _unlock(handle)

    def _sync(self) -> None:
        """Read complete records appended (by any writer) since the last read."""
        if not self.path.exists():
            return
        with self.path.open("rb") as handle:
            handle.seek(self._offset)
            chunk = handle.read()
        complete = chunk[: chunk.rfind(b"\n") + 1]
        for line in complete.splitlines():
            try:
                event = json.loads(line)
                if event["seq"] != len(self._hashes) or any(k not in event for k in CORE_FIELDS):
                    raise KeyError("seq")
                digest, actor, log = event["hash"], event["actor"], event["log"]
                if not is_hex("log", log) or self._log_id not in (None, log):
                    raise ValueError("log id")
            except (ValueError, KeyError, TypeError) as error:
                raise LedgerCorrupt("unreadable record in the log") from error
            self._log_id = log
            self._hashes.append(digest)
            self._heads[actor] = digest
        self._offset += len(complete)

    def _ensure_log_id(self) -> str:
        if self._log_id is None:
            self._log_id = uuid.uuid4().hex
        return self._log_id


def _main() -> None:
    """Demo: record one engagement, seal it, pin a checkpoint, then tamper and truncate."""
    import tempfile

    ledger = AuditLedger(Path(tempfile.mkdtemp(prefix="audit-")) / "audit.jsonl")
    ledger.append("attacker", "attack", {"objective": "redirect payment", "technique": "dan_1"})
    ledger.append("oracle", "breach", {"tool": "update_vendor_bank", "proof": "canary reached bank_account"})
    ledger.append("defender", "patch", {"patch_ids": ["P2", "P4"], "code_hash": "a1b2c3d4"})
    ledger.append("verifier", "verdict", {"attack_blocked": True, "safe_to_ship": True})
    ledger.append("audit", "seal", {"merkle_root": ledger.seal()})
    trust = ledger.export_trust()  # pinned out of band: it is what makes tampering provable

    print(f"events: {ledger.count()} · root: {trust['checkpoint']['root'][:16]}…")
    print("intact:   ", ledger.verify(trust))
    lines = ledger.path.read_text().splitlines()
    ledger.path.write_text("\n".join(lines[:-1]) + "\n")
    print("truncated:", ledger.verify(trust))
    lines[1] = lines[1].replace("update_vendor_bank", "lookup_vendor")
    ledger.path.write_text("\n".join(lines) + "\n")
    print("tampered: ", ledger.verify(trust))


if __name__ == "__main__":
    _main()
