"""Hybrid signing keys, one set per actor, so every agent signs its own audit events and cannot deny them.

Each key is a pair: Ed25519 plus ML-DSA-65 (FIPS 204). A signature is valid only if *both* halves
verify, so breaking either algorithm alone forges nothing, and evidence stays trustworthy if a
quantum computer later breaks Ed25519. The key id (``kid``) hashes both public keys under a domain
label, so the signed event hash binds both. ML-DSA signatures are made under a context string that
names what is signed (an event or a checkpoint), so one can never pass for the other.

A keyring never signs classically unless created with ``pq=False``: there is no silent fallback when
ML-DSA is unavailable, and a current key without a post-quantum half is rotated to a hybrid one
before it signs. Keys carry their ``kid`` so events stay verifiable after a rotation. Without a
directory the keyring is ephemeral (tests, demos). With one, private keys are stored as
passphrase-encrypted PKCS#8 (``<actor>.<n>.<kid>.pem`` for Ed25519, ``….mldsa.pem`` for ML-DSA) and
never written in the clear; supply the passphrase from the environment or a secrets manager. A
stored key whose ML-DSA file is missing is refused rather than quietly downgraded. Because a hybrid
key file renamed to a classical id (its ML-DSA file deleted) looks exactly like a classical key, a
post-quantum keyring refuses to load *any* classical-only key unless it is opened with
``allow_classical_history=True``, which is for a directory that really was created before
post-quantum keys; even then it never signs with such a key. Any object with
``kid`` / ``sign`` / ``rotate`` / ``public_keys`` can replace this class, which is how a KMS or HSM
signer plugs in. Public keys are exportable for offline verification; private keys never leave it.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

try:
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
    PQ_AVAILABLE = True
except ImportError:  # cryptography older than 48, or built without ML-DSA
    PQ_AVAILABLE = False

EVENT_CONTEXT = b"purpleteam.audit.event.v1"
CHECKPOINT_CONTEXT = b"purpleteam.audit.checkpoint.v1"
HARDWARE_CHECKPOINT_CONTEXT = b"purpleteam.audit.checkpoint.hw.v1"  # the hardware key signs under its own context
_HYBRID_DOMAIN = b"purpleteam.hybrid-key.v1"
_RAW = {"encoding": serialization.Encoding.Raw, "format": serialization.PublicFormat.Raw}
_ACTOR = re.compile(r"^[A-Za-z0-9_-]{1,64}$")  # actors name key files, so no path characters
_NO_PQ = ("post-quantum signing needs a cryptography build with ML-DSA (cryptography>=48 on OpenSSL 3.5 or "
          "later); install one, or create the keyring with pq=False to sign with Ed25519 only")

PublicKey = str | dict[str, str]  # Ed25519 hex, or {"ed25519": hex, "mldsa65": hex}


def valid_actor(actor: object) -> bool:
    return isinstance(actor, str) and _ACTOR.fullmatch(actor) is not None


def kid_of(public: PublicKey) -> str:
    """A key's id: a hash of every public key it holds, so a hybrid and a classical key never collide."""
    if isinstance(public, str):
        return hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16]
    material = _HYBRID_DOMAIN + bytes.fromhex(public["ed25519"]) + bytes.fromhex(public["mldsa65"])
    return hashlib.sha256(material).hexdigest()[:16]


@dataclass(frozen=True)
class Signature:
    ed25519: str
    mldsa65: str | None = None


@dataclass(frozen=True)
class _Pair:
    ed: Ed25519PrivateKey
    pq: Any = None  # MLDSA65PrivateKey, or None for a classical-only key

    @cached_property
    def public(self) -> PublicKey:
        ed = self.ed.public_key().public_bytes(**_RAW).hex()
        return ed if self.pq is None else {"ed25519": ed, "mldsa65": self.pq.public_key().public_bytes_raw().hex()}

    @cached_property
    def kid(self) -> str:
        return kid_of(self.public)


class AgentKeyring:
    def __init__(self, directory: str | Path | None = None, passphrase: bytes | None = None, *,
                 pq: bool = True, allow_classical_history: bool = False) -> None:
        if directory is not None and not passphrase:
            raise ValueError("a passphrase is required to store private keys")
        if pq and not PQ_AVAILABLE:
            raise RuntimeError(_NO_PQ)
        self._pq = pq
        self._allow_classical = allow_classical_history
        self._dir = Path(directory) if directory is not None else None
        self._passphrase = passphrase
        self._generations: dict[str, list[_Pair]] = {}  # oldest first; last is current
        if self._dir is not None:
            self._dir.mkdir(parents=True, exist_ok=True)
            self._load()

    def kid(self, actor: str) -> str:
        return self._current(actor).kid

    def sign(self, actor: str, data: bytes, context: bytes, kid: str | None = None) -> Signature:
        """Sign with the current key, or with the generation named by ``kid`` (so a rotation between
        choosing a key id and signing cannot make a signature disagree with the id it is filed under)."""
        pair = self._current(actor) if kid is None else self._generation(actor, kid)
        return Signature(pair.ed.sign(data).hex(), pair.pq.sign(data, context).hex() if pair.pq is not None else None)

    def rotate(self, actor: str) -> str:
        """Start a new key generation for ``actor``; older events stay verifiable."""
        self._check(actor)
        pair = self._new_pair()
        self._add(actor, pair)
        return pair.kid

    def public_keys(self) -> dict[str, dict[str, PublicKey]]:
        """actor -> {kid: public key} for every generation, for pinning and offline checks."""
        return {actor: {pair.kid: pair.public for pair in pairs} for actor, pairs in self._generations.items()}

    def _new_pair(self) -> _Pair:
        try:
            return _Pair(Ed25519PrivateKey.generate(), MLDSA65PrivateKey.generate() if self._pq else None)
        except UnsupportedAlgorithm as error:
            raise RuntimeError(_NO_PQ) from error

    def _current(self, actor: str) -> _Pair:
        self._check(actor)
        pairs = self._generations.get(actor)
        if not pairs or (self._pq and pairs[-1].pq is None):  # never sign classically from a post-quantum keyring
            self._add(actor, self._new_pair())
        return self._generations[actor][-1]

    def _generation(self, actor: str, kid: str) -> _Pair:
        self._check(actor)
        for pair in self._generations.get(actor, []):
            if pair.kid == kid:
                if self._pq and pair.pq is None:
                    raise ValueError("a post-quantum keyring does not sign with a classical-only key")
                return pair
        raise ValueError("this actor has no key with that id")

    @staticmethod
    def _check(actor: str) -> None:
        if not valid_actor(actor):
            raise ValueError(f"invalid actor name: {actor!r}")

    def _add(self, actor: str, pair: _Pair) -> None:
        generation = len(self._generations.get(actor, []))
        if self._dir is not None:  # persisted before it can sign, so no event is ever signed by a key we could lose
            self._store(actor, generation, pair)
        self._generations.setdefault(actor, []).append(pair)

    def _store(self, actor: str, generation: int, pair: _Pair) -> None:
        stem = self._dir / f"{actor}.{generation:04d}.{pair.kid}"
        if pair.pq is not None:  # the Ed25519 file marks a complete generation, so it is written last
            self._write(Path(f"{stem}.mldsa.pem"), pair.pq)
        self._write(Path(f"{stem}.pem"), pair.ed)

    def _write(self, target: Path, key: Any) -> None:
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(self._passphrase))
        temp = Path(f"{target}.tmp")
        temp.write_bytes(pem)
        os.chmod(temp, 0o600)  # best effort on Windows, which only honours the read-only bit
        os.replace(temp, target)

    def _read(self, path: Path, expected: type) -> Any:
        key = serialization.load_pem_private_key(path.read_bytes(), self._passphrase)
        if not isinstance(key, expected):
            raise ValueError(f"key file holds the wrong kind of key: {path.name}")
        return key

    def _load(self) -> None:
        for path in sorted(self._dir.glob("*.pem")):
            if path.name.endswith(".mldsa.pem"):
                continue  # read together with its Ed25519 file below
            parts = path.name.split(".")
            if len(parts) != 4:
                raise ValueError(f"unexpected file in the key directory: {path.name}")
            actor, generation, kid, _ = parts
            self._check(actor)
            pq_path = path.with_name(f"{actor}.{generation}.{kid}.mldsa.pem")
            if pq_path.exists() and not PQ_AVAILABLE:
                raise RuntimeError(_NO_PQ)
            pair = _Pair(self._read(path, Ed25519PrivateKey),
                         self._read(pq_path, MLDSA65PrivateKey) if pq_path.exists() else None)
            if pair.kid != kid or int(generation) != len(self._generations.get(actor, [])):
                raise ValueError(f"key file does not match its name, is incomplete, or is out of sequence: {path.name}")
            if self._pq and pair.pq is None and not self._allow_classical:
                raise ValueError(f"classical-only key in a post-quantum key directory (renamed, or created before "
                                 f"post-quantum keys; see allow_classical_history): {path.name}")
            self._generations.setdefault(actor, []).append(pair)


def verify_signature(public_hex: str, data: bytes, signature_hex: str) -> bool:
    if not public_hex:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(signature_hex), data)
        return True
    except Exception:
        return False


def verify_pq(public_hex: str, data: bytes, signature_hex: str, context: bytes) -> bool:
    """An ML-DSA-65 signature under ``context``; False (never an exception) on any failure, including no ML-DSA."""
    if not PQ_AVAILABLE or not public_hex:
        return False
    try:
        MLDSA65PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(signature_hex), data, context)
        return True
    except Exception:
        return False
