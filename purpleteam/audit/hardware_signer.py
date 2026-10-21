"""Signers whose private key lives in hardware, and the check anyone can run on what they sign.

A ``HardwareSigner`` holds an ECDSA P-256 key that never leaves its chip (a TPM today; a Secure Enclave
later) and signs on request. P-256 is what TPMs and Secure Enclaves implement; they do not offer Ed25519 or
ML-DSA, so a hardware signature is an *additional* component next to the ledger's software hybrid, never a
replacement for it. Because the key cannot be copied, a signature proves the signing happened on that machine.

A signer here is only ever asked to sign a *checkpoint* (``audit.ledger.AuditLedger.checkpoint``), never an
individual event: a hardware round trip (tens to hundreds of milliseconds) on every event would make the
gateway's request path far too slow, so every event instead gets the fast software hybrid signature, and the
hardware key signs only the periodic summary. This is a difference in signing *cadence*, not in what is
protected — a checkpoint signs the Merkle root of every event up to its size, so a single altered bit in any
one of those events changes its hash, changes the root, and breaks the checkpoint's signature. A hardware
signature on the checkpoint therefore still vouches for every event under it, just less often than per event.

Every signature is made over ``signed_message(context, data)``, a length-prefixed, domain-separated message,
so a signature made for one purpose (a checkpoint) can never pass for another (an event). Signatures are the
raw 64-byte ``r || s`` that TPMs return. ``verify_p256`` needs no hardware and never raises, so an auditor
can check a signature on any machine.

A signer states how its key is protected in ``kind``: ``tpm2``, ``secure_enclave``, ``hsm`` (a PKCS#11 hardware
module), ``kms`` (a cloud key service whose keys sit in the provider's HSMs) or ``software``. The
``software`` signer exists for machines with no hardware and for tests, and it is always labelled: evidence
must say which protection a key had, so a software key is never mistaken for a hardware one. ``open_signer``
never falls back to software on its own; it refuses and says why.
"""

from __future__ import annotations

import hashlib
import re
from typing import Callable, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from purpleteam.audit.hardware import SECURE_ENCLAVE, TPM2, Probes, RootOfTrust, detect

PREFIX = b"purpleteam.hardware-signature.v1"
SOFTWARE, HSM, KMS = "software", "hsm", "kms"
PROTECTIONS = (TPM2, SECURE_ENCLAVE, HSM, KMS, SOFTWARE)  # how a signing key can be protected
HARDWARE_KINDS = (TPM2, SECURE_ENCLAVE, HSM, KMS)  # the ones that count as hardware; "software" never does
POLICIES = ("off", "preferred", "required")
POINT_BYTES, SIGNATURE_BYTES = 65, 64
KEY_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


class SignerError(RuntimeError):
    """The hardware refused or failed. The message never holds key material."""


class SignerUnavailable(SignerError):
    """No usable hardware signer here, with the reason; the caller must choose what to do instead."""


class HardwareSigner(Protocol):
    kind: str  # how the private key is protected

    def public_key(self) -> bytes:
        """The key's public half as an uncompressed P-256 point (65 bytes)."""
        ...

    def sign(self, data: bytes, context: bytes) -> bytes:
        """64 bytes ``r || s`` over ``signed_message(context, data)``."""
        ...

    def close(self) -> None: ...


def signed_message(context: bytes, data: bytes) -> bytes:
    """What is actually signed: unambiguous, so no context/data pair can be read as another."""
    if len(context) > 0xFFFF:
        raise ValueError("a signing context is at most 65535 bytes")
    return PREFIX + len(context).to_bytes(2, "big") + context + data


def key_id(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()[:16]


def verify_p256(public: bytes, context: bytes, data: bytes, signature: bytes) -> bool:
    """True only for a valid signature by this public key over this context and data. Never raises."""
    try:
        if len(public) != POINT_BYTES or len(signature) != SIGNATURE_BYTES:
            return False
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        if not (0 < r < _ORDER and 0 < s < _ORDER):
            return False
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)  # rejects points off the curve
        key.verify(encode_dss_signature(r, s), signed_message(context, data), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError, OverflowError):
        return False


class SoftwareP256Signer:
    """A P-256 key held in memory. It has no hardware protection and says so; use it only where there is no hardware."""

    kind = SOFTWARE

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._public = self._key.public_key().public_bytes(serialization.Encoding.X962,
                                                           serialization.PublicFormat.UncompressedPoint)

    def public_key(self) -> bytes:
        return self._public

    def sign(self, data: bytes, context: bytes) -> bytes:
        r, s = decode_dss_signature(self._key.sign(signed_message(context, data), ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def close(self) -> None:
        pass


def open_signer(name: str, *, probes: Probes | None = None, system: str | None = None) -> HardwareSigner:
    """The hardware signer for key ``name`` on this machine (created on first use), or ``SignerUnavailable``.

    Windows with a TPM 2.0 is supported. Every other case refuses with a reason; nothing falls back to software.
    """
    if not KEY_NAME.fullmatch(name or ""):
        raise ValueError("a key name is 1-64 letters, digits, dots, dashes or underscores")
    root = detect(probes, system)
    if root.kind == TPM2 and root.reachable and root.system == "Windows":
        from purpleteam.audit.tpm_windows import WindowsTpmSigner

        return WindowsTpmSigner(name)
    raise SignerUnavailable(_why(root))


def resolve_signer(policy: str, name: str, *, probes: Probes | None = None, system: str | None = None,
                   opener: Callable[[], HardwareSigner] | None = None) -> tuple[HardwareSigner | None, str]:
    """The signer to use under a customer's policy, and a note saying what was decided.

    ``off`` never uses hardware. ``preferred`` uses the best hardware here and otherwise carries on without it
    (the note says why). ``required`` raises ``SignerUnavailable`` rather than run without hardware. Without an
    ``opener`` the machine's own TPM is tried; pass one to use another backend, for example
    ``lambda: AwsKmsSigner.from_boto3(key_arn)``. Only ``SignerUnavailable`` (the backend is not installed or not
    there) is soft under ``preferred``; a configured backend that refuses (``SignerError``) is a fault and always
    raises, because quietly dropping to software would hide a misconfiguration.
    """
    if policy not in POLICIES:
        raise ValueError(f"hardware signing policy must be one of {', '.join(POLICIES)}")
    if policy == "off":
        return None, "hardware signing is off"
    try:
        signer = opener() if opener is not None else open_signer(name, probes=probes, system=system)
    except SignerUnavailable as error:
        if policy == "required":
            raise
        return None, f"continuing without hardware signing: {error}"
    return signer, f"signing checkpoints with a {signer.kind} key"


def _why(root: RootOfTrust) -> str:
    if root.present is None:
        return f"could not tell whether this machine has a hardware root of trust: {'; '.join(root.notes)}"
    if not root.present:
        return f"this machine has no hardware root of trust: {'; '.join(root.notes)}"
    if root.kind == SECURE_ENCLAVE:
        return "this Mac has a Secure Enclave, but its signer is not built yet"
    if not root.reachable:
        return f"a {root.kind} is present but this process cannot open it: {'; '.join(root.notes)}"
    return f"a {root.kind} is present on {root.system}, but its signer is not built yet"
