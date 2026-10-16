"""A signing key held in AWS KMS: an ECC_NIST_P256 key whose private half never leaves AWS's HSMs.

Signing sends KMS a SHA-256 digest and gets back an ECDSA signature, so the result is the same 64-byte
``r || s`` over ``signed_message`` that every other hardware signer produces and ``verify_p256`` checks. The
signer is written against the two KMS calls it needs (``get_public_key`` and ``sign``, with boto3's names and
shapes), so the customer's own ``boto3`` supplies credentials the way their environment already does: instance
roles, container roles, web identity, SSO, profiles. Nothing here reads or stores AWS credentials, and boto3 is
not a dependency of this project: ``from_boto3`` imports it only if the customer has installed it.

A key may be named by id, ARN or alias. Aliases can be re-pointed, so the signer reads the key's real ARN once
and refuses any signature that KMS reports as made by a different key: the public key we pinned is always the
one that signed. The key must be ECC_NIST_P256 with usage SIGN_VERIFY and the ECDSA_SHA_256 algorithm.

Errors name AWS's own error code (``AccessDeniedException``, ``ThrottlingException``...) and nothing else:
no ARNs, account ids or request ids reach exceptions or logs. KMS keys are HSM-backed by AWS, so the kind is
``kms``; as with every kind, that is a claim in the trust bundle that nothing here attests.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from purpleteam.audit.hardware_signer import KMS, SignerError, SignerUnavailable, signed_message

KEY_REFERENCE = re.compile(r"[A-Za-z0-9:/_.\-]{1,2048}")  # a key id, key ARN, alias name or alias ARN
_ERROR_CODE = re.compile(r"[A-Za-z0-9]{1,64}")
_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


class KmsClient(Protocol):
    """The two KMS calls used, with the names and shapes boto3's KMS client has."""

    def get_public_key(self, *, KeyId: str) -> dict: ...

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict: ...


def _refusal(what: str, error: Exception) -> SignerError:
    response = getattr(error, "response", None)
    detail = response.get("Error") if isinstance(response, dict) else None
    code = detail.get("Code") if isinstance(detail, dict) else None
    label = code if isinstance(code, str) and _ERROR_CODE.fullmatch(code) else type(error).__name__
    return SignerError(f"AWS KMS refused {what} ({label})")


class AwsKmsSigner:
    kind = KMS

    def __init__(self, key: str, client: KmsClient) -> None:
        if not KEY_REFERENCE.fullmatch(key if isinstance(key, str) else ""):
            raise ValueError("a KMS key is named by id, ARN or alias")
        self._reference, self._client = key, client
        try:
            info = client.get_public_key(KeyId=key)
        except Exception as error:  # botocore errors, network errors, a client that is not a KMS client
            raise _refusal("reading the public key", error) from None
        self._arn, self._public = self._pin(info)

    def public_key(self) -> bytes:
        return self._public

    def sign(self, data: bytes, context: bytes) -> bytes:
        digest = hashlib.sha256(signed_message(context, data)).digest()
        try:
            response = self._client.sign(KeyId=self._arn, Message=digest, MessageType="DIGEST",
                                         SigningAlgorithm="ECDSA_SHA_256")
        except Exception as error:
            raise _refusal("signing", error) from None
        if not isinstance(response, dict) or response.get("KeyId") != self._arn:
            raise SignerError("AWS KMS signed with a different key than the one pinned")
        try:
            r, s = decode_dss_signature(response["Signature"])
        except (KeyError, ValueError, TypeError):
            raise SignerError("AWS KMS returned a signature that is not ECDSA") from None
        if not (0 < r < _ORDER and 0 < s < _ORDER):
            raise SignerError("AWS KMS returned an invalid signature")
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def close(self) -> None:
        pass

    @classmethod
    def from_boto3(cls, key: str, *, region: str | None = None, session: Any = None) -> "AwsKmsSigner":
        """A signer using the customer's boto3 (and so their credentials). Raises ``SignerUnavailable`` without it."""
        try:
            import boto3
        except ImportError:
            raise SignerUnavailable("AWS KMS signing needs boto3; install it where this runs (pip install boto3)") from None
        return cls(key, (session or boto3).client("kms", region_name=region))

    @staticmethod
    def _pin(info: Any) -> tuple[str, bytes]:
        if not isinstance(info, dict):
            raise SignerError("AWS KMS returned an unreadable public key")
        spec, usage, algorithms = (info.get("KeySpec") or info.get("CustomerMasterKeySpec"), info.get("KeyUsage"),
                                   info.get("SigningAlgorithms"))
        if (spec != "ECC_NIST_P256" or usage != "SIGN_VERIFY" or not isinstance(algorithms, list)
                or "ECDSA_SHA_256" not in algorithms):
            raise SignerError("the KMS key must be ECC_NIST_P256 for SIGN_VERIFY with ECDSA_SHA_256")
        arn = info.get("KeyId")
        if not isinstance(arn, str) or not KEY_REFERENCE.fullmatch(arn):
            raise SignerError("AWS KMS did not report the key's identity")
        try:
            key = serialization.load_der_public_key(info["PublicKey"])
        except (KeyError, ValueError, TypeError):
            raise SignerError("AWS KMS returned a public key that cannot be read") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise SignerError("the KMS public key is not a P-256 key")
        return arn, key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
