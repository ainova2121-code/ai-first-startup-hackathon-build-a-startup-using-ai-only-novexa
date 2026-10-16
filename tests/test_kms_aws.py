"""AWS KMS signing, against a fake KMS that behaves like the service (pre-hashed ECDSA, DER signatures, botocore-shaped errors)."""

import hashlib
import sys
import threading
import types

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

from purpleteam.audit.hardware_signer import (
    HARDWARE_KINDS, KMS, PROTECTIONS, SOFTWARE, SignerError, SignerUnavailable, resolve_signer, signed_message,
    verify_p256)
from purpleteam.audit.kms_aws import AwsKmsSigner
from purpleteam.audit.ledger import AuditLedger

ARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
DATA, CONTEXT = b"merkle root and size", b"checkpoint"
SPKI = {"encoding": serialization.Encoding.DER, "format": serialization.PublicFormat.SubjectPublicKeyInfo}
ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


class ClientError(Exception):
    """The shape of botocore's ClientError: the AWS error code is in .response."""

    def __init__(self, code, message="arn:aws:kms:eu-west-1:111122223333:key/secret request-id 9f8e"):
        super().__init__(f"An error occurred ({code}): {message}")
        self.response = {"Error": {"Code": code, "Message": message}}


class FakeKms:
    def __init__(self, **overrides):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.info = {"KeyId": ARN, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY",
                     "SigningAlgorithms": ["ECDSA_SHA_256"], "PublicKey": self.key.public_key().public_bytes(**SPKI)}
        self.info.update(overrides.pop("info", {}))
        self.overrides, self.calls = overrides, []

    def get_public_key(self, *, KeyId):
        self.calls.append(("get_public_key", KeyId))
        if "get_error" in self.overrides:
            raise self.overrides["get_error"]
        return self.info

    def sign(self, *, KeyId, Message, MessageType, SigningAlgorithm):
        self.calls.append(("sign", KeyId, Message, MessageType, SigningAlgorithm))
        if "sign_error" in self.overrides:
            raise self.overrides["sign_error"]
        assert MessageType == "DIGEST" and SigningAlgorithm == "ECDSA_SHA_256" and len(Message) == 32
        signature = (self.overrides["signature"] if "signature" in self.overrides
                     else self.key.sign(Message, ec.ECDSA(Prehashed(hashes.SHA256()))))
        return {"KeyId": self.overrides.get("signed_by", ARN), "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


def test_signs_with_a_digest_and_the_signature_verifies_anywhere():
    client = FakeKms()
    signer = AwsKmsSigner(ARN, client)
    signature = signer.sign(DATA, CONTEXT)
    assert signer.kind == KMS and len(signature) == 64 and verify_p256(signer.public_key(), CONTEXT, DATA, signature)
    assert not verify_p256(signer.public_key(), b"event", DATA, signature)
    _, key, digest, message_type, algorithm = client.calls[-1]
    assert digest == hashlib.sha256(signed_message(CONTEXT, DATA)).digest() and (message_type, algorithm) == ("DIGEST", "ECDSA_SHA_256")


def test_an_alias_is_resolved_once_and_signing_uses_the_real_key():
    client = FakeKms()
    signer = AwsKmsSigner("alias/purpleteam-ledger", client)
    signer.sign(DATA, CONTEXT)
    assert client.calls[0] == ("get_public_key", "alias/purpleteam-ledger") and client.calls[1][1] == ARN


def test_an_alias_repointed_to_another_key_cannot_sign_in_the_pinned_keys_name():
    signer = AwsKmsSigner("alias/purpleteam-ledger", FakeKms(signed_by=ARN.replace("1234abcd", "ffffffff")))
    with pytest.raises(SignerError, match="different key"):
        signer.sign(DATA, CONTEXT)


def test_only_a_p256_signing_key_is_accepted():
    p384 = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(**SPKI)
    rsa_key = rsa.generate_private_key(65537, 2048).public_key().public_bytes(**SPKI)
    for info in ({"KeySpec": "RSA_2048"}, {"KeySpec": "ECC_NIST_P384"}, {"KeyUsage": "KEY_AGREEMENT"},
                 {"SigningAlgorithms": []}, {"SigningAlgorithms": "ECDSA_SHA_256"}, {"SigningAlgorithms": None},
                 {"PublicKey": p384}, {"PublicKey": rsa_key}, {"PublicKey": b"not der"}, {"PublicKey": None},
                 {"KeyId": None}, {"KeyId": "has spaces"}):
        with pytest.raises(SignerError):
            AwsKmsSigner(ARN, FakeKms(info=info))
    for junk in (None, [], "text"):
        client = FakeKms()
        client.get_public_key = lambda KeyId, value=junk: value
        with pytest.raises(SignerError):
            AwsKmsSigner(ARN, client)
    old_name = FakeKms(info={"CustomerMasterKeySpec": "ECC_NIST_P256", "KeySpec": None})
    assert AwsKmsSigner(ARN, old_name).public_key()[0] == 4  # older API field name


def test_key_references_are_validated():
    for bad in ("", "has space", "line\nbreak", "x" * 2049, None, 5, "semi;colon", "arn:aws:kms:..\\x"):
        with pytest.raises(ValueError, match="KMS key"):
            AwsKmsSigner(bad, FakeKms())
    assert AwsKmsSigner("alias/ledger-1", FakeKms())


def test_errors_carry_aws_error_code_and_never_arns_or_request_ids():
    for code in ("AccessDeniedException", "ThrottlingException", "DisabledException"):
        with pytest.raises(SignerError) as error:
            AwsKmsSigner(ARN, FakeKms(get_error=ClientError(code)))
        assert code in str(error.value) and "arn:" not in str(error.value) and "9f8e" not in str(error.value)
    signer = AwsKmsSigner(ARN, FakeKms(sign_error=ClientError("KMSInternalException")))
    with pytest.raises(SignerError, match="KMSInternalException") as error:
        signer.sign(DATA, CONTEXT)
    assert "111122223333" not in str(error.value) and error.value.__cause__ is None
    for odd in (ConnectionError("host db.internal refused"), ClientError("bad code!<script>"), RuntimeError("x")):
        with pytest.raises(SignerError) as error:
            AwsKmsSigner(ARN, FakeKms(sign_error=odd)).sign(DATA, CONTEXT)
        assert "db.internal" not in str(error.value) and "<script>" not in str(error.value)


def test_a_malformed_signature_is_refused():
    good = FakeKms()
    for signature in (b"", b"\x00" * 64, b"not der", encode_dss_signature(0, 5), encode_dss_signature(5, 0),
                      encode_dss_signature(ORDER, 5), encode_dss_signature(5, ORDER + 1), None, 7):
        signer = AwsKmsSigner(ARN, good)
        good.overrides["signature"] = signature
        with pytest.raises(SignerError):
            signer.sign(DATA, CONTEXT)
    broken = FakeKms()
    broken.sign = lambda **kw: {"KeyId": ARN}
    with pytest.raises(SignerError, match="not ECDSA"):
        AwsKmsSigner(ARN, broken).sign(DATA, CONTEXT)
    broken.sign = lambda **kw: "text"
    with pytest.raises(SignerError, match="different key"):
        AwsKmsSigner(ARN, broken).sign(DATA, CONTEXT)


def test_signing_is_safe_from_several_threads():
    signer = AwsKmsSigner(ARN, FakeKms())
    results = []

    def work(i):
        message = f"message {i}".encode()
        results.append(verify_p256(signer.public_key(), CONTEXT, message, signer.sign(message, CONTEXT)))

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results == [True] * 8


def test_a_ledger_signed_through_kms_verifies_and_counts_as_hardware(tmp_path):
    signer = AwsKmsSigner(ARN, FakeKms())
    ledger = AuditLedger(tmp_path / "log.jsonl", hardware=signer)
    for index in range(3):
        ledger.append("attacker", "attack", {"id": f"a{index}"})
    trust = ledger.export_trust()
    assert trust["hardware"][trust["checkpoint"]["hwkid"]]["kind"] == "kms"
    result = ledger.verify(trust, require_pq=True, require_hardware=True)
    assert result.ok and result.anchored and result.hardware == "kms"


def test_every_hardware_kind_counts_and_software_never_does():
    assert set(HARDWARE_KINDS) == {"tpm2", "secure_enclave", "hsm", "kms"} and SOFTWARE not in HARDWARE_KINDS
    assert set(PROTECTIONS) == set(HARDWARE_KINDS) | {SOFTWARE}


def test_boto3_is_optional_and_used_when_present(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)  # an import of None raises ImportError, as if not installed
    with pytest.raises(SignerUnavailable, match="boto3"):
        AwsKmsSigner.from_boto3(ARN)

    made = {}

    class Session:
        def client(self, service, region_name=None):
            made["client"] = (service, region_name)
            return FakeKms()

    fake = types.SimpleNamespace(client=Session().client)
    monkeypatch.setitem(sys.modules, "boto3", fake)
    assert AwsKmsSigner.from_boto3(ARN, region="eu-west-1").kind == KMS and made["client"] == ("kms", "eu-west-1")
    assert AwsKmsSigner.from_boto3(ARN, session=Session()).kind == KMS


def test_the_policy_treats_a_missing_library_as_unavailable_but_a_refusal_as_an_error(monkeypatch):
    def missing():
        raise SignerUnavailable("AWS KMS signing needs boto3")

    def denied():
        raise SignerError("AWS KMS refused reading the public key (AccessDeniedException)")

    assert resolve_signer("off", "x", opener=denied)[0] is None
    signer, note = resolve_signer("preferred", "x", opener=missing)
    assert signer is None and "continuing without hardware" in note and "boto3" in note
    with pytest.raises(SignerUnavailable):
        resolve_signer("required", "x", opener=missing)
    for policy in ("preferred", "required"):  # a configured key that AWS refuses is a fault, never a quiet downgrade
        with pytest.raises(SignerError, match="AccessDenied"):
            resolve_signer(policy, "x", opener=denied)
    signer, note = resolve_signer("required", "x", opener=lambda: AwsKmsSigner(ARN, FakeKms()))
    assert signer.kind == KMS and "kms" in note
