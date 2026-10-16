"""Signed release provenance: a build artifact's digest is signed by the vendor's key and verified
offline, the same way a license is — so a tampered download or a compromised mirror is detectable."""

import pytest

from purpleteam.audit.keys import AgentKeyring
from purpleteam.provenance import digest_file, sign_release, verify_release


@pytest.fixture
def vendor_keyring():
    return AgentKeyring()  # ephemeral, hybrid (Ed25519 + ML-DSA) by default


@pytest.fixture
def artifact(tmp_path):
    path = tmp_path / "purpleteam-1.2.0.whl"
    path.write_bytes(b"pretend wheel contents")
    return path


def test_digest_file_matches_a_direct_sha256_of_the_bytes(artifact):
    import hashlib

    assert digest_file(artifact) == hashlib.sha256(artifact.read_bytes()).hexdigest()


def test_a_freshly_signed_release_verifies_against_the_real_artifact(vendor_keyring, artifact):
    statement = sign_release(vendor_keyring, artifact.name, "1.2.0", "a1b2c3d", digest_file(artifact))
    result = verify_release(statement, vendor_keyring.public_keys(), artifact_path=artifact)
    assert result.ok and result.version == "1.2.0" and result.revision == "a1b2c3d"


def test_verifying_without_the_artifact_only_checks_the_statement_itself(vendor_keyring, artifact):
    statement = sign_release(vendor_keyring, artifact.name, "1.2.0", "a1b2c3d", digest_file(artifact))
    result = verify_release(statement, vendor_keyring.public_keys())
    assert result.ok  # the signature is genuine; nothing here claimed to check a specific file


def test_a_modified_artifact_fails_verification_even_with_a_genuine_signature(vendor_keyring, artifact):
    statement = sign_release(vendor_keyring, artifact.name, "1.2.0", "a1b2c3d", digest_file(artifact))
    artifact.write_bytes(b"a backdoored wheel, same name, different bytes")
    result = verify_release(statement, vendor_keyring.public_keys(), artifact_path=artifact)
    assert not result.ok and result.reason == "artifact digest does not match the signed statement"


def test_a_known_digest_can_be_compared_without_reading_a_local_file(vendor_keyring, artifact):
    digest = digest_file(artifact)
    statement = sign_release(vendor_keyring, artifact.name, "1.2.0", "a1b2c3d", digest)
    assert verify_release(statement, vendor_keyring.public_keys(), artifact_digest=digest).ok
    assert not verify_release(statement, vendor_keyring.public_keys(), artifact_digest="0" * 64).ok


def test_a_tampered_statement_fails_signature_verification(vendor_keyring, artifact):
    statement = sign_release(vendor_keyring, artifact.name, "1.2.0", "a1b2c3d", digest_file(artifact))
    tampered = {**statement, "version": "9.9.9"}  # claiming a different version without a new signature
    result = verify_release(tampered, vendor_keyring.public_keys())
    assert not result.ok and result.reason == "signature does not verify"


def test_a_statement_signed_by_an_unpinned_key_is_rejected(vendor_keyring, artifact):
    statement = sign_release(vendor_keyring, artifact.name, "1.2.0", "a1b2c3d", digest_file(artifact))
    other_vendor = AgentKeyring()
    result = verify_release(statement, other_vendor.public_keys())
    assert not result.ok and result.reason == "unknown signing key"


@pytest.mark.parametrize("broken", [
    {"version": 9},         # wrong type
    {"digest": "not-hex"},  # not a sha256 hex digest
    {"extra_field": "x"},   # schema must be exact
])
def test_malformed_statement_input_is_rejected_not_raised(vendor_keyring, artifact, broken):
    statement = {**sign_release(vendor_keyring, artifact.name, "1.2.0", "a1b2c3d", digest_file(artifact)), **broken}
    result = verify_release(statement, vendor_keyring.public_keys())
    assert not result.ok and result.reason == "malformed release statement"


def test_require_pq_rejects_a_classical_only_statement(artifact):
    classical_vendor = AgentKeyring(pq=False)
    statement = sign_release(classical_vendor, artifact.name, "1.2.0", "a1b2c3d", digest_file(artifact))
    assert "pqsig" not in statement
    result = verify_release(statement, classical_vendor.public_keys(), require_pq=True)
    assert not result.ok and result.reason == "post-quantum signature required but missing"


def test_sign_release_rejects_an_invalid_digest(vendor_keyring, artifact):
    with pytest.raises(ValueError):
        sign_release(vendor_keyring, artifact.name, "1.2.0", "a1b2c3d", "not-a-sha256-digest")
