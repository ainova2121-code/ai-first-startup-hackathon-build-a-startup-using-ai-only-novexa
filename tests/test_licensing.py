"""Signed license entitlements: issued by the vendor's private key, verified offline with only
the public half — no phone-home, so BYOC holds even for licensing."""

import pytest

from purpleteam.audit.keys import AgentKeyring
from purpleteam.licensing import entitled, issue, verify


@pytest.fixture
def vendor_keyring():
    return AgentKeyring()  # ephemeral, hybrid (Ed25519 + ML-DSA) by default


def test_a_freshly_issued_license_verifies_and_carries_its_features(vendor_keyring):
    license = issue(vendor_keyring, "acme-corp", "enterprise", ["blast_radius", "trend"])
    result = verify(license, vendor_keyring.public_keys())
    assert result.ok and not result.expired
    assert result.customer == "acme-corp" and result.edition == "enterprise"
    assert result.features == {"blast_radius", "trend"}


def test_entitled_checks_one_feature_at_a_time(vendor_keyring):
    license = issue(vendor_keyring, "acme-corp", "pro", ["trend"])
    public_keys = vendor_keyring.public_keys()
    assert entitled(license, public_keys, "trend")
    assert not entitled(license, public_keys, "blast_radius")


def test_a_tampered_license_fails_signature_verification(vendor_keyring):
    license = issue(vendor_keyring, "acme-corp", "starter", ["trend"])
    tampered = {**license, "edition": "enterprise"}  # trying to upgrade without the vendor's signature
    result = verify(tampered, vendor_keyring.public_keys())
    assert not result.ok and result.reason == "signature does not verify"


def test_an_expired_license_is_reported_distinctly_from_a_tampered_one(vendor_keyring):
    license = issue(vendor_keyring, "acme-corp", "pro", ["trend"], expires_at=1000.0)
    result = verify(license, vendor_keyring.public_keys(), now=2000.0)
    assert not result.ok and result.expired and result.reason == "license expired"


def test_a_license_signed_by_an_unpinned_key_is_rejected(vendor_keyring):
    license = issue(vendor_keyring, "acme-corp", "pro", ["trend"])
    other_vendor = AgentKeyring()  # a different vendor keyring entirely
    result = verify(license, other_vendor.public_keys())
    assert not result.ok and result.reason == "unknown signing key"


@pytest.mark.parametrize("broken", [
    {"customer": 123},  # wrong type
    {"features": "trend"},  # not a list
    {"extra_field": "x"},  # schema must be exact
])
def test_malformed_license_input_is_rejected_not_raised(vendor_keyring, broken):
    license = {**issue(vendor_keyring, "acme-corp", "pro", ["trend"]), **broken}
    result = verify(license, vendor_keyring.public_keys())
    assert not result.ok and result.reason == "malformed license"


def test_require_pq_rejects_a_classical_only_license():
    classical_vendor = AgentKeyring(pq=False)
    license = issue(classical_vendor, "acme-corp", "pro", ["trend"])
    assert "pqsig" not in license
    result = verify(license, classical_vendor.public_keys(), require_pq=True)
    assert not result.ok and result.reason == "post-quantum signature required but missing"


def test_a_hybrid_license_satisfies_require_pq(vendor_keyring):
    license = issue(vendor_keyring, "acme-corp", "pro", ["trend"])
    assert "pqsig" in license
    result = verify(license, vendor_keyring.public_keys(), require_pq=True)
    assert result.ok


def test_issue_rejects_invalid_names(vendor_keyring):
    with pytest.raises(ValueError):
        issue(vendor_keyring, "acme corp!", "pro", [])
    with pytest.raises(ValueError):
        issue(vendor_keyring, "acme-corp", "pro", ["ok", "not a valid feature name!"])
