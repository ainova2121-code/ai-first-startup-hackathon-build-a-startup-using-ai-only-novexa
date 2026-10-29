"""Hardware-signed checkpoints: they verify, they name their protection, and none of the ways to strip or fake them work."""

import copy
import platform
import uuid

import pytest

from purpleteam.audit import tpm_windows
from purpleteam.audit.hardware import Probes, detect
from purpleteam.audit.hardware_signer import (
    SignerError, SignerUnavailable, SoftwareP256Signer, key_id, resolve_signer, verify_p256)
from purpleteam.audit.keys import AgentKeyring
from purpleteam.audit.ledger import AuditLedger, LedgerCorrupt
from purpleteam.audit.verify import verify_proof


class ClaimsTpm(SoftwareP256Signer):
    """A software key labelled tpm2: all a trust bundle ever has is this claim, which is why it is called a claim."""

    kind = "tpm2"


def _ledger(tmp_path, signer, name="log.jsonl", events=3):
    ledger = AuditLedger(tmp_path / name, hardware=signer)
    for index in range(events):
        ledger.append("attacker", "attack", {"id": f"a{index}"})
    return ledger


def _bad(ledger, trust, **policy):
    result = ledger.verify(trust, **policy)
    assert not result.ok, "a forged checkpoint was accepted"
    return result


def test_a_hardware_signed_checkpoint_verifies_and_names_its_claimed_protection(tmp_path):
    signer = ClaimsTpm()
    ledger = _ledger(tmp_path, signer)
    trust = ledger.export_trust()
    checkpoint = trust["checkpoint"]
    assert checkpoint["hwkid"] == key_id(signer.public_key()) and len(checkpoint["hwsig"]) == 128
    assert trust["hardware"] == {checkpoint["hwkid"]: {"public": signer.public_key().hex(), "kind": "tpm2"}}
    result = ledger.verify(trust, require_pq=True, require_hardware=True)
    assert result.ok and result.anchored and result.hardware == "tpm2"


def test_a_ledger_without_hardware_works_as_before_and_is_refused_where_hardware_is_required(tmp_path):
    ledger = _ledger(tmp_path, None)
    trust = ledger.export_trust()
    assert "hardware" not in trust and "hwkid" not in trust["checkpoint"]
    result = ledger.verify(trust)
    assert result.ok and result.anchored and result.hardware == ""
    assert "hardware-protected" in _bad(ledger, trust, require_hardware=True).reason


def test_a_software_hardware_key_is_labelled_software_and_does_not_count_as_hardware(tmp_path):
    ledger = _ledger(tmp_path, SoftwareP256Signer())
    trust = ledger.export_trust()
    assert ledger.verify(trust).hardware == "software"
    assert "hardware-protected" in _bad(ledger, trust, require_hardware=True).reason


def _trust(tmp_path):
    ledger = _ledger(tmp_path, ClaimsTpm())
    return ledger, ledger.export_trust()


def test_the_hardware_signature_cannot_be_stripped_to_downgrade_a_checkpoint(tmp_path):
    ledger, trust = _trust(tmp_path)

    def strip(*fields):
        forged = copy.deepcopy(trust)
        for field in fields:
            del forged["checkpoint"][field]
        return forged

    assert "invalid" in _bad(ledger, strip("hwkid", "hwsig")).reason  # the software signatures covered hwkid
    _bad(ledger, strip("hwsig"))
    _bad(ledger, strip("hwkid"))
    without_key = copy.deepcopy(trust)
    del without_key["hardware"]
    _bad(ledger, without_key)


def test_a_forged_or_replayed_hardware_signature_is_rejected(tmp_path):
    ledger, trust = _trust(tmp_path)
    flipped = copy.deepcopy(trust)
    flipped["checkpoint"]["hwsig"] = ("0" if trust["checkpoint"]["hwsig"][0] != "0" else "1") + trust["checkpoint"]["hwsig"][1:]
    _bad(ledger, flipped)

    ledger.append("attacker", "attack", {"id": "later"})
    newer = ledger.export_trust()  # same hardware key, a different checkpoint
    replay = copy.deepcopy(newer)
    replay["checkpoint"]["hwsig"] = trust["checkpoint"]["hwsig"]
    _bad(ledger, replay)
    assert ledger.verify(newer, require_hardware=True).ok


def test_a_different_hardware_key_in_the_bundle_does_not_vouch_for_the_checkpoint(tmp_path):
    ledger, trust = _trust(tmp_path)
    other = ClaimsTpm()
    swapped = copy.deepcopy(trust)
    swapped["hardware"] = {key_id(other.public_key()): {"public": other.public_key().hex(), "kind": "tpm2"}}
    _bad(ledger, swapped)
    reid = copy.deepcopy(trust)
    reid["checkpoint"]["hwkid"] = key_id(other.public_key())
    _bad(ledger, reid)


def test_a_malformed_hardware_section_fails_closed(tmp_path):
    ledger, trust = _trust(tmp_path)
    hwkid = trust["checkpoint"]["hwkid"]
    entry = trust["hardware"][hwkid]
    other = ClaimsTpm().public_key().hex()
    bad_sections = [
        {hwkid: {**entry, "kind": "quantum"}},
        {hwkid: {"public": entry["public"]}},
        {hwkid: {**entry, "extra": 1}},
        {hwkid: {"public": other, "kind": "tpm2"}},        # the id is not the key's id
        {hwkid: {"public": entry["public"][:-2], "kind": "tpm2"}},
        {hwkid: {"public": entry["public"].upper(), "kind": "tpm2"}},
        {"not-a-kid": entry}, {hwkid: "text"}, {hwkid: None}, "text", [entry],
    ]
    for section in bad_sections:
        forged = {**trust, "hardware": section}
        result = ledger.verify(forged)
        assert not result.ok and "malformed" in result.reason, section


def test_a_hardware_key_can_be_revoked(tmp_path):
    ledger, trust = _trust(tmp_path)
    hwkid, size = trust["checkpoint"]["hwkid"], trust["checkpoint"]["size"]
    _bad(ledger, {**trust, "revoked": {hwkid: 0}})
    _bad(ledger, {**trust, "revoked": {hwkid: size - 1}})
    assert ledger.verify({**trust, "revoked": {hwkid: size}}).ok  # revoked only after this checkpoint


def test_inclusion_proofs_honour_the_hardware_requirement(tmp_path):
    ledger, trust = _trust(tmp_path)
    proof = ledger.prove(1)
    assert verify_proof(proof, trust) and verify_proof(proof, trust, require_hardware=True)
    software = _ledger(tmp_path, None, "plain.jsonl")
    plain = software.export_trust()
    assert verify_proof(software.prove(1), plain) and not verify_proof(software.prove(1), plain, require_hardware=True)
    forged = copy.deepcopy(trust)
    forged["checkpoint"]["hwsig"] = "0" * 128
    assert not verify_proof(proof, forged)


class BrokenSigner(ClaimsTpm):
    def sign(self, data, context):
        raise SignerError("the TPM is locked")


class LyingSigner(ClaimsTpm):
    """Signs, but with a different key than the one it advertises."""

    def __init__(self):
        super().__init__()
        self._other = SoftwareP256Signer()

    def sign(self, data, context):
        return self._other.sign(data, context)


def test_a_failing_or_lying_hardware_signer_stops_the_checkpoint_instead_of_downgrading_it(tmp_path):
    with pytest.raises(SignerError, match="locked"):
        _ledger(tmp_path, BrokenSigner()).checkpoint()
    with pytest.raises(SignerError, match="does not verify"):
        _ledger(tmp_path, LyingSigner(), "lying.jsonl").export_trust()


def test_the_ledger_rejects_something_that_is_not_a_hardware_signer(tmp_path):
    class NoKind:
        def public_key(self):
            return b"\x04" * 65

    class ShortKey(ClaimsTpm):
        def public_key(self):
            return b"\x04" * 10

    for bad in (NoKind(), ShortKey(), object()):
        with pytest.raises(ValueError, match="HardwareSigner"):
            AuditLedger(tmp_path / "x.jsonl", hardware=bad)


def test_a_restart_pinned_to_a_hardware_checkpoint_needs_the_hardware_key_to_check_it(tmp_path):
    signer, keyring = ClaimsTpm(), AgentKeyring()  # a restart reuses its keys
    ledger = AuditLedger(tmp_path / "log.jsonl", keyring, hardware=signer)
    for index in range(3):
        ledger.append("attacker", "attack", {"id": f"a{index}"})
    trust = ledger.export_trust()
    path = tmp_path / "log.jsonl"
    assert AuditLedger(path, keyring, hardware=signer, pinned_checkpoint=trust["checkpoint"]).count() == 3
    with pytest.raises(LedgerCorrupt):  # a machine without the key cannot check the hardware half
        AuditLedger(path, keyring, pinned_checkpoint=trust["checkpoint"])
    pinned = AuditLedger(path, keyring, pinned_checkpoint=trust["checkpoint"], pinned_hardware=trust["hardware"])
    assert pinned.count() == 3


def test_a_signer_policy_decides_whether_hardware_is_used_or_required():
    absent = Probes(tbs=lambda: 0x8028400F)
    assert resolve_signer("off", "ledger", probes=absent, system="Windows")[0] is None
    signer, note = resolve_signer("preferred", "ledger", probes=absent, system="Windows")
    assert signer is None and "continuing without hardware" in note and "no hardware root of trust" in note
    with pytest.raises(SignerUnavailable, match="no hardware root of trust"):
        resolve_signer("required", "ledger", probes=absent, system="Windows")
    for bad in ("always", "", None, "OFF"):
        with pytest.raises(ValueError, match="policy"):
            resolve_signer(bad, "ledger")


needs_tpm = pytest.mark.skipif(
    platform.system() != "Windows" or not (detect().kind == "tpm2" and detect().reachable),
    reason="needs a reachable Windows TPM 2.0")


@pytest.fixture
def tpm_name():
    name = "ledger-test-" + uuid.uuid4().hex[:10]
    yield name
    try:
        tpm_windows.WindowsTpmSigner(name, create=False).delete()
    except SignerUnavailable:
        pass


@needs_tpm
def test_a_ledger_signed_by_the_real_tpm_verifies_anywhere_with_only_public_data(tmp_path, tpm_name):
    with tpm_windows.WindowsTpmSigner(tpm_name) as signer:
        ledger = _ledger(tmp_path, signer)
        trust = ledger.export_trust()
    assert trust["hardware"][trust["checkpoint"]["hwkid"]]["kind"] == "tpm2"
    fresh = AuditLedger(tmp_path / "log.jsonl")  # a machine with no TPM and no private keys
    result = fresh.verify(trust, require_pq=True, require_hardware=True)
    assert result.ok and result.anchored and result.hardware == "tpm2"
    public = bytes.fromhex(trust["hardware"][trust["checkpoint"]["hwkid"]]["public"])
    assert verify_p256(public, b"purpleteam.audit.checkpoint.hw.v1", b"x", bytes(64)) is False


@needs_tpm
def test_the_policy_opens_the_real_tpm_when_it_is_preferred_or_required(tmp_path, tpm_name):
    for policy in ("preferred", "required"):
        signer, note = resolve_signer(policy, tpm_name)
        try:
            assert signer is not None and signer.kind == "tpm2" and "tpm2" in note
        finally:
            if signer:
                signer.close()


def test_the_live_console_can_sign_with_a_software_key_on_a_host_with_no_tpm(tmp_path):
    """PURPLETEAM_HARDWARE_SIGNING=software gives a free host a real, verifiable checkpoint co-signature, labelled
    software and never a TPM. off means none; an unknown policy is refused."""
    from purpleteam.live_run import resolve_hardware

    signer, note = resolve_hardware("software")
    assert signer is not None and signer.kind == "software" and "software" in note
    ledger = _ledger(tmp_path, signer, name="soft.jsonl")
    trust = ledger.export_trust()
    assert trust["hardware"][trust["checkpoint"]["hwkid"]]["kind"] == "software"  # the truth, not "tpm2"
    assert ledger.verify(trust).ok  # the signature is genuine and verifies
    assert not ledger.verify(trust, require_hardware=True).ok  # but software never counts as hardware

    assert resolve_hardware("off") == (None, "hardware signing is off")
    with pytest.raises(ValueError):
        resolve_hardware("make-believe")
