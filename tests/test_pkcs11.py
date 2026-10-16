"""PKCS#11 signing: parsing and validation anywhere; the real driver against a SoftHSM2 token where one is installed.

SoftHSM2 (``apt install softhsm2``) is a software emulator of an HSM, so these tests prove the driver speaks the
standard to a real module, and that it reports such a token as ``software``, never as hardware.
"""

import platform
import shutil
import subprocess
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr

from purpleteam.audit import pkcs11
from purpleteam.audit.hardware_signer import SOFTWARE, SignerError, SignerUnavailable, verify_p256
from purpleteam.audit.pkcs11 import Pkcs11Signer, parse_ec_point

DATA, CONTEXT = b"merkle root and size", b"checkpoint"
PIN, SO_PIN, TOKEN = SecretStr("87654321"), "12345678", "purpleteam-test"
POINT = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def test_a_point_is_read_from_the_standard_der_wrapping_or_bare():
    assert parse_ec_point(b"\x04\x41" + POINT) == POINT and parse_ec_point(POINT) == POINT


def test_anything_that_is_not_a_p256_point_is_refused():
    for bad in (b"", POINT[:-1], POINT + b"\x00", b"\x02" + POINT[1:33], b"\x04" + bytes(64),
                b"\x04" + (1).to_bytes(32, "big") + (1).to_bytes(32, "big"), b"\x04\x41" + POINT[:-1], b"\x04\x40" + POINT):
        with pytest.raises(SignerError):
            parse_ec_point(bad)


def test_the_driver_refuses_windows_and_bad_input_before_touching_any_module(monkeypatch, tmp_path):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    with pytest.raises(SignerUnavailable, match="Linux and macOS"):
        Pkcs11Signer("module.so", TOKEN, "ledger", PIN)
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    for key in ("", "has space", "x" * 65, "semi;colon", None):
        with pytest.raises(ValueError, match="label"):
            Pkcs11Signer("module.so", TOKEN, key, PIN)
    for token in ("", "x" * 33, None, 5):
        with pytest.raises(ValueError, match="label"):
            Pkcs11Signer("module.so", token, "ledger", PIN)
    with pytest.raises(SignerUnavailable, match="not found"):
        Pkcs11Signer(tmp_path / "missing.so", TOKEN, "ledger", PIN)
    (tmp_path / "text.so").write_text("this is not a shared library")
    with pytest.raises(SignerUnavailable, match="not a usable PKCS#11 module"):
        Pkcs11Signer(tmp_path / "text.so", TOKEN, "ledger", PIN)


def test_errors_name_the_result_code_and_never_the_pin():
    for code, name in ((0xA0, "CKR_PIN_INCORRECT"), (0xA4, "CKR_PIN_LOCKED"), (0xE0, "CKR_TOKEN_NOT_PRESENT"),
                       (0x12345, "CKR 0x12345")):
        message = str(pkcs11._fail("the PIN", code))
        assert name in message and "87654321" not in message


LIVE = platform.system() in ("Linux", "Darwin") and shutil.which("softhsm2-util") is not None
MODULES = ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
           "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so", "/opt/homebrew/lib/softhsm/libsofthsm2.so",
           "/usr/local/lib/softhsm/libsofthsm2.so")
MODULE = next((m for m in MODULES if Path(m).is_file()), None)
needs_softhsm = pytest.mark.skipif(not (LIVE and MODULE), reason="needs SoftHSM2 (apt install softhsm2)")


def _run(*args, env):
    done = subprocess.run(args, capture_output=True, text=True, env=env)
    assert done.returncode == 0, f"{args[0]} failed: {done.stderr[-300:]}"


@pytest.fixture(scope="module")
def token(tmp_path_factory):
    """A fresh SoftHSM2 token in a private directory, selected through SOFTHSM2_CONF for this module only."""
    root = tmp_path_factory.mktemp("softhsm")
    (root / "tokens").mkdir()
    conf = root / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {root / 'tokens'}\nobjectstore.backend = file\nlog.level = ERROR\n")
    patch = pytest.MonkeyPatch()
    patch.setenv("SOFTHSM2_CONF", str(conf))
    import os
    _run("softhsm2-util", "--init-token", "--free", "--label", TOKEN, "--so-pin", SO_PIN, "--pin",
         PIN.get_secret_value(), env=dict(os.environ))
    yield root
    patch.undo()


@needs_softhsm
def test_a_real_module_generates_a_key_and_signs_with_it(token):
    with Pkcs11Signer.generate_key(MODULE, TOKEN, "ledger-a", PIN) as signer:
        assert signer.kind == SOFTWARE  # SoftHSM is an emulator, so it is never labelled hardware
        assert signer.token["manufacturer"].lower().startswith("softhsm")
        signature = signer.sign(DATA, CONTEXT)
        assert len(signature) == 64 and verify_p256(signer.public_key(), CONTEXT, DATA, signature)
        assert not verify_p256(signer.public_key(), b"event", DATA, signature)


@needs_softhsm
def test_the_key_persists_on_the_token_and_reopens_by_label(token):
    with Pkcs11Signer.generate_key(MODULE, TOKEN, "ledger-b", PIN) as first:
        public = first.public_key()
    with Pkcs11Signer(MODULE, TOKEN, "ledger-b", PIN) as again:
        assert again.public_key() == public and verify_p256(public, CONTEXT, DATA, again.sign(DATA, CONTEXT))


@needs_softhsm
def test_a_wrong_pin_is_refused_once_and_does_not_reveal_it(token):
    with pytest.raises(SignerError, match="CKR_PIN_INCORRECT") as error:
        Pkcs11Signer(MODULE, TOKEN, "ledger-a", SecretStr("00000000"))
    assert "00000000" not in str(error.value)
    with Pkcs11Signer(MODULE, TOKEN, "ledger-a", PIN):  # a correct login afterwards still works
        pass


@needs_softhsm
def test_unknown_tokens_and_keys_are_reported_as_unavailable(token):
    with pytest.raises(SignerUnavailable, match="no PKCS#11 token"):
        Pkcs11Signer(MODULE, "no-such-token", "ledger-a", PIN)
    with pytest.raises(SignerUnavailable, match="no P-256 key"):
        Pkcs11Signer(MODULE, TOKEN, "no-such-key", PIN)


@needs_softhsm
def test_a_key_label_that_is_not_unique_is_refused(token):
    Pkcs11Signer.generate_key(MODULE, TOKEN, "ledger-dup", PIN).close()
    with pytest.raises(SignerUnavailable, match="more than one key"):
        Pkcs11Signer.generate_key(MODULE, TOKEN, "ledger-dup", PIN)


def _weak_key(label, *, extractable, sensitive):
    """A P-256 key created on the token with the given protection flags (the driver's own helper never makes weak ones)."""
    from ctypes import byref, c_ulong

    from purpleteam.audit import pkcs11_abi as abi

    device = Pkcs11Signer._provisioner(MODULE, TOKEN, PIN)
    try:
        text = label.encode()
        public, keep_public = pkcs11._template([(abi.CKA_TOKEN, b"\x01"), (abi.CKA_LABEL, text), (abi.CKA_VERIFY, b"\x01"),
                                                (abi.CKA_EC_PARAMS, abi.P256_PARAMS[0])])
        private, keep_private = pkcs11._template([
            (abi.CKA_TOKEN, b"\x01"), (abi.CKA_PRIVATE, b"\x01"), (abi.CKA_LABEL, text), (abi.CKA_SIGN, b"\x01"),
            (abi.CKA_SENSITIVE, b"\x01" if sensitive else b"\x00"), (abi.CKA_EXTRACTABLE, b"\x01" if extractable else b"\x00")])
        mechanism, handles = abi.Mechanism(abi.CKM_EC_KEY_PAIR_GEN, None, 0), (c_ulong(), c_ulong())
        device._check(device._calls["C_GenerateKeyPair"](
            device._session, byref(mechanism), public, len(public), private, len(private), byref(handles[0]),
            byref(handles[1])), "generating a weak key")
    finally:
        device.close()


@needs_softhsm
@pytest.mark.parametrize("extractable,sensitive", [(True, True), (False, False), (True, False)],
                         ids=["extractable", "not-sensitive", "both"])
def test_a_key_that_can_be_extracted_is_refused(token, extractable, sensitive):
    label = f"weak-{int(extractable)}{int(sensitive)}"
    _weak_key(label, extractable=extractable, sensitive=sensitive)
    with pytest.raises(SignerError, match="extracted"):
        Pkcs11Signer(MODULE, TOKEN, label, PIN)


@needs_softhsm
def test_a_second_signer_cannot_bypass_the_pin_by_riding_the_first_ones_login(token):
    with Pkcs11Signer(MODULE, TOKEN, "ledger-a", PIN):
        with pytest.raises(SignerError, match="does not match") as error:
            Pkcs11Signer(MODULE, TOKEN, "ledger-b", SecretStr("00000000"))
        assert "00000000" not in str(error.value)
        with Pkcs11Signer(MODULE, TOKEN, "ledger-b", PIN) as second:  # the same PIN is fine
            assert second.sign(DATA, CONTEXT)


@needs_softhsm
def test_the_last_signer_to_close_logs_the_token_out(token):
    first = Pkcs11Signer(MODULE, TOKEN, "ledger-a", PIN)
    second = Pkcs11Signer(MODULE, TOKEN, "ledger-b", PIN)
    first.close()
    assert second.sign(DATA, CONTEXT)  # still logged in: only the last one out logs out
    second.close()
    with pytest.raises(SignerError, match="CKR_PIN_INCORRECT"):  # logged out, so the PIN is checked afresh
        Pkcs11Signer(MODULE, TOKEN, "ledger-a", SecretStr("00000000"))


@needs_softhsm
def test_closing_one_signer_does_not_shut_the_module_under_another(token):
    first = Pkcs11Signer(MODULE, TOKEN, "ledger-a", PIN)
    second = Pkcs11Signer(MODULE, TOKEN, "ledger-b", PIN)
    first.close()
    first.close()  # harmless twice
    assert verify_p256(second.public_key(), CONTEXT, DATA, second.sign(DATA, CONTEXT))
    second.close()
    with pytest.raises(SignerError, match="closed"):
        second.sign(DATA, CONTEXT)
    with Pkcs11Signer(MODULE, TOKEN, "ledger-a", PIN) as reopened:  # the module can be started again afterwards
        assert reopened.sign(DATA, CONTEXT)


@needs_softhsm
def test_signing_is_safe_from_several_threads(token):
    with Pkcs11Signer(MODULE, TOKEN, "ledger-a", PIN) as signer:
        results = []

        def work(i):
            message = f"message {i}".encode()
            results.append(verify_p256(signer.public_key(), CONTEXT, message, signer.sign(message, CONTEXT)))

        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
    assert results == [True] * 8


@needs_softhsm
def test_a_ledger_signed_through_pkcs11_verifies_but_a_software_token_is_not_hardware(token, tmp_path):
    from purpleteam.audit.ledger import AuditLedger

    with Pkcs11Signer(MODULE, TOKEN, "ledger-a", PIN) as signer:
        ledger = AuditLedger(tmp_path / "log.jsonl", hardware=signer)
        for index in range(3):
            ledger.append("attacker", "attack", {"id": f"a{index}"})
        trust = ledger.export_trust()
    assert trust["hardware"][trust["checkpoint"]["hwkid"]]["kind"] == SOFTWARE
    result = ledger.verify(trust)
    assert result.ok and result.anchored and result.hardware == SOFTWARE
    assert not ledger.verify(trust, require_hardware=True).ok  # an emulator never satisfies "hardware required"
