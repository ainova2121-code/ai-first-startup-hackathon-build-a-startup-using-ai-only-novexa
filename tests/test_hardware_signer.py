"""Hardware signers: the interface and verifier (any machine), the Windows driver's control flow (faked), and the real TPM."""

import ctypes
import platform
import threading
import uuid

import pytest

from purpleteam.audit import tpm_windows
from purpleteam.audit.hardware import Probes, detect
from purpleteam.audit.hardware_signer import (
    SOFTWARE, SignerError, SignerUnavailable, SoftwareP256Signer, key_id, open_signer, signed_message, verify_p256)

DATA, CONTEXT = b"merkle root and size", b"checkpoint"


def test_a_signature_verifies_only_for_its_key_context_and_data():
    signer = SoftwareP256Signer()
    signature = signer.sign(DATA, CONTEXT)
    assert len(signature) == 64 and verify_p256(signer.public_key(), CONTEXT, DATA, signature)
    assert not verify_p256(signer.public_key(), b"event", DATA, signature)       # a checkpoint cannot pass for an event
    assert not verify_p256(signer.public_key(), CONTEXT, DATA + b"x", signature)
    assert not verify_p256(SoftwareP256Signer().public_key(), CONTEXT, DATA, signature)
    assert not verify_p256(signer.public_key(), CONTEXT, DATA, bytes([signature[0] ^ 1]) + signature[1:])


def test_the_signed_message_is_unambiguous():
    assert signed_message(b"ab", b"c") != signed_message(b"a", b"bc")
    assert signed_message(b"", b"") != signed_message(b"", b"\x00")
    with pytest.raises(ValueError, match="65535"):
        signed_message(b"c" * 65536, b"")


def test_the_verifier_never_raises_on_garbage():
    good = SoftwareP256Signer()
    signature = good.sign(DATA, CONTEXT)
    order = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    bad_points = [b"", b"\x04" * 65, b"\x00" * 65, b"\x02" + b"\x01" * 64, good.public_key()[:-1], good.public_key() + b"\x00",
                  b"\x04" + (1).to_bytes(32, "big") + (1).to_bytes(32, "big")]  # (1, 1) is not on the curve
    for point in bad_points:
        assert verify_p256(point, CONTEXT, DATA, signature) is False
    for bad in (b"", b"\x00" * 64, b"\xff" * 64, signature[:-1], signature + b"\x00",
                (order).to_bytes(32, "big") + signature[32:], signature[:32] + (order + 1).to_bytes(32, "big")):
        assert verify_p256(good.public_key(), CONTEXT, DATA, bad) is False
    for junk in (None, 5, "text", [1]):
        assert verify_p256(junk, CONTEXT, DATA, signature) is False
        assert verify_p256(good.public_key(), CONTEXT, DATA, junk) is False


def test_the_software_signer_is_labelled_and_keys_have_stable_ids():
    first, second = SoftwareP256Signer(), SoftwareP256Signer()
    assert first.kind == SOFTWARE and first.public_key() != second.public_key()
    assert key_id(first.public_key()) == key_id(first.public_key()) != key_id(second.public_key())


def _refusal(probes, system):
    with pytest.raises(SignerUnavailable) as error:
        open_signer("ledger", probes=probes, system=system)
    return str(error.value)


def test_a_missing_or_unreachable_tpm_is_refused_with_the_reason_and_never_replaced_by_software(tmp_path):
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/version").write_text("Linux")
    assert "no hardware root of trust" in _refusal(Probes(root=tmp_path), "Linux")
    assert "no hardware root of trust" in _refusal(Probes(tbs=lambda: 0x8028400F), "Windows")
    assert "could not tell" in _refusal(Probes(tbs=lambda: 0x80284001), "Windows")
    assert "Secure Enclave" in _refusal(Probes(run=lambda args: "1\n"), "Darwin")
    sysfs = tmp_path / "sys/class/tpm/tpm0"
    sysfs.mkdir(parents=True)
    (sysfs / "tpm_version_major").write_text("2")
    assert "cannot open it" in _refusal(Probes(root=tmp_path, access=lambda p: False), "Linux")
    (tmp_path / "dev").mkdir()
    (tmp_path / "dev/tpmrm0").write_text("")
    assert "not built yet" in _refusal(Probes(root=tmp_path, access=lambda p: True), "Linux")


def test_key_names_are_validated():
    for bad in ("", "../escape", "a b", "x" * 65, "semi;colon", None):
        with pytest.raises(ValueError, match="key name"):
            open_signer(bad)
        with pytest.raises(ValueError, match="key name"):
            tpm_windows.WindowsTpmSigner(bad)


class FakeLib:
    """Stands in for the Windows crypto API, so the driver's control flow runs on any machine."""

    def __init__(self, **status):
        self.status, self.freed, self.deleted = status, [], False
        self.blob = (0x31534345).to_bytes(4, "little") + (32).to_bytes(4, "little") + bytes(range(64))
        self.signature = bytes(range(64))

    def NCryptOpenStorageProvider(self, ref, name, flags):
        if self.status.get("provider"):
            return self.status["provider"]
        ref._obj.value = 11
        return 0

    def NCryptOpenKey(self, provider, ref, name, spec, flags):
        if not self.status.get("open"):
            ref._obj.value = 22
        return self.status.get("open", 0)

    def NCryptCreatePersistedKey(self, provider, ref, algorithm, name, spec, flags):
        ref._obj.value = 33
        return self.status.get("create", 0)

    def NCryptFinalizeKey(self, key, flags):
        return self.status.get("finalize", 0)

    def NCryptExportKey(self, key, export_key, kind, params, buffer, size, ref, flags):
        ref._obj.value = len(self.blob)
        if buffer is not None:
            ctypes.memmove(buffer, self.blob, len(self.blob))
        return 0

    def NCryptSignHash(self, key, padding, digest, length, buffer, size, ref, flags):
        ref._obj.value = len(self.signature)
        if buffer is not None:
            ctypes.memmove(buffer, self.signature, len(self.signature))
        return self.status.get("sign", 0)

    def NCryptDeleteKey(self, key, flags):
        self.deleted = flags == 0
        return 0 if flags == 0 else 0x80090009

    def NCryptFreeObject(self, handle):
        self.freed.append(handle.value)
        return 0


def _fake(monkeypatch, **status):
    lib = FakeLib(**status)
    monkeypatch.setattr(tpm_windows, "_library", lambda: lib)
    return lib


def test_the_driver_creates_a_missing_key_and_reads_its_public_point(monkeypatch):
    lib = _fake(monkeypatch, open=0x80090016)
    signer = tpm_windows.WindowsTpmSigner("ledger")
    assert signer.public_key() == b"\x04" + bytes(range(64)) and signer.key_name == "purpleteam.ledger"
    assert signer.sign(DATA, CONTEXT) == bytes(range(64))
    signer.close()
    assert sorted(lib.freed) == [11, 33]
    signer.close()  # closing twice is harmless
    assert sorted(lib.freed) == [11, 33]


def test_the_driver_refuses_to_create_when_told_not_to_and_leaks_no_handle(monkeypatch):
    lib = _fake(monkeypatch, open=0x80090016)
    with pytest.raises(SignerUnavailable, match="no key named"):
        tpm_windows.WindowsTpmSigner("ledger", create=False)
    assert lib.freed == [11]


def test_the_driver_cleans_up_when_any_step_fails(monkeypatch):
    _fake(monkeypatch, provider=0x80284008)
    with pytest.raises(SignerError, match="0x80284008"):
        tpm_windows.WindowsTpmSigner("ledger")
    lib = _fake(monkeypatch, open=0x80090016, finalize=0x8009000F)
    with pytest.raises(SignerError, match="finalizing"):
        tpm_windows.WindowsTpmSigner("ledger")
    assert sorted(lib.freed) == [11, 33]
    lib = _fake(monkeypatch, open=0x80090005)  # any other open failure is an error, not "create a key"
    with pytest.raises(SignerError, match="opening the key"):
        tpm_windows.WindowsTpmSigner("ledger")
    assert lib.freed == [11]


def test_the_driver_rejects_a_public_key_that_is_not_p256_or_a_signature_of_the_wrong_size(monkeypatch):
    for blob in (b"\x00" * 72, (0x31534345).to_bytes(4, "little") + (48).to_bytes(4, "little") + bytes(96),
                 (0x31534345).to_bytes(4, "little") + (32).to_bytes(4, "little") + bytes(63)):
        lib = _fake(monkeypatch)
        lib.blob = blob
        with pytest.raises(SignerError, match="P-256|unexpected size"):
            tpm_windows.WindowsTpmSigner("ledger")
        assert sorted(lib.freed) == [11, 22]
    lib = _fake(monkeypatch)
    signer = tpm_windows.WindowsTpmSigner("ledger")
    lib.signature = bytes(70)
    with pytest.raises(SignerError, match="unexpected size"):
        signer.sign(DATA, CONTEXT)
    lib.status["sign"] = 0x80284008
    with pytest.raises(SignerError, match="0x80284008"):
        signer.sign(DATA, CONTEXT)


def test_a_closed_driver_cannot_sign_and_delete_passes_no_flags(monkeypatch):
    lib = _fake(monkeypatch)
    signer = tpm_windows.WindowsTpmSigner("ledger")
    signer.delete()
    assert lib.deleted
    with pytest.raises(SignerError, match="closed"):
        signer.sign(DATA, CONTEXT)


needs_tpm = pytest.mark.skipif(
    platform.system() != "Windows" or not (detect().kind == "tpm2" and detect().reachable),
    reason="needs a reachable Windows TPM 2.0")


@pytest.fixture
def tpm_name():
    name = "test-" + uuid.uuid4().hex[:12]
    yield name
    try:
        tpm_windows.WindowsTpmSigner(name, create=False).delete()
    except SignerUnavailable:
        pass


@needs_tpm
def test_the_real_tpm_signs_and_the_signature_verifies_anywhere(tpm_name):
    with tpm_windows.WindowsTpmSigner(tpm_name) as signer:
        assert signer.kind == "tpm2" and len(signer.public_key()) == 65
        signature = signer.sign(DATA, CONTEXT)
        assert verify_p256(signer.public_key(), CONTEXT, DATA, signature)
        assert not verify_p256(signer.public_key(), b"event", DATA, signature)
        assert not verify_p256(signer.public_key(), CONTEXT, DATA + b"!", signature)


@needs_tpm
def test_the_real_key_persists_by_name_and_different_names_are_different_keys(tpm_name):
    first = tpm_windows.WindowsTpmSigner(tpm_name)
    other = tpm_windows.WindowsTpmSigner(tpm_name + "-b")
    try:
        again = tpm_windows.WindowsTpmSigner(tpm_name, create=False)
        assert again.public_key() == first.public_key() != other.public_key()
        again.close()
    finally:
        first.close()
        other.delete()


@needs_tpm
def test_the_real_private_key_cannot_be_exported(tpm_name):
    with tpm_windows.WindowsTpmSigner(tpm_name) as signer:
        size = tpm_windows.wintypes.DWORD()
        for blob in ("PRIVATEBLOB", "ECCPRIVATEBLOB", "PKCS8_PRIVATEKEY"):
            status = signer._lib.NCryptExportKey(signer._key, None, blob, None, None, 0, ctypes.byref(size), 0)
            assert status != 0, f"the TPM allowed exporting {blob}"


@needs_tpm
def test_a_deleted_real_key_is_gone(tpm_name):
    tpm_windows.WindowsTpmSigner(tpm_name).delete()
    with pytest.raises(SignerUnavailable):
        tpm_windows.WindowsTpmSigner(tpm_name, create=False)


@needs_tpm
def test_the_real_tpm_signs_correctly_from_several_threads(tpm_name):
    with tpm_windows.WindowsTpmSigner(tpm_name) as signer:
        results, errors = [], []

        def work(index):
            try:
                message = f"message {index}".encode()
                results.append(verify_p256(signer.public_key(), CONTEXT, message, signer.sign(message, CONTEXT)))
            except Exception as error:  # surfaced below
                errors.append(error)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
    assert not errors and results == [True] * 8


@needs_tpm
def test_open_signer_returns_the_real_tpm_signer_on_this_machine(tpm_name):
    signer = open_signer(tpm_name)
    try:
        assert signer.kind == "tpm2" and verify_p256(signer.public_key(), CONTEXT, DATA, signer.sign(DATA, CONTEXT))
    finally:
        signer.delete()
