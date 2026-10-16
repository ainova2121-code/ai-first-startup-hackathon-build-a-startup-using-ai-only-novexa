"""A signing key that lives inside the Windows TPM, reached through the Windows crypto API (CNG).

The key is created by the "Microsoft Platform Crypto Provider", which generates it inside the TPM and keeps
only a TPM-wrapped blob on disk: the private half never exists outside the chip and cannot be exported (a test
proves the export is refused). Signing asks the TPM to sign a SHA-256 digest and returns the raw 64-byte
``r || s``. Nothing needs administrator rights, and ``NCRYPT_SILENT_FLAG`` stops any prompt from appearing.

The key persists under the name ``purpleteam.<name>`` in the current user's key store, so the same name
reopens the same key after a restart; it is the Windows account plus this TPM that can use it. ``delete``
removes it for good. Windows only: elsewhere ``ctypes.WinDLL`` does not exist and opening raises ``OSError``.
"""

from __future__ import annotations

import ctypes
import hashlib
import threading
from ctypes import wintypes

from purpleteam.audit.hardware import TPM2
from purpleteam.audit.hardware_signer import (
    KEY_NAME, POINT_BYTES, SIGNATURE_BYTES, SignerError, SignerUnavailable, signed_message)

PROVIDER = "Microsoft Platform Crypto Provider"
KEY_PREFIX = "purpleteam."
_ALGORITHM, _PUBLIC_BLOB = "ECDSA_P256", "ECCPUBLICBLOB"
_P256_PUBLIC_MAGIC = 0x31534345  # "ECS1": BCRYPT_ECDSA_PUBLIC_P256_MAGIC
_SILENT = 0x40
_MISSING_KEY = (0x80090016, 0x8009000D)  # NTE_BAD_KEYSET, NTE_NO_KEY


def _library() -> ctypes.WinDLL:
    lib = ctypes.WinDLL("ncrypt")
    handle, pointer, dword, text = ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD, wintypes.LPCWSTR
    size = ctypes.POINTER(wintypes.DWORD)
    signatures = {
        "NCryptOpenStorageProvider": [pointer, text, dword],
        "NCryptOpenKey": [handle, pointer, text, dword, dword],
        "NCryptCreatePersistedKey": [handle, pointer, text, text, dword, dword],
        "NCryptFinalizeKey": [handle, dword],
        "NCryptExportKey": [handle, handle, text, handle, handle, dword, size, dword],
        "NCryptSignHash": [handle, handle, ctypes.c_char_p, dword, handle, dword, size, dword],
        "NCryptDeleteKey": [handle, dword],
        "NCryptFreeObject": [handle],
    }
    for name, argtypes in signatures.items():
        function = getattr(lib, name)
        function.argtypes, function.restype = argtypes, ctypes.c_long  # a 32-bit status; 0 is success
    return lib


def _check(status: int, what: str) -> None:
    if status != 0:
        raise SignerError(f"the TPM refused {what} (status 0x{status & 0xFFFFFFFF:08X})")


class WindowsTpmSigner:
    kind = TPM2

    def __init__(self, name: str, *, create: bool = True) -> None:
        if not KEY_NAME.fullmatch(name or ""):
            raise ValueError("a key name is 1-64 letters, digits, dots, dashes or underscores")
        self.key_name = KEY_PREFIX + name
        self._lock = threading.Lock()
        self._lib = _library()
        self._provider, self._key = ctypes.c_void_p(), ctypes.c_void_p()
        try:
            _check(self._lib.NCryptOpenStorageProvider(ctypes.byref(self._provider), PROVIDER, 0),
                   "opening the TPM key provider")
            status = self._lib.NCryptOpenKey(self._provider, ctypes.byref(self._key), self.key_name, 0, _SILENT)
            if status & 0xFFFFFFFF in _MISSING_KEY:
                if not create:
                    raise SignerUnavailable(f"the TPM holds no key named {name!r}")
                _check(self._lib.NCryptCreatePersistedKey(self._provider, ctypes.byref(self._key), _ALGORITHM,
                                                          self.key_name, 0, _SILENT), "creating a key")
                _check(self._lib.NCryptFinalizeKey(self._key, _SILENT), "finalizing the key")
            else:
                _check(status, "opening the key")
            self._public = self._export_public()
        except BaseException:
            self.close()
            raise

    def public_key(self) -> bytes:
        return self._public

    def sign(self, data: bytes, context: bytes) -> bytes:
        digest = hashlib.sha256(signed_message(context, data)).digest()
        with self._lock:
            if not self._key:
                raise SignerError("this signer is closed")
            size = wintypes.DWORD()
            _check(self._lib.NCryptSignHash(self._key, None, digest, len(digest), None, 0, ctypes.byref(size), _SILENT),
                   "sizing a signature")
            buffer = ctypes.create_string_buffer(size.value)
            _check(self._lib.NCryptSignHash(self._key, None, digest, len(digest), buffer, size.value,
                                            ctypes.byref(size), _SILENT), "signing")
        signature = buffer.raw[:size.value]
        if len(signature) != SIGNATURE_BYTES:
            raise SignerError("the TPM returned a signature of an unexpected size")
        return signature

    def delete(self) -> None:
        """Remove the key from the TPM for good."""
        with self._lock:
            if self._key:
                _check(self._lib.NCryptDeleteKey(self._key, 0), "deleting the key")  # this call takes no flags
                self._key = ctypes.c_void_p()  # deleting also frees the handle
        self.close()

    def close(self) -> None:
        with self._lock:
            for handle in (self._key, self._provider):
                if handle:
                    self._lib.NCryptFreeObject(handle)
            self._key, self._provider = ctypes.c_void_p(), ctypes.c_void_p()

    def __enter__(self) -> "WindowsTpmSigner":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _export_public(self) -> bytes:
        size = wintypes.DWORD()
        _check(self._lib.NCryptExportKey(self._key, None, _PUBLIC_BLOB, None, None, 0, ctypes.byref(size), 0),
               "sizing the public key")
        buffer = ctypes.create_string_buffer(size.value)
        _check(self._lib.NCryptExportKey(self._key, None, _PUBLIC_BLOB, None, buffer, size.value,
                                         ctypes.byref(size), 0), "exporting the public key")
        blob = buffer.raw[:size.value]
        magic, length = int.from_bytes(blob[:4], "little"), int.from_bytes(blob[4:8], "little")
        if magic != _P256_PUBLIC_MAGIC or length != 32 or len(blob) != 8 + 2 * length:
            raise SignerError("the TPM returned a public key that is not a P-256 key")
        point = b"\x04" + blob[8:]
        if len(point) != POINT_BYTES:
            raise SignerError("the TPM returned a public key of an unexpected size")
        return point
