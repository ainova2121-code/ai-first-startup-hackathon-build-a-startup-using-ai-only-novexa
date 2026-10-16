"""A signing key on a PKCS#11 device: an HSM, a smart card, a YubiKey, or SoftHSM for development.

PKCS#11 is the standard interface to hardware key stores. This driver speaks it directly through ``ctypes``
(no extra dependency): it loads the vendor's module, logs in to one named token, finds one named P-256 key and
asks the device to sign a SHA-256 digest with ``CKM_ECDSA``, which returns the 64-byte ``r || s`` every other
hardware signer here returns. The private key never leaves the device, and the driver refuses a key that could
be extracted (``CKA_EXTRACTABLE`` true or ``CKA_SENSITIVE`` false), because an extractable key is not hardware
protection.

The kind is ``hsm``, except for SoftHSM, a software emulator: it reports ``software`` so a test token can never
pass as hardware. As with every kind, ``hsm`` is a claim in the trust bundle that nothing here attests.

The PIN is a ``SecretStr`` (or a function returning one, for a secrets manager), is never logged and never
appears in an error. A wrong PIN is not retried: tokens lock after a few failures.

Linux and macOS only. Windows modules use a different structure packing that this driver has not been verified
against, so it refuses there rather than risk calling the wrong function. ``generate_key`` creates a
non-extractable P-256 key pair for development and tests; production keys are provisioned with the HSM's tools.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import platform
import sys
import threading
from ctypes import POINTER, byref, c_ulong
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr

from purpleteam.audit.pkcs11_abi import (
    Attribute, CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL,
    CKA_PRIVATE, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_VERIFY, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKK_EC,
    CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKR_ALREADY_INITIALIZED, CKR_OK,
    CKR_USER_ALREADY_LOGGED_IN, CKU_USER, FunctionList, Mechanism, P256_PARAMS, PROTOTYPES, RESULTS, TokenInfo)
from purpleteam.audit.hardware_signer import HSM, KEY_NAME, SOFTWARE, SignerError, SignerUnavailable, signed_message

_modules: dict[str, dict] = {}  # module path -> {"users": signers using it, "ours": we initialised it}
_modules_lock = threading.Lock()
# Login state belongs to the whole token, not to a session: a second login is refused, and one logout would end
# every signer's. So logins are counted per token, and a repeat login is accepted only with the same PIN.
_logins: dict[tuple[str, int], dict] = {}  # (module, slot) -> {"users": signers logged in, "check": salted PIN hash}
_SALT = os.urandom(16)
_MAX_ATTRIBUTE = 65_536  # CK_UNAVAILABLE_INFORMATION is all ones; no real attribute is this large


def _fail(what: str, code: int) -> SignerError:
    return SignerError(f"the PKCS#11 device refused {what} ({RESULTS.get(code, f'CKR 0x{code:X}')})")


def _text(raw) -> str:
    return bytes(raw).decode("utf-8", "replace").strip()


def parse_ec_point(value: bytes) -> bytes:
    """An uncompressed P-256 point from ``CKA_EC_POINT``: a DER OCTET STRING around it (the standard), or bare."""
    point = value[2:] if len(value) == 67 and value[:3] == b"\x04\x41\x04" else value
    if len(point) != 65 or point[0] != 4:
        raise SignerError("the PKCS#11 key's public point is not an uncompressed P-256 point")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)  # rejects a point off the curve
    except ValueError:
        raise SignerError("the PKCS#11 key's public point is not on the P-256 curve") from None
    return point


def _template(items: list[tuple[int, bytes]]):
    """A CK_ATTRIBUTE array over byte values, and the buffers that must stay alive while it is in use."""
    keep = [ctypes.create_string_buffer(value, max(len(value), 1)) for _, value in items]
    array = (Attribute * len(items))(*[Attribute(t, ctypes.addressof(b), len(v)) for (t, v), b in zip(items, keep)])
    return array, keep


def _bool(flag: bool) -> bytes:
    return b"\x01" if flag else b"\x00"


def _ulong(number: int) -> bytes:
    return number.to_bytes(ctypes.sizeof(c_ulong), sys.byteorder)


class Pkcs11Signer:
    def __init__(self, module: str | Path, token: str, key: str, pin: SecretStr | Callable[[], SecretStr]) -> None:
        if platform.system() not in ("Linux", "Darwin"):
            raise SignerUnavailable("PKCS#11 is verified on Linux and macOS only; use another signer on this system")
        if not KEY_NAME.fullmatch(key or "") or not isinstance(token, str) or not 0 < len(token) <= 32:
            raise ValueError("a PKCS#11 key label is 1-64 letters, digits, dots, dashes or underscores; a token label 1-32 characters")
        path = Path(module)
        if not path.is_file():
            raise SignerUnavailable("the PKCS#11 module file was not found")
        self._lock, self._session, self._logged_in, self._registered = threading.Lock(), None, False, False
        self._module = str(path.resolve())
        self._calls = self._load(self._module)
        try:
            slot = self._find_slot(token)
            self.kind = HSM if "softhsm" not in self.token["manufacturer"].lower() else SOFTWARE
            self._open(slot, pin)
            self._private, self._public = self._find_key(key)
        except BaseException:
            self.close()
            raise

    def public_key(self) -> bytes:
        return self._point

    def sign(self, data: bytes, context: bytes) -> bytes:
        digest = hashlib.sha256(signed_message(context, data)).digest()
        with self._lock:
            if self._session is None:
                raise SignerError("this signer is closed")
            mechanism = Mechanism(CKM_ECDSA, None, 0)
            self._check(self._calls["C_SignInit"](self._session, byref(mechanism), self._private), "starting to sign")
            out, size = ctypes.create_string_buffer(64), c_ulong(64)
            self._check(self._calls["C_Sign"](self._session, digest, len(digest), out, byref(size)), "signing")
        if size.value != 64:
            raise SignerError("the PKCS#11 device returned a signature of an unexpected size")
        return out.raw[:64]

    def close(self) -> None:
        with self._lock:
            session, self._session = self._session, None
            if session is not None:
                if self._logged_in and self._release_login():
                    self._calls["C_Logout"](session)  # the last signer on this token logs everyone out
                self._calls["C_CloseSession"](session)
            self._logged_in = False
            if self._registered:  # the last signer out finalises the module, and only if we were the ones to start it
                self._registered = False
                with _modules_lock:
                    state = _modules[self._module]
                    state["users"] -= 1
                    if state["users"] == 0:
                        del _modules[self._module]
                        if state["ours"]:
                            self._calls["C_Finalize"](None)

    def _release_login(self) -> bool:
        """True if this was the last signer logged in to the token."""
        with _modules_lock:
            state = _logins.get((self._module, self._slot))
            if state is None:
                return True
            state["users"] -= 1
            if state["users"] > 0:
                return False
            del _logins[(self._module, self._slot)]
            return True

    def __enter__(self) -> "Pkcs11Signer":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _load(self, module: str) -> dict:
        try:
            library = ctypes.CDLL(module)
            function_list = POINTER(FunctionList)()
            library.C_GetFunctionList.argtypes, library.C_GetFunctionList.restype = [POINTER(POINTER(FunctionList))], c_ulong
            self._check(library.C_GetFunctionList(byref(function_list)), "listing its functions")
        except (OSError, AttributeError) as error:
            raise SignerUnavailable(f"the file is not a usable PKCS#11 module ({type(error).__name__})") from None
        self._library = library  # kept alive: the function pointers point into it
        missing = [name for name in PROTOTYPES if not getattr(function_list.contents, name)]
        if missing:  # calling a null function pointer would crash the process
            raise SignerUnavailable(f"the PKCS#11 module does not provide {', '.join(missing)}")
        calls = {name: ctypes.cast(getattr(function_list.contents, name), ctypes.CFUNCTYPE(c_ulong, *args))
                 for name, args in PROTOTYPES.items()}
        with _modules_lock:
            result = calls["C_Initialize"](None)
            if result not in (CKR_OK, CKR_ALREADY_INITIALIZED):
                raise _fail("starting up", result)
            state = _modules.setdefault(module, {"users": 0, "ours": False})
            state["users"] += 1
            state["ours"] = state["ours"] or result == CKR_OK
            self._registered = True
        return calls

    def _find_slot(self, label: str) -> int:
        count = c_ulong()
        self._check(self._calls["C_GetSlotList"](1, None, byref(count)), "listing slots")
        slots = (c_ulong * max(count.value, 1))()
        self._check(self._calls["C_GetSlotList"](1, slots, byref(count)), "listing slots")
        matches = []
        for slot in list(slots)[:count.value]:
            info = TokenInfo()
            if self._calls["C_GetTokenInfo"](slot, byref(info)) == CKR_OK and _text(info.label) == label:
                matches.append((slot, {"label": label, "manufacturer": _text(info.manufacturer), "model": _text(info.model)}))
        if len(matches) != 1:
            raise SignerUnavailable("no PKCS#11 token has that label" if not matches else "more than one token has that label")
        self.token = matches[0][1]
        return matches[0][0]

    def _open(self, slot: int, pin: SecretStr | Callable[[], SecretStr], *, writable: bool = False) -> None:
        """Signing needs only a read-only session; creating a key on the token needs a read-write one."""
        session = c_ulong()
        flags = CKF_SERIAL_SESSION | (CKF_RW_SESSION if writable else 0)
        self._check(self._calls["C_OpenSession"](slot, flags, None, None, byref(session)), "opening a session")
        self._session = session.value
        secret = (pin() if callable(pin) else pin).get_secret_value().encode("utf-8")
        check, key = hashlib.sha256(_SALT + secret).digest(), (self._module, slot)
        with _modules_lock:
            result = self._calls["C_Login"](self._session, CKU_USER, secret, len(secret))  # never retried
            state = _logins.get(key)
            if result == CKR_OK:
                _logins[key] = {"users": 1, "check": check}
            elif result == CKR_USER_ALREADY_LOGGED_IN and state and hmac.compare_digest(state["check"], check):
                state["users"] += 1
            elif result == CKR_USER_ALREADY_LOGGED_IN:  # never wave through a PIN that was not checked
                raise SignerError("this token is already logged in by this process, and the PIN given does not match")
            else:
                raise _fail("the PIN", result)
        self._slot, self._logged_in = slot, True

    def _find(self, items: list[tuple[int, bytes]]) -> list[int]:
        template, keep = _template(items)
        self._check(self._calls["C_FindObjectsInit"](self._session, template, len(items)), "searching for the key")
        try:
            handles, found = (c_ulong * 4)(), c_ulong()
            self._check(self._calls["C_FindObjects"](self._session, handles, 4, byref(found)), "searching for the key")
        finally:
            self._calls["C_FindObjectsFinal"](self._session)
        return list(handles)[:found.value]

    def _read(self, handle: int, attribute: int) -> bytes:
        query = (Attribute * 1)(Attribute(attribute, None, 0))
        self._check(self._calls["C_GetAttributeValue"](self._session, handle, query, 1), "reading a key attribute")
        if query[0].length > _MAX_ATTRIBUTE:
            raise SignerError("the PKCS#11 device does not reveal a key attribute that is needed to trust the key")
        buffer = ctypes.create_string_buffer(max(query[0].length, 1))
        query[0].value = ctypes.addressof(buffer)
        self._check(self._calls["C_GetAttributeValue"](self._session, handle, query, 1), "reading a key attribute")
        return buffer.raw[:query[0].length]

    def _find_key(self, label: str) -> tuple[int, int]:
        text = label.encode()
        private = self._find([(CKA_CLASS, _ulong(CKO_PRIVATE_KEY)), (CKA_KEY_TYPE, _ulong(CKK_EC)), (CKA_LABEL, text)])
        if len(private) != 1:
            raise SignerUnavailable("no P-256 key has that label on the token" if not private else "more than one key has that label")
        if self._read(private[0], CKA_EXTRACTABLE) != b"\x00" or self._read(private[0], CKA_SENSITIVE) != b"\x01":
            raise SignerError("the PKCS#11 key can be extracted from the device, so it is not hardware protection")
        if self._read(private[0], CKA_EC_PARAMS) not in P256_PARAMS:
            raise SignerError("the PKCS#11 key is not a P-256 key")
        public = self._find([(CKA_CLASS, _ulong(CKO_PUBLIC_KEY)), (CKA_KEY_TYPE, _ulong(CKK_EC)), (CKA_LABEL, text)])
        holder = public[0] if len(public) == 1 else private[0]  # some devices keep the point on the private object
        self._point = parse_ec_point(self._read(holder, CKA_EC_POINT))
        return private[0], holder

    @staticmethod
    def _check(result: int, what: str) -> None:
        if result != CKR_OK:
            raise _fail(what, result)

    @classmethod
    def generate_key(cls, module: str | Path, token: str, key: str, pin: SecretStr) -> "Pkcs11Signer":
        """Create a non-extractable P-256 key pair named ``key`` on the token (development and tests), then open it."""
        with cls._provisioner(module, token, pin) as device:
            mechanism = Mechanism(CKM_EC_KEY_PAIR_GEN, None, 0)
            label = key.encode()
            public, keep_public = _template([(CKA_TOKEN, _bool(True)), (CKA_LABEL, label), (CKA_VERIFY, _bool(True)),
                                             (CKA_EC_PARAMS, P256_PARAMS[0])])
            private, keep_private = _template([(CKA_TOKEN, _bool(True)), (CKA_PRIVATE, _bool(True)), (CKA_LABEL, label),
                                               (CKA_SIGN, _bool(True)), (CKA_SENSITIVE, _bool(True)),
                                               (CKA_EXTRACTABLE, _bool(False))])
            handles = (c_ulong(), c_ulong())
            device._check(device._calls["C_GenerateKeyPair"](
                device._session, byref(mechanism), public, len(public), private, len(private), byref(handles[0]),
                byref(handles[1])), "generating a key pair")
        return cls(module, token, key, pin)

    @classmethod
    def _provisioner(cls, module, token, pin):
        device = cls.__new__(cls)
        device._lock, device._session, device._logged_in, device._registered = threading.Lock(), None, False, False
        device._module = str(Path(module).resolve())
        device._calls = device._load(device._module)
        try:
            device._open(device._find_slot(token), pin, writable=True)
        except BaseException:
            device.close()
            raise
        return device
