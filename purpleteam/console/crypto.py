"""Encrypts a registered gateway's admin key at rest, keyed from CONSOLE_SECRET_KEY -- the
console refuses to start without it, the same "no secrets in the clear by default" posture
GATEWAY_REDACTOR_SECRET already takes in gateway_main.py.
"""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken


def derive_key(secret: str) -> bytes:
    """An arbitrary operator-chosen secret, reduced to the 32-byte url-safe key Fernet needs."""
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())


def encrypt(plain: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(plain.encode("utf-8"))


def decrypt(blob: bytes, key: bytes) -> str:
    try:
        return Fernet(key).decrypt(blob).decode("utf-8")
    except InvalidToken as error:
        raise ValueError("could not decrypt with this key") from error
