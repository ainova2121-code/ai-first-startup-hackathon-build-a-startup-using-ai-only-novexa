"""Fake credentials for the secret-detection tests, assembled at runtime.

None is a real credential. They are built from pieces so no key-shaped literal sits in the
repository, which keeps secret scanners and push protection from flagging the tests.
"""

import base64
import json


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt() -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": "1234567890", "name": "test user"}).encode())
    return f"{header}.{payload}.{_b64url(bytes(range(32)))}"


FORMATS = {
    "aws_access_key": "AK" + "IA" + "IOSFODNN7EXAMPLE",
    "github_token": "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "sk_api_key": "s" + "k-" + "proj-" + "AbCdEfGhIjKlMnOpQrStUvWx",
    "slack_token": "xo" + "xb-" + "123456789012-abcdefABCDEF",
    "stripe_key": "s" + "k_live_" + "0123456789abcdefABCDEF12",
    "google_api_key": "AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
    "groq_key": "gs" + "k_" + "A1b2C3d4E5f6G7h8I9j0K1l2",
    "huggingface_token": "hf" + "_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7",
    "jwt": jwt(),
    "private_key": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "url_credentials": "postgres://app:" + "s3cretPass99" + "@db.internal:5432/ledger",
    "bearer_token": "Bearer " + "abcdefghij0123456789ABCDEFGH",
}

RANDOM_LOOKING = "q8Zr3LmX9vB2nT6yWc1KdF4gHj7PsA5e"  # no known format: only context and entropy flag it
