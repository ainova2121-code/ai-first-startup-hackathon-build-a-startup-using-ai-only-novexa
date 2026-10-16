"""Signed release provenance: proves a distributed artifact (wheel, tarball, container image) is
exactly what the vendor built, not tampered with in transit or by a compromised registry or mirror.

Signed by the same hybrid key (Ed25519 + ML-DSA-65, ``audit.keys.AgentKeyring``, actor ``"vendor"``)
that signs licenses (``licensing.py``) and the audit ledger — one key, one trust bundle to pin, not
three separate crypto systems. A customer verifies a downloaded artifact against only the vendor's
public key; nothing is phoned home, so this holds BYOC the same way licensing does. This proves the
bytes are ours and unaltered; it says nothing about the source that produced them — see the
project's packaging and pipeline protections for that.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path

from purpleteam.audit.hashing import canonical
from purpleteam.audit.keys import AgentKeyring, verify_pq, verify_signature
from purpleteam.audit.verify import is_hex

RELEASE_CONTEXT = b"purpleteam.release.v1"
VENDOR = "vendor"  # the actor name the vendor's keyring signs releases under (see licensing.py)
_NAME = re.compile(r"[\w.+-]{1,256}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CORE_FIELDS = ("artifact", "version", "revision", "digest", "built_at", "kid")
_MAX_TIME = 1e15
_CHUNK = 1 << 20  # 1 MiB; artifacts (wheels, container tars) can be large


def _valid_name(value: object) -> bool:
    return isinstance(value, str) and _NAME.fullmatch(value) is not None


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _valid_time(value: object) -> bool:
    return type(value) in (int, float) and abs(value) <= _MAX_TIME


def digest_file(path: str | Path) -> str:
    """SHA-256 of a file's bytes, streamed so a large artifact never has to fit in memory at once."""
    hasher = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


@dataclass(frozen=True)
class ReleaseResult:
    ok: bool
    reason: str = ""
    artifact: str = ""
    version: str = ""
    revision: str = ""
    digest: str = ""


def sign_release(keyring: AgentKeyring, artifact: str, version: str, revision: str, digest: str,
                 *, built_at: float | None = None) -> dict:
    """Vendor-side: sign a release statement binding an artifact's name, version, source revision
    (e.g. a git commit SHA) and content digest. ``keyring`` must hold the private ``vendor`` key."""
    if not (_valid_name(artifact) and _valid_name(version) and _valid_name(revision)):
        raise ValueError("artifact, version and revision must be plain names")
    if not _valid_digest(digest):
        raise ValueError("digest must be a lowercase SHA-256 hex string")
    kid = keyring.kid(VENDOR)
    core = {"artifact": artifact, "version": version, "revision": revision, "digest": digest,
           "built_at": round(built_at if built_at is not None else time.time(), 3), "kid": kid}
    signature = keyring.sign(VENDOR, canonical(core), RELEASE_CONTEXT, kid=kid)
    return {**core, "sig": signature.ed25519, **({"pqsig": signature.mldsa65} if signature.mldsa65 else {})}


def _well_formed(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    fields = set(data)
    if fields not in ({*_CORE_FIELDS, "sig"}, {*_CORE_FIELDS, "sig", "pqsig"}):
        return False
    return (_valid_name(data["artifact"]) and _valid_name(data["version"]) and _valid_name(data["revision"])
            and _valid_digest(data["digest"]) and _valid_time(data["built_at"])
            and is_hex("kid", data["kid"]) and is_hex("sig", data["sig"])
            and ("pqsig" not in data or is_hex("pqsig", data["pqsig"])))


def verify_release(statement: dict, public_keys: dict, *, artifact_path: str | Path | None = None,
                   artifact_digest: str | None = None, require_pq: bool = False) -> ReleaseResult:
    """Customer-side: check a release statement against the vendor's pinned ``public_keys``
    (``AgentKeyring.public_keys()`` shape). Pass ``artifact_path`` (recomputed) or ``artifact_digest``
    (already known, e.g. from a registry pull) to also confirm the artifact in hand matches what was
    signed — without one of those this only proves the statement itself is genuine, not that a
    particular file matches it. Never trusts the statement's own claims; malformed input, an unknown
    key, a bad signature or a digest mismatch are all failures, never exceptions."""
    if not _well_formed(statement):
        return ReleaseResult(False, reason="malformed release statement")
    public = public_keys.get(VENDOR, {}).get(statement["kid"])
    if public is None:
        return ReleaseResult(False, reason="unknown signing key")
    message = canonical({k: statement[k] for k in _CORE_FIELDS})
    public_ed = public if isinstance(public, str) else public.get("ed25519", "")
    if not verify_signature(public_ed, message, statement["sig"]):
        return ReleaseResult(False, reason="signature does not verify")
    has_pq = isinstance(public, dict) and "mldsa65" in public
    if "pqsig" in statement or require_pq:
        if "pqsig" not in statement or not has_pq:
            return ReleaseResult(False, reason="post-quantum signature required but missing")
        if not verify_pq(public["mldsa65"], message, statement["pqsig"], RELEASE_CONTEXT):
            return ReleaseResult(False, reason="post-quantum signature does not verify")
    actual = artifact_digest if artifact_digest is not None else (digest_file(artifact_path) if artifact_path else None)
    if actual is not None and actual != statement["digest"]:
        return ReleaseResult(False, reason="artifact digest does not match the signed statement")
    return ReleaseResult(True, artifact=statement["artifact"], version=statement["version"],
                         revision=statement["revision"], digest=statement["digest"])


def _main() -> None:
    """``uv run python -m purpleteam.provenance <artifact-path> <version> <revision>``: sign one
    release artifact with an ephemeral demo key and print the statement plus the public keys to
    pin. A real release signs with a persisted vendor keyring, not an ephemeral one."""
    import json
    import sys

    if len(sys.argv) != 4:
        print("usage: python -m purpleteam.provenance <artifact-path> <version> <revision>")
        raise SystemExit(2)
    path, version, revision = sys.argv[1:]
    keyring = AgentKeyring()
    statement = sign_release(keyring, Path(path).name, version, revision, digest_file(path))
    print(json.dumps({"statement": statement, "public_keys": keyring.public_keys()[VENDOR]}, indent=2))


if __name__ == "__main__":
    _main()
