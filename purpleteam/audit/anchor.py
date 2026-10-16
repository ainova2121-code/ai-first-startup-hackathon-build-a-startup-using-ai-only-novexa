"""RFC 3161 anchoring: an outside authority vouches that a checkpoint existed by a given time.

Only the SHA-256 of the signed checkpoint leaves the machine, never log content. A timestamp
proves the checkpoint existed *no later than* the authority's time; it cannot prove it was
created then (anyone can timestamp an old checkpoint today), so it protects against backdating,
not staleness. When several authorities vouch, the latest of their times is the bound, so one
authority lying early cannot pull it earlier than an honest one's. Authority certificates are
pinned from disk and checked against a SHA256SUMS manifest; compare that manifest with the
authority's own website when you add it. Every failure is an ``AnchorError``: nothing here
fails open, and the ledger works without anchors (they are attached afterwards).
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence
from urllib.parse import urlparse

import httpx
from cryptography import x509
from rfc3161_client import HashAlgorithm, TimestampRequestBuilder, VerifierBuilder, decode_timestamp_response

from purpleteam.audit.hashing import canonical
from purpleteam.audit.keys import valid_actor
from purpleteam.audit.verify import VerifyResult, verify_log

MAX_RESPONSE_BYTES = 64 * 1024
MAX_REQUEST_DRIFT = 300.0   # seconds: an authority whose clock disagrees with ours this much is not used
FREETSA_URL = "https://freetsa.org/tsr"
FREETSA_DIR = Path(__file__).resolve().parents[2] / "config" / "tsa" / "freetsa"

Post = Callable[[str, bytes, float], bytes]


class AnchorError(Exception):
    """An anchor could not be obtained or did not verify."""


@dataclass(frozen=True)
class Authority:
    name: str
    url: str
    roots: tuple[x509.Certificate, ...]
    signer: x509.Certificate | None = None  # pin the exact signing certificate when known


def _require_https(url: str) -> None:
    try:
        parsed = urlparse(url)
        valid = parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
    except ValueError:  # urlparse rejects malformed hosts such as an unclosed IPv6 bracket
        valid = False
    if not valid:
        raise AnchorError("the timestamp authority URL must be plain https")


def _manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, _, name = line.partition(" ")
            entries[name.strip().lstrip("*")] = digest.strip()
    return entries


def load_authority(name: str, url: str, directory: str | Path, *, roots: Sequence[str] = ("cacert.pem",),
                   signer: str | None = "tsa.crt") -> Authority:
    """Load pinned PEM certificates, refusing any file that differs from the directory's SHA256SUMS."""
    if not valid_actor(name):
        raise AnchorError("invalid authority name")
    _require_https(url)
    directory = Path(directory)
    expected = _manifest(directory / "SHA256SUMS")

    def load(file_name: str) -> x509.Certificate:
        if Path(file_name).name != file_name:
            raise AnchorError("certificate files must sit directly in the authority directory")
        data = (directory / file_name).read_bytes()
        if expected.get(file_name) != hashlib.sha256(data).hexdigest():
            raise AnchorError(f"{file_name} does not match SHA256SUMS")
        try:
            certificates = x509.load_pem_x509_certificates(data)
        except ValueError as error:
            raise AnchorError(f"{file_name} is not a PEM certificate") from error
        if len(certificates) != 1:  # one pinned file, one certificate: nothing extra may ride along
            raise AnchorError(f"{file_name} must hold exactly one certificate, found {len(certificates)}")
        return certificates[0]

    return Authority(name, url, tuple(load(f) for f in roots), load(signer) if signer else None)


def freetsa(directory: str | Path = FREETSA_DIR) -> Authority:
    return load_authority("freetsa", FREETSA_URL, directory)


def https_post(url: str, body: bytes, timeout: float, *, transport: httpx.BaseTransport | None = None) -> bytes:
    """POST a timestamp query: https only, no redirects, bounded response."""
    _require_https(url)
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, transport=transport) as client:
            with client.stream("POST", url, content=body,
                               headers={"Content-Type": "application/timestamp-query"}) as response:
                if response.status_code != 200:
                    raise AnchorError(f"the authority answered HTTP {response.status_code}")
                data = bytearray()
                for chunk in response.iter_bytes():
                    data += chunk
                    if len(data) > MAX_RESPONSE_BYTES:
                        raise AnchorError("the authority's response is too large")
                return bytes(data)
    except (httpx.HTTPError, httpx.InvalidURL) as error:
        raise AnchorError(f"could not reach the authority ({type(error).__name__})") from error


def verify_token(token: bytes, message: bytes, authority: Authority, *, request=None) -> datetime:
    """The authority's time if ``token`` is a valid timestamp of ``message``; otherwise ``AnchorError``.

    Passing the ``request`` that was sent also checks the nonce, so a captured genuine response
    cannot be replayed to answer a fresh request.
    """
    if len(token) > MAX_RESPONSE_BYTES:
        raise AnchorError("the timestamp token is too large")
    try:
        response = decode_timestamp_response(token)
        builder = VerifierBuilder.from_request(request) if request is not None else VerifierBuilder()
        for root in authority.roots:  # a fresh builder each time: its add_* methods mutate shared lists
            builder = builder.add_root_certificate(root)
        if authority.signer is not None:
            builder = builder.tsa_certificate(authority.signer)
        builder.build().verify_message(response, message)
        stamped = response.tst_info.gen_time
    except Exception as error:  # the parser and verifier raise several types on hostile input
        raise AnchorError(f"timestamp token rejected: {error}") from error
    return stamped if stamped.tzinfo else stamped.replace(tzinfo=timezone.utc)


def request_anchor(checkpoint: dict, authority: Authority, *, post: Post = https_post,
                   timeout: float = 10.0, now: float | None = None) -> dict:
    message = canonical(checkpoint)
    request = TimestampRequestBuilder().data(message).hash_algorithm(HashAlgorithm.SHA256).build()
    token = post(authority.url, request.as_bytes(), timeout)
    stamped = verify_token(token, message, authority, request=request)
    if abs((time.time() if now is None else now) - stamped.timestamp()) > MAX_REQUEST_DRIFT:
        raise AnchorError("the authority's clock disagrees with ours")
    return {"authority": authority.name, "response": base64.b64encode(token).decode("ascii")}


def anchor_trust(trust: dict, authorities: Sequence[Authority], *, post: Post = https_post,
                 timeout: float = 10.0) -> tuple[dict, list[str]]:
    """Attach an anchor from each reachable authority; unreachable ones are reported, not fatal."""
    anchors, errors = [], []
    for authority in authorities:
        try:
            anchors.append(request_anchor(trust["checkpoint"], authority, post=post, timeout=timeout))
        except AnchorError as error:
            errors.append(f"{authority.name}: {error}")
    return {**trust, "anchors": anchors}, errors


def verify_anchor(checkpoint: dict, anchor: dict, authorities: dict[str, Authority]) -> datetime:
    try:
        authority = authorities[anchor["authority"]]
        token = base64.b64decode(anchor["response"], validate=True)
    except (KeyError, TypeError, ValueError) as error:
        raise AnchorError("unknown authority or malformed anchor") from error
    return verify_token(token, canonical(checkpoint), authority)


def verify_anchored_log(events: list[dict], trust: dict, authorities: dict[str, Authority], *,
                        min_anchors: int = 1, anchored_before: float | None = None,
                        max_clock_skew: float = 60.0, **policy) -> VerifyResult:
    """``verify_log`` plus: at least ``min_anchors`` distinct authorities vouch for the pinned checkpoint.

    ``anchored_before`` (epoch seconds) requires that every verified anchor is no later than it,
    i.e. the log's committed prefix existed by then. ``policy`` goes to ``verify_log``.
    """
    result = verify_log(events, trust, max_clock_skew=max_clock_skew, **policy)
    if not result.ok:
        return result

    def fail(reason: str) -> VerifyResult:
        return replace(result, ok=False, anchored=False, reason=reason)

    if not result.anchored:
        return fail("no pinned checkpoint to anchor")
    stamps: dict[str, datetime] = {}
    problems: list[str] = []
    for anchor in trust.get("anchors") or []:
        try:
            stamps[anchor["authority"]] = verify_anchor(trust["checkpoint"], anchor, authorities)
        except (AnchorError, KeyError, TypeError) as error:
            problems.append(str(error))
    if len(stamps) < min_anchors:
        detail = f" ({'; '.join(problems)})" if problems else ""
        return fail(f"{len(stamps)} of {min_anchors} required timestamp anchors verified{detail}")
    if not stamps:
        return result
    anchored_at = max(t.timestamp() for t in stamps.values())
    if trust["checkpoint"]["ts"] > anchored_at + max_clock_skew:
        return fail("the checkpoint claims a time after its own timestamp")
    if anchored_before is not None and anchored_at > anchored_before:
        return fail("anchored later than required")
    return replace(result, anchored_at=anchored_at)
