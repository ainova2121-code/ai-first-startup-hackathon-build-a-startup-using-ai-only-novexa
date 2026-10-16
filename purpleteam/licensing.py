"""Signed license entitlements: offline, no phone-home — fits BYOC the same way the audit ledger does.

A license names what a customer may run (edition, features, expiry) and is signed by the vendor's
own hybrid key (``audit.keys.AgentKeyring``, actor ``"vendor"``) — the same Ed25519 + ML-DSA-65
scheme that signs the audit trail, so there is no second cryptographic system to trust or maintain.
A deployment verifies a license with only the vendor's *public* keys, pinned at install time; it
never calls out to us to check entitlement, which is the point for a customer who runs everything
in their own cloud. A license can restrict edition, features and validity; it cannot stop a
customer with full control of the runtime from patching the check out of the binary — see the
project's packaging and legal protections for that risk, this only covers the honest case.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from purpleteam.audit.hashing import canonical
from purpleteam.audit.keys import AgentKeyring, verify_pq, verify_signature
from purpleteam.audit.verify import is_hex

LICENSE_CONTEXT = b"purpleteam.license.v1"
VENDOR = "vendor"  # the actor name the vendor's keyring signs licenses under
_NAME = re.compile(r"[\w.-]{1,128}")
_CORE_FIELDS = ("customer", "edition", "features", "issued_at", "expires_at", "kid")
_MAX_TIME = 1e15


def _valid_name(value: object) -> bool:
    return isinstance(value, str) and _NAME.fullmatch(value) is not None


def _valid_time(value: object) -> bool:
    return type(value) in (int, float) and abs(value) <= _MAX_TIME


@dataclass(frozen=True)
class LicenseResult:
    ok: bool
    reason: str = ""
    expired: bool = False
    customer: str = ""
    edition: str = ""
    features: frozenset[str] = field(default_factory=frozenset)


def issue(keyring: AgentKeyring, customer: str, edition: str, features: list[str] | set[str],
          *, expires_at: float | None = None, issued_at: float | None = None) -> dict:
    """Vendor-side: sign a new license. ``keyring`` must hold the private ``vendor`` key — never
    ship it to a customer; only ``verify``'s public-key bundle does."""
    if not (_valid_name(customer) and _valid_name(edition) and all(_valid_name(f) for f in features)):
        raise ValueError("customer, edition and every feature must be plain names")
    if expires_at is not None and not _valid_time(expires_at):
        raise ValueError("expires_at must be a epoch-seconds number")
    kid = keyring.kid(VENDOR)
    core = {"customer": customer, "edition": edition, "features": sorted(set(features)),
           "issued_at": round(issued_at if issued_at is not None else time.time(), 3),
           "expires_at": expires_at, "kid": kid}
    signature = keyring.sign(VENDOR, canonical(core), LICENSE_CONTEXT, kid=kid)
    return {**core, "sig": signature.ed25519, **({"pqsig": signature.mldsa65} if signature.mldsa65 else {})}


def _well_formed(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    fields = set(data)
    if fields not in ({*_CORE_FIELDS, "sig"}, {*_CORE_FIELDS, "sig", "pqsig"}):
        return False
    return (_valid_name(data["customer"]) and _valid_name(data["edition"])
            and isinstance(data["features"], list) and len(data["features"]) <= 1000
            and all(_valid_name(f) for f in data["features"])
            and _valid_time(data["issued_at"]) and (data["expires_at"] is None or _valid_time(data["expires_at"]))
            and is_hex("kid", data["kid"]) and is_hex("sig", data["sig"])
            and ("pqsig" not in data or is_hex("pqsig", data["pqsig"])))


def verify(license: dict, public_keys: dict, *, require_pq: bool = False, now: float | None = None) -> LicenseResult:
    """Customer-side: check a license against the vendor's pinned ``public_keys`` (``AgentKeyring.public_keys()``
    shape — ``{"vendor": {kid: public}}``), read from somewhere the vendor cannot silently change after the
    fact. Never trusts the license's own claims: malformed input, an unknown key, a bad signature or an expired
    license are all failures, never exceptions."""
    if not _well_formed(license):
        return LicenseResult(False, reason="malformed license")
    public = public_keys.get(VENDOR, {}).get(license["kid"])
    if public is None:
        return LicenseResult(False, reason="unknown signing key")
    core = {k: license[k] for k in _CORE_FIELDS}
    message = canonical(core)
    public_ed = public if isinstance(public, str) else public.get("ed25519", "")
    if not verify_signature(public_ed, message, license["sig"]):
        return LicenseResult(False, reason="signature does not verify")
    has_pq = isinstance(public, dict) and "mldsa65" in public
    if "pqsig" in license or require_pq:
        if "pqsig" not in license or not has_pq:
            return LicenseResult(False, reason="post-quantum signature required but missing")
        if not verify_pq(public["mldsa65"], message, license["pqsig"], LICENSE_CONTEXT):
            return LicenseResult(False, reason="post-quantum signature does not verify")
    features = frozenset(license["features"])
    if license["expires_at"] is not None and (now if now is not None else time.time()) > license["expires_at"]:
        return LicenseResult(False, reason="license expired", expired=True,
                             customer=license["customer"], edition=license["edition"], features=features)
    return LicenseResult(True, customer=license["customer"], edition=license["edition"], features=features)


def entitled(license: dict, public_keys: dict, feature: str, **kwargs) -> bool:
    """One-line gate for a feature check: True only for a license that verifies, is not expired, and names it."""
    result = verify(license, public_keys, **kwargs)
    return result.ok and feature in result.features
