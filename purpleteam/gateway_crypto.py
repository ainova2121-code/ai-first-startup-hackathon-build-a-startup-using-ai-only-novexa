"""Production cryptographic config for the gateway: a persisted signing keyring, an optional
hardware-backed checkpoint signer, and a pinned checkpoint — kept fresh while the gateway runs by
``RepinningLedger``, not just taken once at startup — so a restart refuses to resume a log that
was truncated or rewritten while the gateway was not running.

Every failure here is deliberately loud. A gateway that silently ran with an ephemeral signing
identity, or silently dropped hardware signing, or silently accepted a tampered log, would make
the audit trail's tamper-evidence claim false. None of that happens quietly.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from purpleteam.audit.hardware_signer import HardwareSigner, resolve_signer
from purpleteam.audit.keys import AgentKeyring

HARDWARE_POLICIES = ("off", "preferred", "required")
# "tpm" auto-detects a Windows TPM (resolve_signer's own default opener). "pkcs11" and "kms" are
# for Linux/macOS (or any OS with a KMS-reachable network): both signers already exist and are
# hardware-backed, they just needed a way to be selected here rather than only via code.
HARDWARE_BACKENDS = ("tpm", "pkcs11", "kms")


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


def passphrase() -> bytes:
    direct = os.environ.get("GATEWAY_KEYRING_PASSPHRASE")
    path = os.environ.get("GATEWAY_KEYRING_PASSPHRASE_FILE")
    if direct and path:
        raise RuntimeError("set only one of GATEWAY_KEYRING_PASSPHRASE or GATEWAY_KEYRING_PASSPHRASE_FILE")
    if path:
        return Path(path).read_bytes().strip()
    if direct:
        return direct.encode("utf-8")
    raise RuntimeError("GATEWAY_KEYRING_DIR is set but no passphrase was given — set "
                       "GATEWAY_KEYRING_PASSPHRASE_FILE (preferred: a secret mounted from your secrets "
                       "manager) or GATEWAY_KEYRING_PASSPHRASE")


def keyring() -> AgentKeyring:
    """A persisted, passphrase-encrypted signing keyring when GATEWAY_KEYRING_DIR is configured;
    otherwise an explicitly-flagged in-memory one. GATEWAY_REQUIRE_PERSISTENT_KEYS=true turns the
    missing-directory case into a startup failure instead of a warning."""
    directory = os.environ.get("GATEWAY_KEYRING_DIR")
    if not directory:
        if _bool("GATEWAY_REQUIRE_PERSISTENT_KEYS", False):
            raise RuntimeError("GATEWAY_REQUIRE_PERSISTENT_KEYS is set but GATEWAY_KEYRING_DIR is not — "
                               "refusing to start with an in-memory signing identity")
        print("purpleteam gateway: GATEWAY_KEYRING_DIR is not set — the audit trail's signing keys are "
             "in-memory. A restart generates a new identity; events signed before it will no longer "
             "verify against the new public keys. Set GATEWAY_KEYRING_DIR and a passphrase for production.",
             file=sys.stderr)
        return AgentKeyring()
    return AgentKeyring(directory, passphrase(),
                        allow_classical_history=_bool("GATEWAY_KEYRING_ALLOW_CLASSICAL_HISTORY", False))


def _pkcs11_pin():
    from pydantic import SecretStr

    direct = os.environ.get("GATEWAY_PKCS11_PIN")
    path = os.environ.get("GATEWAY_PKCS11_PIN_FILE")
    if direct and path:
        raise RuntimeError("set only one of GATEWAY_PKCS11_PIN or GATEWAY_PKCS11_PIN_FILE")
    if path:
        return SecretStr(Path(path).read_text(encoding="utf-8").strip())
    if direct:
        return SecretStr(direct)
    raise RuntimeError("GATEWAY_HARDWARE_BACKEND=pkcs11 needs a PIN: set GATEWAY_PKCS11_PIN_FILE "
                       "(preferred: a secret mounted from your secrets manager) or GATEWAY_PKCS11_PIN")


def _pkcs11_opener() -> HardwareSigner:
    """An HSM, YubiKey, SoftHSM (dev) or — fronted by tpm2-pkcs11 middleware — a Linux TPM: whatever
    PKCS#11 module the operator points this at. See audit.pkcs11.Pkcs11Signer."""
    from purpleteam.audit.pkcs11 import Pkcs11Signer

    module, token, key = (os.environ.get(f"GATEWAY_PKCS11_{part}") for part in ("MODULE", "TOKEN", "KEY"))
    if not (module and token and key):
        raise RuntimeError("GATEWAY_HARDWARE_BACKEND=pkcs11 needs GATEWAY_PKCS11_MODULE, "
                           "GATEWAY_PKCS11_TOKEN and GATEWAY_PKCS11_KEY")
    return Pkcs11Signer(module, token, key, _pkcs11_pin())


def _kms_opener() -> HardwareSigner:
    """AWS KMS, HSM-backed by AWS and reachable from any OS. Credentials come from the customer's
    own boto3 setup (instance role, profile...); nothing here reads or stores them."""
    from purpleteam.audit.kms_aws import AwsKmsSigner

    key = os.environ.get("GATEWAY_KMS_KEY")
    if not key:
        raise RuntimeError("GATEWAY_HARDWARE_BACKEND=kms needs GATEWAY_KMS_KEY (a key id, ARN or alias)")
    return AwsKmsSigner.from_boto3(key, region=os.environ.get("GATEWAY_KMS_REGION"))


_OPENERS = {"pkcs11": _pkcs11_opener, "kms": _kms_opener}


def hardware(resolve=resolve_signer) -> HardwareSigner | None:
    """A hardware-backed checkpoint signer under GATEWAY_HARDWARE_SIGNING's policy ("off" by
    default; "preferred" uses one if present; "required" refuses to start without one), from the
    backend GATEWAY_HARDWARE_BACKEND names ("tpm", the default, auto-detects a Windows TPM;
    "pkcs11" and "kms" need the config their own opener reads and raise loudly if it is missing —
    the operator asked for hardware signing, so a typo in its config is never read as "no hardware
    here"). ``resolve`` is injected so tests never touch real hardware — see
    audit.hardware_signer.resolve_signer."""
    policy = os.environ.get("GATEWAY_HARDWARE_SIGNING", "off")
    if policy not in HARDWARE_POLICIES:
        raise RuntimeError(f"GATEWAY_HARDWARE_SIGNING must be one of {', '.join(HARDWARE_POLICIES)}")
    backend = os.environ.get("GATEWAY_HARDWARE_BACKEND", "tpm")
    if backend not in HARDWARE_BACKENDS:
        raise RuntimeError(f"GATEWAY_HARDWARE_BACKEND must be one of {', '.join(HARDWARE_BACKENDS)}")
    name = os.environ.get("GATEWAY_HARDWARE_KEY_NAME", "gateway-checkpoint")
    opener = _OPENERS.get(backend)
    signer, note = resolve(policy, name, opener=opener) if opener is not None else resolve(policy, name)
    print(f"purpleteam gateway: {note}", file=sys.stderr)
    return signer


def pinned_trust(path: Path | None) -> tuple[dict | None, dict | None]:
    """(pinned_checkpoint, pinned_hardware) from a previously saved trust file, or (None, None)
    the first time there is nothing to pin against yet. A present but unreadable file (a crash
    mid-write before atomic replacement existed, disk corruption, tampering) fails loud rather
    than being read as "no pin yet" — that reading would quietly erase the very protection this
    file exists to provide."""
    if path is None or not path.exists():
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise RuntimeError(f"the pinned trust file at {path} is not readable JSON ({error}) — "
                           "it may be corrupt or tampered with; it must be fixed or removed by hand, "
                           "never silently treated as if no checkpoint had ever been pinned") from error
    if not isinstance(data, dict):
        raise RuntimeError(f"the pinned trust file at {path} does not hold the expected object")
    return data.get("checkpoint"), data.get("hardware")


def save_trust(path: Path | None, trust: dict) -> None:
    """Pin this run's checkpoint for the next restart to check the log against. Only a local,
    restart-to-restart defence — periodic external timestamp anchoring (purpleteam.audit.anchor)
    is the stronger, continuous protection for a log whose host could be compromised while live.

    Written atomically (a temp file, then an OS-level rename over the target): a process killed
    mid-write leaves either the old pin intact or the new one complete, never a half-written file
    that the next restart could fail to parse.

    Callers must only call this for a ledger that already holds at least one event
    (``ledger.count() > 0``): an empty ledger's checkpoint carries a log identity that exists only
    in memory, never written to disk, so pinning it would make the *next* real append — which
    mints its own, different identity — look like a different, tampered log on every later
    restart. There is nothing meaningful to protect in an empty log anyway."""
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f"{path.suffix}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(trust, indent=2), encoding="utf-8")
    os.replace(tmp, path)  # atomic on both POSIX and Windows: never a partially-written trust file


class RepinningLedger:
    """Wraps an ``AuditLedger`` so the pinned trust file catches up while the gateway keeps
    running, not only once at startup. Without this, a pin taken at boot only protects the
    sliver of the log that existed then: every event appended afterwards is still individually
    signature-checked on the next restart, but the checkpoint itself — the thing that would
    catch wholesale truncation or rewriting of everything appended since boot — stays frozen at
    its startup size for the gateway's entire uptime.

    Re-pins after ``every`` appends or ``seconds`` of wall time, whichever comes first, so a
    checkpoint — an O(log size) verification over the whole log — is never taken on every single
    request. Every other attribute (``count``, ``events``, ``verify``, ``export_trust``...)
    passes straight through to the wrapped ledger."""

    def __init__(self, ledger: Any, trust_path: Path, *, every: int = 100, seconds: float = 300.0,
                clock=time.monotonic) -> None:
        self._ledger, self._trust_path, self._every, self._seconds, self._clock = (
            ledger, trust_path, every, seconds, clock)
        self._since_pin, self._last_pin = 0, clock()

    def append(self, actor: str, kind: str, payload: dict) -> dict:
        event = self._ledger.append(actor, kind, payload)
        self._since_pin += 1
        now = self._clock()
        if self._since_pin >= self._every or now - self._last_pin >= self._seconds:
            save_trust(self._trust_path, self._ledger.export_trust())
            self._since_pin, self._last_pin = 0, now
        return event

    def __getattr__(self, name: str) -> Any:
        return getattr(self._ledger, name)
