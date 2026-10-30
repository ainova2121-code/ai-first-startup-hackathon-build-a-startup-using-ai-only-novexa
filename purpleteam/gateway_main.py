"""Production entry point for the LLM gateway: ``uvicorn --factory purpleteam.gateway_main:app``.

Configured entirely from the environment (see ``_PROVIDER_ENV`` below), so the same container
image runs unmodified in any customer's BYOC cloud. At least one provider must be configured.

The audit ledger's own signing identity is production-hardened (see ``gateway_crypto``): a
persisted, passphrase-encrypted keyring by default rather than an ephemeral one, an optional
hardware-backed checkpoint signer, and a pinned checkpoint — kept fresh while the gateway runs,
not only taken once at startup — so a restart refuses to resume a log that was truncated or
rewritten while the gateway was down.

``GatewayKeys`` (the bearer tokens that authenticate *requests* to the gateway — a different thing
from the ledger's own signing keys above) is in-memory unless ``GATEWAY_KEYS_FILE`` is set, in
which case issued keys (and revocations) persist to that file and reload on restart — only what
proves a credential is still the same one; never the secret, never its spent budget or rate-limit
state, which starts fresh every time, same as before this existed. Without it, a restart still
invalidates every issued key, which is workable for a single short-lived instance but not for
anything meant to run continuously. A multi-replica deployment needs a shared backend (Redis, a
database) implementing ``gateway_keys.KeyStore``'s three methods instead of ``FileKeyStore``.
Either way, this entry point issues one bootstrap admin key and one bootstrap target key on every
startup and prints them once, clearly marked, to stderr — persistence does not change that; mint
and switch to real, scoped keys once the gateway is reachable.

No guard is attached by default (observe-only: traffic is profiled and logged, nothing is
blocked). ``GATEWAY_ENFORCE=true`` turns enforcement on, loading the guard from
``GATEWAY_POLICY_FILE`` — a policy a human signed and saved after reviewing a completed
assessment's findings and defense (``purpleteam.defender.policy.save_policy``) — and verified
against ``GATEWAY_POLICY_TRUST_FILE``, the approver's public key, pinned separately from the
policy file itself so editing one never lets you edit the other; this entry point never decides
what to enforce on its own. Without both, or if the policy fails to verify, ``GATEWAY_ENFORCE=true``
refuses to start rather than silently running observe-only — or on a tampered policy — under a
name that implies otherwise. ``GATEWAY_FAIL_CLOSED`` is a different, narrower setting: it governs
what happens if an audit-log *write* fails, never whether an unsafe tool call is blocked —
conflating the two is exactly the mistake ``GATEWAY_ENFORCE`` exists to make impossible. Leave
``GATEWAY_ENFORCE`` unset (the default) to run observe-only on purpose.

``GATEWAY_DECISION_BASELINE`` (with ``GATEWAY_DECISION_DIGEST``, the digest a run's signed ledger pinned it
by) adds policy-decision drift to that start-up check: every decision the last approved policy made is
replayed through the policy about to be enforced, and the gateway refuses to start if any decision it
made against verified attack input (or any redaction) would now be looser — see ``purpleteam.decisions``.

``GATEWAY_LIVE_CONTAINMENT=true`` (needs ``GATEWAY_ENFORCE=true`` with a policy that declares a
manifest) turns on automatic, proof-gated narrowing on top of that signed policy — see
``purpleteam.gateway_containment``: a proven block escalates to denying the specific tool, or
revoking the agent's bearer key outright for a repeat offender or an identity-level breach, signed
into the ledger as it happens. It only ever tightens what the policy already allows, never grants
anything beyond it, and forgets its own escalations on restart (the policy and keyring do not).
Off by default, the same deliberate opt-in as ``GATEWAY_ENFORCE`` itself.

``GATEWAY_DEBUG_REASONING_PATH`` turns on a different, narrower trade-off: full, unredacted model
reasoning/thinking text (see ``gateway_dialects.Exchange.reasoning``) written as plain JSON lines to
that local file — never to the signed ledger, which holds no raw data by design (see
``gateway_policy`` and ``gateway_debug.ReasoningDebugLog``). Unset (the default), no reasoning text
is written anywhere. This is a debugging aid, not an audit artifact: the file is unsigned, not
tamper-evident, and meant to be deleted when you are done with it.

``GATEWAY_HARDWARE_SIGNING=required`` without ``GATEWAY_LEDGER_PATH`` (and a persistent keyring
and trust file) refuses to start too: the hardware signer is only ever reached through a checkpoint
the ledger takes, so "required" would otherwise start up having silently never touched hardware
signing at all — the opposite of what "required" promises.

This process itself speaks plain HTTP (see the container's ``uvicorn`` command); it has no way to
know, from inside, whether something in front of it (a load balancer, ingress, sidecar) terminates
TLS. ``app()`` — the actual entry point uvicorn loads — refuses to start unless
``GATEWAY_TLS_TERMINATED_UPSTREAM=true`` says that has been checked, because the alternative is
bearer keys and model traffic crossing the network in the clear by default. A deployment with no
such proxy should call ``purpleteam.gateway_serve.serve(...)`` directly with ``certfile``/``keyfile``
instead, which terminates TLS itself and enforces the same thing (``check_binding``).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Callable

import httpx
from pydantic import SecretStr

from purpleteam.audit.ledger import AuditLedger, LedgerCorrupt
from purpleteam.audit.privacy import Redactor
from purpleteam.decisions import require_no_loosening
from purpleteam.defender.policy import LoadedPolicy, load_guard
from purpleteam.gateway import Provider, create_gateway
from purpleteam.gateway_bootstrap import bootstrap_keys
from purpleteam.gateway_containment import LiveContainment
from purpleteam.gateway_crypto import (
    RepinningLedger, check_unpinned_history, hardware, keyring, pinned_trust, save_trust)
from purpleteam.gateway_debug import ReasoningDebugLog
from purpleteam.gateway_keys import FileKeyStore, GatewayKeys
from purpleteam.gateway_observer import GatewayObserver
from purpleteam.oversight import ReviewQueue

_PROVIDER_ENV = {"openai": "OPENAI", "anthropic": "ANTHROPIC", "gemini": "GEMINI"}
KEYS_ACTOR = "gateway_keys"



def _provider(name: str) -> Provider | None:
    url = os.environ.get(f"GATEWAY_{name}_URL")
    key = os.environ.get(f"GATEWAY_{name}_KEY")
    if not (url and key):
        return None
    return Provider(url, SecretStr(key))


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


def _policy_public_keys() -> dict:
    """The approver's pinned ``{kid: public key}`` for the policy's ``"defender"`` actor —
    deliberately a separate file from the policy itself, and never the gateway's own keyring,
    which has no business approving its own enforcement. Without it, GATEWAY_ENFORCE has no way
    to tell an approved policy from an edited one, so it refuses rather than trust either blindly."""
    trust_path = os.environ.get("GATEWAY_POLICY_TRUST_FILE")
    if not trust_path:
        raise RuntimeError(
            "GATEWAY_ENFORCE=true but GATEWAY_POLICY_TRUST_FILE is not set — enforcement needs to "
            "know which key is allowed to approve a policy. Point it at a JSON file holding the "
            "approver's public key(s) (an AgentKeyring.public_keys()['defender'] dump), pinned "
            "separately from the policy file so editing one does not let you edit the other.")
    try:
        data = json.loads(Path(trust_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"GATEWAY_POLICY_TRUST_FILE at {trust_path} could not be read "
                           f"({type(error).__name__}: {error})") from error
    if not isinstance(data, dict):
        raise RuntimeError(f"GATEWAY_POLICY_TRUST_FILE at {trust_path} does not hold the expected object")
    return data


def _review_queue() -> ReviewQueue | None:
    """``GATEWAY_REVIEW_QUEUE_FILE``, when set, is where every P4 hold/approval/rejection this
    gateway's loaded policy produces is durably recorded, so a restart never forgets a pending or
    already-decided human review. ``GATEWAY_REVIEW_AUTHORIZED`` (comma-separated), when set,
    restricts who may actually approve or reject one. Left unset, P4 still works but only for the
    life of this process — the same opt-in posture every other persistence knob here already
    takes (GATEWAY_KEYS_FILE, GATEWAY_LEDGER_PATH...)."""
    path = os.environ.get("GATEWAY_REVIEW_QUEUE_FILE")
    if not path:
        return None
    authorized = os.environ.get("GATEWAY_REVIEW_AUTHORIZED")
    reviewers = {name.strip() for name in authorized.split(",") if name.strip()} if authorized else None
    return ReviewQueue(Path(path), authorized_reviewers=reviewers)


def _policy() -> LoadedPolicy | None:
    """None when enforcement is off (observe-only, the default). ``GATEWAY_ENFORCE=true`` needs
    ``GATEWAY_POLICY_FILE`` naming a saved, signed, human-reviewed defender policy (see
    ``purpleteam.defender.policy.save_policy``) and ``GATEWAY_POLICY_TRUST_FILE`` naming who was
    trusted to approve it, and refuses to start if either is missing or the policy fails to load
    or verify — enforcement must never silently fall back to observe-only under a name that
    implies otherwise. ``GATEWAY_FAIL_CLOSED`` is unrelated: it governs audit-log write failures,
    not whether an unsafe tool call is blocked."""
    if not _bool("GATEWAY_ENFORCE", False):
        return None
    policy_path = os.environ.get("GATEWAY_POLICY_FILE")
    if not policy_path:
        raise RuntimeError(
            "GATEWAY_ENFORCE=true but GATEWAY_POLICY_FILE is not set — enforcement needs a saved, "
            "human-reviewed defender policy to load (purpleteam.defender.policy.save_policy). "
            "Leave GATEWAY_ENFORCE unset to run observe-only on purpose (the default).")
    public_keys = _policy_public_keys()
    secrets_key = os.environ.get("GATEWAY_POLICY_SECRETS_KEY")
    try:
        loaded = load_guard(Path(policy_path), public_keys, review_queue=_review_queue(), secrets_key=secrets_key)
        baseline_path = os.environ.get("GATEWAY_DECISION_BASELINE")
        if baseline_path:  # a fresh, queue-less copy per decision, so no replay touches live review state
            require_no_loosening(json.loads(Path(baseline_path).read_text(encoding="utf-8")),
                                 os.environ.get("GATEWAY_DECISION_DIGEST", ""),
                                 lambda: load_guard(Path(policy_path), public_keys, secrets_key=secrets_key).guard)
        return loaded
    except Exception as error:
        raise RuntimeError(
            f"GATEWAY_ENFORCE=true but the policy at {policy_path} could not be loaded "
            f"({type(error).__name__}: {error}) — refusing to start rather than run observe-only "
            "under a name that implies enforcement is on.") from error



def _ledger(redactor) -> AuditLedger | RepinningLedger | None:
    ledger_path = os.environ.get("GATEWAY_LEDGER_PATH")
    if not ledger_path:
        return None
    trust_path_env = os.environ.get("GATEWAY_TRUST_FILE")
    trust_path = Path(trust_path_env) if trust_path_env else None
    if trust_path is not None and not os.environ.get("GATEWAY_KEYRING_DIR"):
        raise RuntimeError(
            "GATEWAY_TRUST_FILE is set but GATEWAY_KEYRING_DIR is not — pinning a checkpoint signed "
            "by an in-memory identity is pointless: the next restart mints a brand new identity, "
            "the pinned checkpoint's signature no longer verifies against it, and a perfectly clean "
            "log then looks tampered. Set GATEWAY_KEYRING_DIR (and a passphrase) or drop GATEWAY_TRUST_FILE.")
    pinned_checkpoint, pinned_hardware = pinned_trust(trust_path)
    try:
        ledger = AuditLedger(Path(ledger_path), keyring=keyring(), redactor=redactor, hardware=hardware(),
                             pinned_checkpoint=pinned_checkpoint, pinned_hardware=pinned_hardware)
    except LedgerCorrupt as error:
        raise RuntimeError(
            f"refusing to start: the audit ledger at {ledger_path} does not match its pinned "
            f"checkpoint ({error}) — it may have been truncated or rewritten while this gateway "
            "was not running") from error
    check_unpinned_history(trust_path, pinned_checkpoint, ledger.count(), ledger_path)
    if ledger.count() > 0:  # an empty log has no durable identity yet (see gateway_crypto.save_trust);
        save_trust(trust_path, ledger.export_trust())  # pinning it would just invent a phantom one
    if trust_path is None:
        return ledger
    # Keep the pin fresh for as long as the gateway runs — a pin taken only once at startup would
    # otherwise protect nothing appended during this run by the time of the next restart.
    return RepinningLedger(ledger, trust_path, every=int(os.environ.get("GATEWAY_TRUST_REPIN_EVERY", 100)),
                          seconds=float(os.environ.get("GATEWAY_TRUST_REPIN_SECONDS", 300)))


def _key_audit(ledger) -> Callable[[str, dict], None] | None:
    """Every key issued or revoked and every refused request, signed into the audit ledger under its own actor
    (``GatewayKeys`` already holds back floods and never passes a secret); None when there is no ledger."""
    if ledger is None:
        return None
    return lambda kind, payload: ledger.append(KEYS_ACTOR, kind, payload)


def build_app():
    providers = {name: _provider(env) for name, env in _PROVIDER_ENV.items()}
    if not any(providers.values()):
        raise RuntimeError("configure at least one provider: set GATEWAY_OPENAI_URL/_KEY (or "
                           "ANTHROPIC/GEMINI)")
    policy = _policy()
    guard = policy.guard if policy is not None else None
    if os.environ.get("GATEWAY_HARDWARE_SIGNING") == "required":
        missing = [name for name in ("GATEWAY_LEDGER_PATH", "GATEWAY_KEYRING_DIR", "GATEWAY_TRUST_FILE")
                  if not os.environ.get(name)]
        if missing:
            raise RuntimeError(
                "GATEWAY_HARDWARE_SIGNING=required but " + ", ".join(missing) + " "
                + ("is" if len(missing) == 1 else "are") + " not set — the hardware signer is only ever "
                "used through a checkpoint the ledger takes, so 'required' without a ledger, a "
                "persistent keyring and a pinned trust file would start up having never touched "
                "hardware signing at all. Configure all three, or drop GATEWAY_HARDWARE_SIGNING=required.")
    secret = os.environ.get("GATEWAY_REDACTOR_SECRET")
    ledger_configured = bool(os.environ.get("GATEWAY_LEDGER_PATH"))
    if not secret:
        if ledger_configured and not _bool("GATEWAY_ALLOW_UNREDACTED_LEDGER", False):
            raise RuntimeError(
                "GATEWAY_LEDGER_PATH is set but GATEWAY_REDACTOR_SECRET is not — refusing to start: "
                "sensitive values (bank accounts, emails...) would be written in the clear into a "
                "durable, signed, append-only log. Set GATEWAY_REDACTOR_SECRET, or set "
                "GATEWAY_ALLOW_UNREDACTED_LEDGER=true once you have decided that risk is acceptable.")
        print("purpleteam gateway: GATEWAY_REDACTOR_SECRET is not set — sensitive values (bank "
             "accounts, emails...) will be logged in the clear. Set a long random secret to log "
             "only keyed commitments instead.", file=sys.stderr)
    redactor = Redactor(secret.encode("utf-8")) if secret else None
    ledger = _ledger(redactor)
    observer = GatewayObserver()
    keys_file = os.environ.get("GATEWAY_KEYS_FILE")
    keys = GatewayKeys(audit=_key_audit(ledger), store=FileKeyStore(keys_file) if keys_file else None)
    bootstrap_keys(keys, persisted=bool(keys_file))
    containment = None
    if _bool("GATEWAY_LIVE_CONTAINMENT", False):
        if policy is None or policy.manifest is None:
            raise RuntimeError(
                "GATEWAY_LIVE_CONTAINMENT=true needs an active, signed policy that declares a "
                "manifest (see purpleteam.defender.policy.save_policy) — containment only ever "
                "narrows what that manifest already allows, so without one there is nothing for it "
                "to narrow from. Set GATEWAY_ENFORCE=true with a policy that declares a manifest, "
                "or drop GATEWAY_LIVE_CONTAINMENT.")
        containment = LiveContainment(policy.manifest, keys)
    reasoning_debug_path = os.environ.get("GATEWAY_DEBUG_REASONING_PATH")
    reasoning_debug = None
    if reasoning_debug_path:
        print(f"purpleteam gateway: GATEWAY_DEBUG_REASONING_PATH is set — full, unredacted model "
             f"reasoning/thinking text will be written in the clear to {reasoning_debug_path}. This "
             "file is NOT the signed audit ledger: it is unsigned, not tamper-evident, and meant "
             "only for local debugging. Never point it at shared or long-lived storage.", file=sys.stderr)
        reasoning_debug = ReasoningDebugLog(Path(reasoning_debug_path))
    return create_gateway(
        observer, keys=keys, **providers, client=httpx.AsyncClient(timeout=300), guard=guard,
        fail_closed=_bool("GATEWAY_FAIL_CLOSED", True), containment=containment,
        allow_native_tools=_bool("GATEWAY_ALLOW_NATIVE_TOOLS", False), ledger=ledger, redactor=redactor,
        reasoning_debug=reasoning_debug)


def _check_transport() -> None:
    if _bool("GATEWAY_TLS_TERMINATED_UPSTREAM", False):
        return
    raise RuntimeError(
        "refusing to start: this process serves plain HTTP. Put a TLS-terminating load balancer, "
        "ingress or sidecar in front of it and set GATEWAY_TLS_TERMINATED_UPSTREAM=true once that "
        "is confirmed — otherwise bearer keys and model traffic cross the network in the clear by "
        "default. With no such proxy, call purpleteam.gateway_serve.serve(...) directly with certfile/"
        "keyfile instead, so this process terminates TLS itself.")


def app() -> object:
    """``uvicorn --factory purpleteam.gateway_main:app``: uvicorn calls this to get the ASGI app."""
    _check_transport()
    return build_app()
