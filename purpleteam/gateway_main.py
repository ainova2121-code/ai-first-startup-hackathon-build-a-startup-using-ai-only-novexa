"""Production entry point for the LLM gateway: ``uvicorn --factory purpleteam.gateway_main:app``.

Configured entirely from the environment (see ``_PROVIDER_ENV`` below), so the same container
image runs unmodified in any customer's BYOC cloud. At least one provider must be configured.

Known limitation, not papered over: ``GatewayKeys`` is in-memory only (see its own docstring) —
a restart invalidates every issued key. On startup this issues one bootstrap admin key and one
bootstrap target key and prints them once, clearly marked, to stderr. A real multi-replica or
frequently-restarted deployment needs a persistent key store "behind the same interface" (that
store does not exist yet); for a single long-lived instance this is workable, not ideal.

No guard is attached by default (observe-only: traffic is profiled and logged, nothing is
blocked) — enforcement needs a Guard built from a completed assessment's findings, which is a
deployment-specific wiring decision, not something this entry point can decide on its own.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx
from pydantic import SecretStr

from purpleteam.audit.ledger import AuditLedger
from purpleteam.audit.privacy import Redactor
from purpleteam.gateway import Provider, create_gateway
from purpleteam.gateway_keys import ADMIN, TARGET, GatewayKeys
from purpleteam.gateway_observer import GatewayObserver

_PROVIDER_ENV = {"openai": "OPENAI", "anthropic": "ANTHROPIC", "gemini": "GEMINI"}
_BOOTSTRAP_TTL = 30 * 24 * 3600  # the maximum GatewayKeys allows; reissue before this, not after
_BOOTSTRAP_BUDGET = {"max_requests": 10_000_000, "per_minute": 6000}


def _provider(name: str) -> Provider | None:
    url = os.environ.get(f"GATEWAY_{name}_URL")
    key = os.environ.get(f"GATEWAY_{name}_KEY")
    if not (url and key):
        return None
    return Provider(url, SecretStr(key))


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


def _bootstrap_keys(keys: GatewayKeys) -> None:
    admin = keys.issue("bootstrap-admin", ADMIN, ttl_seconds=_BOOTSTRAP_TTL, **_BOOTSTRAP_BUDGET)
    target = keys.issue("bootstrap-target", TARGET, ttl_seconds=_BOOTSTRAP_TTL, **_BOOTSTRAP_BUDGET)
    print("purpleteam gateway: bootstrap keys issued (shown once; GatewayKeys is in-memory, "
         "these do not survive a restart)", file=sys.stderr)
    print(f"  admin key:  {admin}", file=sys.stderr)
    print(f"  target key: {target}", file=sys.stderr)


def build_app():
    providers = {name: _provider(env) for name, env in _PROVIDER_ENV.items()}
    if not any(providers.values()):
        raise RuntimeError("configure at least one provider: set GATEWAY_OPENAI_URL/_KEY (or "
                           "ANTHROPIC/GEMINI)")
    observer = GatewayObserver()
    keys = GatewayKeys()
    _bootstrap_keys(keys)
    secret = os.environ.get("GATEWAY_REDACTOR_SECRET")
    if not secret:
        print("purpleteam gateway: GATEWAY_REDACTOR_SECRET is not set — sensitive values (bank "
             "accounts, emails...) will be logged in the clear. Set a long random secret to log "
             "only keyed commitments instead.", file=sys.stderr)
    redactor = Redactor(secret.encode("utf-8")) if secret else None
    ledger_path = os.environ.get("GATEWAY_LEDGER_PATH")
    ledger = AuditLedger(Path(ledger_path), redactor=redactor) if ledger_path else None
    return create_gateway(
        observer, keys=keys, **providers, client=httpx.AsyncClient(timeout=300),
        fail_closed=_bool("GATEWAY_FAIL_CLOSED", True),
        allow_native_tools=_bool("GATEWAY_ALLOW_NATIVE_TOOLS", False), ledger=ledger, redactor=redactor)


def app() -> object:
    """``uvicorn --factory purpleteam.gateway_main:app``: uvicorn calls this to get the ASGI app."""
    return build_app()
