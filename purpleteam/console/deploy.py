"""Generates the exact, paste-and-run self-host deployment for a new target's gateway.

Standing up a BYOC gateway normally means: run ``openssl rand -hex 32`` twice (redactor secret,
keyring passphrase), start the container, read its one-time bootstrap keys out of ``docker compose
logs``, then paste them back into this console by hand. Every one of those steps is something the
console itself can already do -- the bearer keys are plain random tokens (``gateway_keys.PREFIX``),
and nothing stops the console from minting them *before* the gateway's first boot instead of after.

So here, the console generates the admin and target keys itself, registers the admin key into its
own fleet registry immediately (the target starts out "unknown" until the first successful poll),
and hands back a single shell block with every secret already filled in. The gateway picks the same
two keys up via ``GATEWAY_BOOTSTRAP_ADMIN_KEY``/``GATEWAY_BOOTSTRAP_TARGET_KEY`` (see
``gateway_bootstrap.bootstrap_keys``) instead of minting its own -- so the moment the operator pastes
and runs this, the console is already able to poll it. The only thing nobody but the operator can
fill in is their own LLM provider's key, left as a placeholder on purpose: the platform never sees
a customer's provider credentials.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from purpleteam.gateway_keys import MAX_TTL, generate_token


@dataclass(frozen=True)
class DeployPlan:
    base_url: str
    admin_key: str   # also handed to FleetRegistry.add_target -- this is what polling uses
    target_key: str  # for the agent team's own LLM_API_KEY -- the console never stores this
    script: str       # paste-and-run: writes .env.gateway, then starts the gateway and its TLS proxy


def plan_deployment(domain: str) -> DeployPlan:
    """``domain`` is a bare host (``gateway.acme.example``, or ``localhost`` to try it locally) --
    the same value Caddy's automatic TLS needs, so what gets registered and what gets served can
    never silently drift apart."""
    admin_key, target_key = generate_token(), generate_token()
    redactor_secret = secrets.token_hex(32)
    script = f"""cat > .env.gateway <<'EOF'
GATEWAY_DOMAIN={domain}
GATEWAY_OPENAI_URL=https://api.openai.com/v1
GATEWAY_OPENAI_KEY=   # <-- paste your own LLM provider key here; the platform never sees this
GATEWAY_REDACTOR_SECRET={redactor_secret}
GATEWAY_BOOTSTRAP_ADMIN_KEY={admin_key}
GATEWAY_BOOTSTRAP_TARGET_KEY={target_key}
GATEWAY_BOOTSTRAP_TTL_SECONDS={MAX_TTL}
EOF
mkdir -p deploy/secrets && openssl rand -hex 32 > deploy/secrets/keyring_passphrase
docker compose up -d gateway tls"""
    return DeployPlan(f"https://{domain}", admin_key, target_key, script)
