"""The gateway's first-start keys: one admin and one target key, issued once (or pinned by a fleet console
before the first boot), short-lived and budgeted, so a leaked setup credential is worth little."""

from __future__ import annotations

import os
import sys

from purpleteam.gateway_keys import ADMIN, TARGET, GatewayKeys

# Deliberately modest, not "the maximum GatewayKeys allows": these keys are printed to stderr once
# (log collection could retain them) and the target key is unbound to any one agent (unavoidable —
# multi-agent discovery needs one shared credential to see every agent's traffic before any of them
# have a separate identity). Short TTL and a bounded budget limit what a leaked bootstrap key is
# worth; mint per-agent keys once discovery has run and stop using these.
BOOTSTRAP_TTL = 24 * 3600
BOOTSTRAP_BUDGET = {"max_requests": 50_000, "per_minute": 600}


def bootstrap_keys(keys: GatewayKeys, *, persisted: bool) -> None:
    """Issuing a bootstrap key is meant as a one-time setup step, not something to repeat on
    every restart: with a persistent store, a still-valid pair from an earlier run is left alone
    (and not reprinted — the secret was only ever shown once) rather than minting an unbounded
    pile of bootstrap credentials that all stay valid at once.

    ``GATEWAY_BOOTSTRAP_ADMIN_KEY``/``GATEWAY_BOOTSTRAP_TARGET_KEY`` pin these to exact values
    instead of minting a random pair — a fleet console generates and registers both *before* this
    gateway's first boot (see ``purpleteam.console.deploy``), so there is nothing to copy out of a
    log here; both or neither must be set, since a console that pins one already knows the other too."""
    if persisted and keys.has_active_label("bootstrap-admin") and keys.has_active_label("bootstrap-target"):
        print("purpleteam gateway: existing bootstrap keys (persisted) are still valid — not "
             "issuing new ones. Mint and switch to real, per-agent keys, or delete the key store "
             "to force a fresh bootstrap pair.", file=sys.stderr)
        return
    admin_token = os.environ.get("GATEWAY_BOOTSTRAP_ADMIN_KEY")
    target_token = os.environ.get("GATEWAY_BOOTSTRAP_TARGET_KEY")
    if bool(admin_token) != bool(target_token):
        raise RuntimeError(
            "set both GATEWAY_BOOTSTRAP_ADMIN_KEY and GATEWAY_BOOTSTRAP_TARGET_KEY, or neither — a fleet "
            "console that pins one already pins the other, so it knows what to poll with the moment this "
            "gateway starts.")
    ttl = float(os.environ.get("GATEWAY_BOOTSTRAP_TTL_SECONDS", BOOTSTRAP_TTL))
    budget = {"max_requests": int(os.environ.get("GATEWAY_BOOTSTRAP_MAX_REQUESTS", BOOTSTRAP_BUDGET["max_requests"])),
             "per_minute": int(os.environ.get("GATEWAY_BOOTSTRAP_PER_MINUTE", BOOTSTRAP_BUDGET["per_minute"]))}
    admin = keys.issue("bootstrap-admin", ADMIN, ttl_seconds=ttl, token=admin_token, **budget)
    target = keys.issue("bootstrap-target", TARGET, ttl_seconds=ttl, token=target_token, **budget)
    if admin_token:
        print("purpleteam gateway: bootstrap keys pinned from GATEWAY_BOOTSTRAP_ADMIN_KEY/"
             "GATEWAY_BOOTSTRAP_TARGET_KEY — a fleet console generated these before this gateway ever "
             "started, so there is nothing new to copy here.", file=sys.stderr)
        return
    survive = "survive a restart (GATEWAY_KEYS_FILE is set)" if persisted else "do not survive a restart"
    print(f"purpleteam gateway: bootstrap keys issued (shown once; expire in {ttl:.0f}s; {survive}). "
         "The target key is unbound to any one agent — that is required for multi-agent discovery "
         "to see every agent's traffic, not a mistake — so treat it as a setup credential: mint "
         "per-agent keys once discovery has run, and stop using this one. A log collector that "
         "retains stderr will retain these; rotate promptly.", file=sys.stderr)
    print(f"  admin key:  {admin}", file=sys.stderr)
    print(f"  target key: {target}", file=sys.stderr)
