"""Production entry point for the fleet console: uvicorn --factory purpleteam.console.main:app

Configured entirely from the environment, the same BYOC-friendly, refuse-rather-than-guess
posture gateway_main.py already takes for the gateway itself.
"""

from __future__ import annotations

import os
from pathlib import Path

from purpleteam.console.app import create_console


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


def build_app():
    db_path = os.environ.get("CONSOLE_DB_PATH")
    if not db_path:
        raise RuntimeError(
            "CONSOLE_DB_PATH is not set -- point it at a file path for the console's own SQLite store.")
    secret_key = os.environ.get("CONSOLE_SECRET_KEY")
    if not secret_key:
        raise RuntimeError(
            "CONSOLE_SECRET_KEY is not set -- refusing to start: this key encrypts every registered "
            "gateway's admin credential at rest. Set a long random secret (openssl rand -hex 32).")
    poll_seconds = float(os.environ.get("CONSOLE_POLL_SECONDS", 15))
    return create_console(Path(db_path), secret_key=secret_key, poll_seconds=poll_seconds)


def _check_transport() -> None:
    if _bool("CONSOLE_TLS_TERMINATED_UPSTREAM", False):
        return
    raise RuntimeError(
        "refusing to start: this process serves plain HTTP. Put a TLS-terminating load balancer, "
        "ingress or sidecar in front of it and set CONSOLE_TLS_TERMINATED_UPSTREAM=true once that "
        "is confirmed -- otherwise session cookies and gateway admin keys cross the network in the clear.")


def app() -> object:
    """``uvicorn --factory purpleteam.console.main:app``: uvicorn calls this to get the ASGI app."""
    _check_transport()
    return build_app()
