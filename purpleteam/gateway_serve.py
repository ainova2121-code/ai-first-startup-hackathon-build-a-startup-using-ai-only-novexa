"""Serving the gateway: plain HTTP only on loopback (behind a TLS proxy on the same machine), TLS everywhere
else, and optionally mutual TLS for every caller."""

from __future__ import annotations

import ipaddress
import ssl

from fastapi import FastAPI


def check_binding(host: str, certfile: str | None, keyfile: str | None, client_ca: str | None) -> None:
    """Plain HTTP is allowed only on loopback (behind a TLS proxy on the same machine); anything else needs TLS."""
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if bool(certfile) != bool(keyfile):
        raise ValueError("certfile and keyfile go together")
    if client_ca and not certfile:
        raise ValueError("client certificates (mutual TLS) need TLS: pass certfile and keyfile as well")
    if not certfile and not loopback:
        raise ValueError(f"refusing to listen on {host} without TLS: pass certfile and keyfile, "
                         "or bind 127.0.0.1 behind a TLS-terminating proxy")


def serve(app: FastAPI, *, host: str = "127.0.0.1", port: int = 8443, certfile: str | None = None,
          keyfile: str | None = None, client_ca: str | None = None) -> None:
    """Run the gateway. With ``client_ca`` every caller must also present a certificate that CA signed."""
    check_binding(host, certfile, keyfile, client_ca)
    import uvicorn

    uvicorn.run(app, host=host, port=port, ssl_certfile=certfile, ssl_keyfile=keyfile, ssl_ca_certs=client_ca,
                ssl_cert_reqs=ssl.CERT_REQUIRED if client_ca else ssl.CERT_NONE,
                access_log=False, server_header=False)
