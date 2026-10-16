"""A model gateway that lets the platform watch any agent product's model traffic.

Point the target's model base URL at this service and give it a ``target`` key (see ``gateway_keys``) as its
API key, in whichever header its SDK uses (``Authorization: Bearer``, ``x-api-key`` or ``x-goog-api-key``). The
gateway checks the key, forwards the request to the real provider with *our* upstream key (the target never
holds it), returns the provider's answer unchanged and tells the observer what passed. Three provider formats
exist, each only when configured, so the gateway exposes nothing it was not asked to proxy:

    openai     POST /v1/chat/completions, GET /v1/models      (OpenAI, Azure OpenAI, Ollama, vLLM, LiteLLM...)
    anthropic  POST /v1/messages
    gemini     POST /v1beta/models/<model>:generateContent or :streamGenerateContent?alt=sse (and /v1/...)

``/profile`` (``admin`` key only) reports what was learned. The interactive docs are off.

Pass a ``ledger`` and every model decision is written to the signed audit ledger; pass a ``guard`` and each tool
call the model proposes is checked first and withdrawn if it fails (see ``gateway_policy``).

Security: keys are scoped, expiring, budgeted and rate limited; bodies are size-capped; the target's key and
other headers are never forwarded (only the API version headers Anthropic needs); the upstream key and request
bodies are never logged; provider errors are reduced to a generic 502; and streams pass through untouched
while their tool calls are rebuilt on the side. A stream that cannot be read that way is refused rather than
passed unobserved. A key must still be valid when an answer is released, not only when the request arrived: an answer whose key was
revoked or expired in the meantime is withheld whole (a stream is cut), so revoking a key stops work already in
flight. Observation can never fail a request: ``GatewayObserver.observe`` does not raise. Each
upstream key can be a function, so it can be fetched from the customer's secrets manager on each request.
``serve`` refuses to listen on a network address without TLS.
"""

from __future__ import annotations

import ipaddress
import json
import re
import ssl
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import SecretStr

from purpleteam.gateway_dialects import ANTHROPIC, GEMINI, OPENAI, Dialect
from purpleteam.gateway_keys import ADMIN, TARGET, AuthError, GatewayKeys
from purpleteam.gateway_observer import GatewayObserver
from purpleteam.gateway_policy import DecisionPoint, Guard, Refusal

AGENT_HEADER = "x-purpleteam-agent"
MAX_BODY = 4_000_000
_REFUSALS = {401: "unauthorized", 403: "this key cannot be used here", 429: "too many requests"}
_MODEL = re.compile(r"[A-Za-z0-9._-]{1,100}")
_ACTIONS = ("generateContent", "streamGenerateContent")
_PLAIN_HEADER = re.compile(r"[ -~]{1,200}")


@dataclass(frozen=True)
class Provider:
    base: str  # OpenAI: the URL ending in /v1; Anthropic and Gemini: the host, e.g. https://api.anthropic.com
    key: SecretStr | Callable[[], SecretStr]

    def __post_init__(self) -> None:
        parts = urlsplit(self.base)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("a provider base must be an http(s) URL such as https://api.openai.com/v1")

    @property
    def url(self) -> str:
        return self.base.rstrip("/")

    def secret(self) -> str:
        return (self.key() if callable(self.key) else self.key).get_secret_value()


async def _read_capped(request: Request) -> bytes:
    """The body, refused as soon as it passes the cap, whether or not the client declared its length."""
    declared = request.headers.get("content-length", "0")
    if declared.isdigit() and int(declared) > MAX_BODY:
        raise HTTPException(413, "request too large")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY:
            raise HTTPException(413, "request too large")
    return bytes(body)


async def _tee(upstream_response: httpx.Response, observer: GatewayObserver, decisions: DecisionPoint,
               dialect: Dialect, payload: dict, hint: str | None, model: str, identity: str | None,
               active: Callable[[], bool]):
    """Pass a streamed answer through untouched while rebuilding its tool calls; always release the upstream."""
    tap, cut = dialect.tap(), False
    try:
        async for chunk in upstream_response.aiter_raw():
            if not active():  # the key was revoked or expired mid-stream: send nothing more
                cut = True
                break
            tap.feed(chunk)
            yield chunk
    finally:
        await upstream_response.aclose()
        if cut:
            decisions.log_withheld(dialect, hint, model, identity, "key_inactive")
        elif tap.overflowed:
            observer.note("a streamed answer was too large to read its tool calls")
        else:
            try:
                decisions.process(dialect, payload, tap.response(), hint, model, identity)  # not reached when enforcing
            except Refusal:
                observer.note("a streamed decision could not be written to the audit log")


def create_gateway(observer: GatewayObserver, *, keys: GatewayKeys, openai: Provider | None = None,
                   anthropic: Provider | None = None, gemini: Provider | None = None,
                   client: httpx.AsyncClient | None = None, guard: Guard | None = None, ledger: Any = None,
                   redactor: Any = None, allow_native_tools: bool = False, fail_closed: bool = True) -> FastAPI:
    if not (openai or anthropic or gemini):
        raise ValueError("configure at least one provider")
    decisions = DecisionPoint(observer, guard=guard, ledger=ledger, redactor=redactor,
                              allow_native_tools=allow_native_tools, fail_closed=fail_closed)
    http = client or httpx.AsyncClient(timeout=300)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        if client is None:
            await http.aclose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def authorize(request: Request, role: str):
        """The key from whichever header the caller's SDK uses; refusals say nothing about why. The agent the key
        is bound to, if any, is kept on the request as its authenticated identity."""
        header = request.headers.get("authorization") or next(
            (f"Bearer {v}" for h in ("x-api-key", "x-goog-api-key") if (v := request.headers.get(h))), "")
        try:
            grant = keys.authenticate(header, role)
            request.state.agent, request.state.key_id = grant.agent, grant.key_id
            return grant
        except AuthError as error:
            raise HTTPException(error.status, _REFUSALS[error.status],
                                headers={"Retry-After": "60"} if error.status == 429 else None) from None

    async def forward(request: Request, dialect: Dialect, url: str, headers: dict[str, str],
                      streaming: bool | None = None, model: str | None = None) -> Response:
        raw = await _read_capped(request)
        try:
            payload = json.loads(raw)
        except (ValueError, RecursionError):
            raise HTTPException(400, "body must be JSON") from None
        if not isinstance(payload, dict):
            raise HTTPException(400, "body must be a JSON object")
        hint, identity = request.headers.get(AGENT_HEADER), getattr(request.state, "agent", None)
        key_id = getattr(request.state, "key_id", None)

        async def withhold_if_inactive(response: httpx.Response | None = None) -> None:
            """The key may have stopped being valid while the provider was thinking."""
            if not keys.is_active(key_id):
                if response is not None:
                    await response.aclose()
                await run_in_threadpool(decisions.log_withheld, dialect, hint, model, identity, "key_inactive")
                raise HTTPException(401, _REFUSALS[401])

        streaming = payload.get("stream") is True if streaming is None else streaming
        model = model if model is not None else (payload["model"] if isinstance(payload.get("model"), str) else "")
        try:
            decisions.check_request(dialect, payload, streaming)
        except Refusal as refusal:
            raise HTTPException(refusal.status, refusal.message) from None
        try:
            if streaming:
                upstream_response = await http.send(http.build_request("POST", url, content=raw, headers=headers),
                                                    stream=True)
                await withhold_if_inactive(upstream_response)
                observer.observe(payload, None, hint, dialect, identity)
                return StreamingResponse(_tee(upstream_response, observer, decisions, dialect, payload, hint, model,
                                              identity, lambda: keys.is_active(key_id)),
                                         status_code=upstream_response.status_code,
                                         media_type=upstream_response.headers.get("content-type"))
            upstream_response = await http.post(url, content=raw, headers=headers)
        except httpx.HTTPError:
            raise HTTPException(502, "the model provider could not be reached") from None
        await withhold_if_inactive()
        try:
            answer = upstream_response.json()
        except (ValueError, RecursionError):
            answer = None
        if isinstance(answer, dict) and upstream_response.status_code < 400:
            try:
                replacement = await run_in_threadpool(decisions.process, dialect, payload, answer, hint, model, identity)
            except Refusal as refusal:
                raise HTTPException(refusal.status, refusal.message) from None
            if replacement is not None:
                return JSONResponse(replacement, status_code=upstream_response.status_code)
        else:
            observer.observe(payload, None, hint, dialect, identity)
        return Response(upstream_response.content, status_code=upstream_response.status_code,
                        media_type=upstream_response.headers.get("content-type"))

    if openai:
        def openai_headers() -> dict[str, str]:
            return {"authorization": f"Bearer {openai.secret()}", "content-type": "application/json"}

        @app.post("/v1/chat/completions")
        async def chat(request: Request) -> Response:
            authorize(request, TARGET)
            return await forward(request, OPENAI, f"{openai.url}/chat/completions", openai_headers())

    if anthropic:
        @app.post("/v1/messages")
        async def messages(request: Request) -> Response:
            authorize(request, TARGET)
            headers = {"x-api-key": anthropic.secret(), "content-type": "application/json",
                       "anthropic-version": request.headers.get("anthropic-version", "2023-06-01")}
            beta = request.headers.get("anthropic-beta", "")
            if _PLAIN_HEADER.fullmatch(beta):
                headers["anthropic-beta"] = beta
            if not _PLAIN_HEADER.fullmatch(headers["anthropic-version"]):
                raise HTTPException(400, "unreadable anthropic-version")
            return await forward(request, ANTHROPIC, f"{anthropic.url}/v1/messages", headers)

    if gemini:
        async def generate(request: Request, version: str, target: str) -> Response:
            authorize(request, TARGET)
            model, _, action = target.partition(":")
            if not _MODEL.fullmatch(model) or action not in _ACTIONS:
                raise HTTPException(404, "not found")
            streaming = action == "streamGenerateContent"
            if streaming and request.query_params.get("alt") != "sse":  # any other stream shape could not be read
                raise HTTPException(400, "streaming needs alt=sse so that tool calls can be observed")
            url = f"{gemini.url}/{version}/models/{model}:{action}" + ("?alt=sse" if streaming else "")
            headers = {"x-goog-api-key": gemini.secret(), "content-type": "application/json"}
            return await forward(request, GEMINI, url, headers, streaming, model)

        @app.post("/v1beta/models/{target}")
        async def generate_beta(request: Request, target: str) -> Response:
            return await generate(request, "v1beta", target)

        @app.post("/v1/models/{target}")
        async def generate_stable(request: Request, target: str) -> Response:
            return await generate(request, "v1", target)

    listing = openai or anthropic
    if listing:
        @app.get("/v1/models")
        async def models(request: Request) -> Response:
            authorize(request, TARGET)
            headers = ({"authorization": f"Bearer {openai.secret()}"} if openai else
                       {"x-api-key": anthropic.secret(), "anthropic-version": "2023-06-01"})
            url = f"{listing.url}/models" if openai else f"{listing.url}/v1/models"
            try:
                upstream_response = await http.get(url, headers=headers)
            except httpx.HTTPError:
                raise HTTPException(502, "the model provider could not be reached") from None
            return Response(upstream_response.content, status_code=upstream_response.status_code,
                            media_type=upstream_response.headers.get("content-type"))

    @app.get("/profile")
    async def profile(request: Request) -> dict:
        authorize(request, ADMIN)
        return observer.summary()

    return app


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
