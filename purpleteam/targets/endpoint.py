"""A Target for any agent product that takes a message over HTTP: an n8n webhook, a chat API, a service.

You give the URL and the JSON field that carries the message; the reply is read from a field of the
answer. The product's tool calls come from the gateway observer, because its model traffic passes through
the gateway, so no code of the product is touched and no framework is assumed.

The endpoint, headers and body are the operator's, so this talks only to what the operator names. Headers
may hold credentials and are never logged or reported. Attacks run one at a time, and each request carries a
nonce: a call whose conversation never held it is marked not attributed and the verdict says so. By default
such calls are kept (a multi-agent product may rewrite the message before a later agent sees it, and
dropping its calls would hide a breach); set ``strict`` on a shared staging system to drop them, or
``tag_requests=False`` if the nonce disturbs the product (every call is then taken as ours).
"""

from __future__ import annotations

from secrets import token_hex
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx

from purpleteam.adapter import Observation
from purpleteam.gateway_observer import GatewayObserver


def _field(body: Any, path: str) -> Any:
    for part in path.split("."):
        body = body.get(part) if isinstance(body, dict) else None
    return body


class HttpTarget:
    def __init__(self, name: str, url: str, observer: GatewayObserver, *, message_field: str = "message",
                 reply_field: str = "reply", headers: dict[str, str] | None = None,
                 extra: dict[str, Any] | None = None, reset: Callable[[], None] | None = None,
                 timeout: float = 300, client: httpx.Client | None = None,
                 tag_requests: bool = True, strict: bool = False) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("url must be an http(s) URL")
        self.name = name
        self._url, self._observer = url, observer
        self._message_field, self._reply_field = message_field, reply_field
        self._headers, self._extra, self._reset = dict(headers or {}), dict(extra or {}), reset
        self._client = client or httpx.Client(timeout=timeout)
        self._tag, self._strict = tag_requests, strict

    def reset(self) -> None:
        self._observer.drain()
        if self._reset:
            self._reset()

    def send(self, request: str) -> Observation:
        self._observer.drain()  # only calls made for this request count
        nonce = token_hex(8) if self._tag else None
        message = f"[ref {nonce}]\n\n{request}" if nonce else request  # in front, so the payload's own end is untouched
        response = self._client.post(self._url, json={**self._extra, self._message_field: message},
                                     headers=self._headers)
        try:
            reply = _field(response.json(), self._reply_field)
        except ValueError:
            reply = None
        calls = self._observer.drain(nonce)
        if self._strict:
            calls = [c for c in calls if c.attributed]
        return Observation(str(reply) if reply is not None else response.text, calls, response.status_code)
