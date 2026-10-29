"""Multipart-PDF target adapter for an operator-owned staging document-ingestion endpoint.

Each request uploads a generated PDF with a benign visible line and the attack payload in an
invisible text layer. Tool calls are taken from the gateway observer, not guessed from response
text. Configure this only for an endpoint and agent you are authorized to assess.
"""

from __future__ import annotations

from secrets import token_hex
from typing import Any
from urllib.parse import urlsplit

import httpx

from purpleteam.adapter import Observation
from purpleteam.attack.documents import invisible_text_pdf
from purpleteam.gateway_observer import GatewayObserver


def _field(body: Any, path: str) -> Any:
    value = body
    for part in path.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


class HttpDocumentTarget:
    """Upload one invisible-text PDF per test attempt to an agent's document-ingestion route."""

    def __init__(self, name: str, url: str, observer: GatewayObserver, *, file_field: str = "file",
                 filename: str = "review-document.pdf", trigger_field: str = "message",
                 trigger: str = "Please review the attached document and process the request.",
                 reply_field: str = "reply", form_fields: dict[str, str] | None = None,
                 headers: dict[str, str] | None = None, timeout: float = 300,
                 client: httpx.Client | None = None, tag_requests: bool = True,
                 visible_text: str = "Document received for review.") -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("url must be an http(s) URL")
        if not file_field:
            raise ValueError("file_field must not be empty")
        self.name, self._url, self._observer = name, url, observer
        self._file_field, self._filename = file_field, filename
        self._trigger_field, self._trigger, self._reply_field = trigger_field, trigger, reply_field
        self._form_fields, self._headers = dict(form_fields or {}), dict(headers or {})
        self._client = client or httpx.Client(timeout=timeout)
        self._tag, self._visible = tag_requests, visible_text

    def reset(self) -> None:
        self._observer.drain()

    def send(self, request: str) -> Observation:
        self._observer.drain()
        nonce = token_hex(8) if self._tag else None
        data = dict(self._form_fields)
        if self._trigger_field:
            data[self._trigger_field] = (f"[ref {nonce}]\n\n{self._trigger}" if nonce else self._trigger)
        artifact = invisible_text_pdf(request, visible_text=self._visible)
        response = self._client.post(
            self._url,
            data=data,
            files={self._file_field: (self._filename, artifact, "application/pdf")},
            headers=self._headers,
        )
        response.raise_for_status()  # failed uploads are inconclusive, never a successful hold
        try:
            body = response.json()
        except ValueError:
            body = None
        reply = _field(body, self._reply_field) if body is not None else None
        calls = self._observer.drain(nonce)
        return Observation(str(reply) if reply is not None else response.text, calls, response.status_code)
