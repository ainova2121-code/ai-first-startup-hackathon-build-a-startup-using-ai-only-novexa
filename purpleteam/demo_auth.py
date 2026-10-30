"""Access-code login for the live demo, so it can sit behind a public URL (a tunnel, a VM).

One shared code (``DEMO_ACCESS_CODE``), compared in constant time. The right code earns an HttpOnly,
SameSite=Strict session cookie (Secure over HTTPS), signed with a key that lives only in this process, so a
restart signs everyone out. Routes need that cookie except for login and the fixed, synthetic attack-corpus
JSON endpoint, which is intentionally public. Wrong codes are counted per client address (the real one when a
local TLS proxy forwards it), and too many in a window lock only that client out, so no one can lock out everyone
else. The page echoes nothing a visitor typed.
"""

from __future__ import annotations

import hmac
import secrets
import time
from hashlib import sha256

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import SecretStr

COOKIE = "pt_session"
SESSION_SECONDS = 12 * 3600
MAX_FAILURES, WINDOW_SECONDS = 10, 600
MAX_TRACKED_CLIENTS = 10_000  # bounds the memory a flood of addresses can take
HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}
NOTICES = {"": "", "wrong": "That code is not right.", "locked": "Too many wrong codes; try again in a few minutes."}

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>purpleteam · sign in</title><style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0A0D13;color:#E6EDF3;font:15px system-ui,sans-serif}}
form{{width:min(360px,calc(100vw - 32px));padding:28px;border:1px solid #243041;border-radius:14px;background:#0F141C}}
h1{{font-size:20px;margin:0 0 6px}}p{{color:#8B98A9;margin:0 0 18px}}.bad{{color:#E25555;min-height:20px;margin:10px 0 0}}
input{{width:100%;box-sizing:border-box;padding:11px 12px;border-radius:8px;border:1px solid #243041;background:#131A24;color:#E6EDF3;font-size:15px}}
button{{width:100%;margin-top:12px;padding:11px;border:0;border-radius:8px;background:#3FB96B;color:#06120a;font-weight:700;cursor:pointer}}
</style></head><body><form method="post" action="/login"><h1>purpleteam</h1><p>Enter the access code for this demo.</p>
<input type="password" name="code" autocomplete="current-password" autofocus required aria-label="Access code">
<button type="submit">Sign in</button><div class="bad" role="alert">{notice}</div></form></body></html>"""


def install_login(app: FastAPI, access_code: SecretStr) -> None:
    key = secrets.token_bytes(32)
    failures: dict[str, list[float]] = {}  # client address -> times of its recent wrong codes

    def sign(expires: int, nonce: str) -> str:
        return hmac.new(key, f"{expires}.{nonce}".encode(), sha256).hexdigest()

    def valid(token: str | None) -> bool:
        try:
            expires, nonce, signature = (token or "").split(".")
            return int(expires) > time.time() and hmac.compare_digest(signature, sign(int(expires), nonce))
        except ValueError:
            return False

    def recent(client: str) -> list[float]:
        cutoff = time.time() - WINDOW_SECONDS
        for address in list(failures):  # forget wrong codes older than the window, and clients with none left
            failures[address] = [t for t in failures[address] if t > cutoff]
            if not failures[address]:
                del failures[address]
        return failures.get(client, [])

    def record_failure(client: str) -> None:
        if client in failures or len(failures) < MAX_TRACKED_CLIENTS:
            failures.setdefault(client, []).append(time.time())

    @app.middleware("http")
    async def require_session(request: Request, call_next) -> Response:
        public_dataset = request.method == "GET" and request.url.path == "/custom-dataset.json"
        if request.url.path == "/login" or public_dataset or valid(request.cookies.get(COOKIE)):
            response = await call_next(request)
        elif request.method == "GET" and request.url.path == "/":
            response = RedirectResponse("/login", 303)
        else:
            response = JSONResponse({"detail": "sign in first"}, 401)
        response.headers.update(HEADERS)
        return response

    @app.get("/login")
    def login_page(failed: str = "") -> HTMLResponse:
        return HTMLResponse(PAGE.format(notice=NOTICES.get(failed, "")))

    @app.post("/login")
    def login(request: Request, code: str = Form(..., max_length=256)) -> Response:
        client = request.client.host if request.client else "unknown"
        if len(recent(client)) >= MAX_FAILURES:
            return RedirectResponse("/login?failed=locked", 303)
        if not hmac.compare_digest(code.encode(), access_code.get_secret_value().encode()):
            record_failure(client)
            return RedirectResponse("/login?failed=wrong", 303)
        expires, nonce = int(time.time()) + SESSION_SECONDS, secrets.token_hex(16)
        response = RedirectResponse("/", 303)
        secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        response.set_cookie(COOKIE, f"{expires}.{nonce}.{sign(expires, nonce)}", max_age=SESSION_SECONDS,
                            httponly=True, samesite="strict", secure=secure)
        return response
