"""Passwordless login for the live demo.

One click earns a signed, HttpOnly, SameSite=Strict session cookie (Secure over HTTPS). There is no
secret to type -- this is a demo. The cookie still gates the app's routes, so "Log out" can end a session
(``/logout`` in ``live_demo``, which also restores the target), and the signing key lives only in this
process, so a restart signs everyone out. The fixed, synthetic attack-corpus JSON endpoint stays public.

This is deliberately open: anyone with the URL can start a run (which spends model credit and edits the
demo target's files). It is meant for a short-lived demo deployment, never a standing public service.
"""

from __future__ import annotations

import hmac
import secrets
import time
from hashlib import sha256

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

COOKIE = "pt_session"
SESSION_SECONDS = 12 * 3600
HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AIQ Security &middot; sign in</title><style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:#E6EDF3;
 background:radial-gradient(1200px 600px at 50% -10%,#141b27 0%,#0A0D13 60%)}
.card{width:min(400px,calc(100vw - 32px));padding:36px 32px;border:1px solid #1d2735;border-radius:18px;text-align:center;
 background:linear-gradient(180deg,rgba(21,27,39,0.9),rgba(15,20,28,0.9));box-shadow:0 24px 60px rgba(0,0,0,0.45)}
.mark{width:46px;height:46px;margin:0 auto 18px;border-radius:12px;display:grid;place-items:center;font-size:22px;
 background:linear-gradient(135deg,#4F8BFF,#8B5CF6);box-shadow:0 8px 24px rgba(79,139,255,0.35)}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-0.2px}
.sub{color:#8B98A9;margin:0 0 4px;font-size:14px}
.note{color:#5d6b7d;margin:0 0 24px;font-size:12.5px}
button{width:100%;padding:13px;border:0;border-radius:10px;font-weight:700;font-size:15px;cursor:pointer;color:#06101F;
 background:linear-gradient(135deg,#4F8BFF,#8B5CF6);transition:transform .08s ease,filter .15s ease}
button:hover{filter:brightness(1.08)}button:active{transform:translateY(1px)}
.foot{margin-top:18px;color:#5d6b7d;font-size:11.5px;display:flex;align-items:center;justify-content:center;gap:6px}
.pulse{width:7px;height:7px;border-radius:50%;background:#3FB96B;box-shadow:0 0 0 0 rgba(63,185,107,0.6);animation:p 2s infinite}
@keyframes p{0%{box-shadow:0 0 0 0 rgba(63,185,107,0.5)}70%{box-shadow:0 0 0 7px rgba(63,185,107,0)}100%{box-shadow:0 0 0 0 rgba(63,185,107,0)}}
</style></head><body><form class="card" method="post" action="/login">
<div class="mark">&#9680;</div>
<h1>AIQ Security</h1>
<p class="sub">Autonomous AI purple-team platform</p>
<p class="note">Live demo &mdash; no sign-in required</p>
<button type="submit">Enter the demo</button>
<div class="foot"><span class="pulse"></span>Demo environment</div>
</form></body></html>"""


def install_login(app: FastAPI, landing: str = "/") -> None:
    """Gate every route behind a session; ``landing`` is where a fresh sign-in goes first."""
    key = secrets.token_bytes(32)

    def sign(expires: int, nonce: str) -> str:
        return hmac.new(key, f"{expires}.{nonce}".encode(), sha256).hexdigest()

    def valid(token: str | None) -> bool:
        try:
            expires, nonce, signature = (token or "").split(".")
            return int(expires) > time.time() and hmac.compare_digest(signature, sign(int(expires), nonce))
        except ValueError:
            return False

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
    def login_page() -> HTMLResponse:
        return HTMLResponse(PAGE)

    @app.post("/login")
    def login(request: Request) -> Response:
        expires, nonce = int(time.time()) + SESSION_SECONDS, secrets.token_hex(16)
        response = RedirectResponse(landing, 303)
        secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        response.set_cookie(COOKIE, f"{expires}.{nonce}.{sign(expires, nonce)}", max_age=SESSION_SECONDS,
                            httponly=True, samesite="strict", secure=secure)
        return response
