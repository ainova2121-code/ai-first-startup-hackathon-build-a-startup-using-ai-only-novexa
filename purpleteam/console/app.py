"""The fleet console's FastAPI app: login, the fleet dashboard, target/user management, and (Phase
4) the live SSE stream. Mirrors gateway.py's shape -- one role check called at the top of each
route, not a FastAPI Depends; interactive docs suppressed the same way.
"""

from __future__ import annotations

import asyncio
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from purpleteam.audit.compliance import evidence_report
from purpleteam.audit.trend import runs as trend_runs
from purpleteam.console import crypto
from purpleteam.console.auth import (
    ADMIN, ANALYST, AUDITOR, ROLES, SESSION_TTL, ConsoleAuth, ConsoleAuthError, Session, hash_password)
from purpleteam.console.db.repositories import SessionRepository, TargetRepository, UserRepository, connect
from purpleteam.console.deploy import plan_deployment
from purpleteam.console.events import Broadcaster
from purpleteam.console.gateway_client import GatewayAuthError, GatewayUnreachable, fetch_events
from purpleteam.console.poller import FleetPoller
from purpleteam.console.registry import FleetRegistry
from purpleteam.console.sse import sse_events
from purpleteam.gateway import MAX_EXPORT

COOKIE = "console_session"
_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).with_name("templates")))
_STATIC = Path(__file__).with_name("static")


def _bootstrap_admin(users: UserRepository) -> str:
    import secrets
    password = secrets.token_urlsafe(16)
    users.add(uuid.uuid4().hex, "admin@local", hash_password(password), ADMIN, time.time())
    print("purpleteam console: no users existed yet -- created bootstrap admin 'admin@local' "
         f"with password: {password}\nThis is shown once. Rotate it immediately after first login.",
         file=sys.stderr)
    return password


def create_console(db_path: Path, *, secret_key: str, poll_seconds: float = 15.0,
                   client: httpx.AsyncClient | None = None) -> FastAPI:
    conn = connect(db_path)
    targets, users, sessions = TargetRepository(conn), UserRepository(conn), SessionRepository(conn)
    registry = FleetRegistry(targets, crypto.derive_key(secret_key))
    auth = ConsoleAuth(users, sessions)
    broadcaster = Broadcaster()
    http = client or httpx.AsyncClient(timeout=30)
    poller = FleetPoller(registry, broadcaster, http, interval=poll_seconds)
    bootstrap_password = _bootstrap_admin(users) if users.count() == 0 else None

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        task = asyncio.create_task(poller.run_forever())
        yield
        task.cancel()
        if client is None:
            await http.aclose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.bootstrap_password = bootstrap_password
    app.state.broadcaster = broadcaster  # the /stream route reads this; tests drive it directly
    app.state.registry = registry        # tests read this; nothing in the app itself needs to
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

    def require_role(request: Request, *roles: str) -> Session:
        try:
            session = auth.authenticate(request.cookies.get(COOKIE))
        except ConsoleAuthError as error:
            raise HTTPException(error.status, error.reason) from None
        if session.role not in roles:
            raise HTTPException(403, "this role cannot do that")
        return session

    async def fetch_fresh(target_id: str) -> tuple[list[dict] | None, str | None]:
        """The authoritative view for one target: fetched live, never the best-effort cache.
        Capped at one page (MAX_EXPORT events) -- a target busier than that needs a windowed UI
        this phase does not build yet."""
        credentials = registry.credentials_for(target_id)
        if credentials is None:
            return None, "target not found"
        base_url, admin_key = credentials
        try:
            page = await fetch_events(http, base_url, admin_key, after_seq=-1, limit=MAX_EXPORT)
        except (GatewayAuthError, GatewayUnreachable) as error:
            return None, str(error)
        return page.events, None

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return _TEMPLATES.TemplateResponse(request, "login.html", {"error": None})

    @app.post("/login")
    async def login_submit(request: Request, email: str = Form(), password: str = Form()):
        try:
            token = auth.login(email, password)
        except ConsoleAuthError:
            return _TEMPLATES.TemplateResponse(request, "login.html", {"error": "Invalid email or password"},
                                               status_code=401)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(COOKIE, token, httponly=True, samesite="lax", max_age=SESSION_TTL)
        return response

    @app.post("/logout")
    async def logout_submit(request: Request):
        token = request.cookies.get(COOKIE)
        if token:
            auth.logout(token)
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE)
        return response

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        session = require_role(request, ADMIN, ANALYST, AUDITOR)
        rows = [{"target": t, "status": registry.get_status(t.id)} for t in registry.list_targets()]
        return _TEMPLATES.TemplateResponse(request, "dashboard.html", {"session": session, "rows": rows})

    row_template = _TEMPLATES.env.get_template("_target_row.html")

    def render_row(target_id: str) -> str | None:
        target = registry.get_target(target_id)
        return None if target is None else row_template.render(target=target, status=registry.get_status(target_id))

    @app.get("/stream")
    async def stream(request: Request):
        """A poll cycle's update, pushed as a server-rendered row fragment (hx-swap-oob routes it
        to the matching row id anywhere on the page) -- polling on the backend, real push to the
        browser."""
        require_role(request, ADMIN, ANALYST, AUDITOR)
        return StreamingResponse(sse_events(broadcaster, render_row), media_type="text/event-stream")

    @app.get("/targets", response_class=HTMLResponse)
    async def targets_page(request: Request):
        session = require_role(request, ADMIN)
        return _TEMPLATES.TemplateResponse(request, "targets.html",
                                           {"session": session, "targets": registry.list_targets(), "error": None})

    @app.post("/targets")
    async def targets_add(request: Request, name: str = Form(), base_url: str = Form(), admin_key: str = Form()):
        session = require_role(request, ADMIN)
        if not base_url.startswith(("http://", "https://")):
            return _TEMPLATES.TemplateResponse(
                request, "targets.html",
                {"session": session, "targets": registry.list_targets(), "error": "base_url must be http(s)"},
                status_code=400)
        registry.add_target(name, base_url, admin_key)
        return RedirectResponse("/targets", status_code=303)

    @app.post("/targets/deploy", response_class=HTMLResponse)
    async def targets_deploy(request: Request, name: str = Form(), domain: str = Form()):
        """Generates a paste-and-run self-host deployment for a brand new gateway: both bearer
        keys are minted here and registered into the fleet immediately, so the operator never
        copies a key out of a log or types one into this form -- see ``console.deploy``."""
        session = require_role(request, ADMIN)
        domain = domain.strip()
        if not domain or domain.startswith(("http://", "https://")) or "/" in domain:
            return _TEMPLATES.TemplateResponse(
                request, "targets.html",
                {"session": session, "targets": registry.list_targets(),
                 "error": "domain must be a bare host, e.g. gateway.acme.example or localhost — no scheme or path"},
                status_code=400)
        plan = plan_deployment(domain)
        registry.add_target(name, plan.base_url, plan.admin_key)
        return _TEMPLATES.TemplateResponse(request, "deploy_command.html",
                                           {"session": session, "name": name, "plan": plan})

    @app.post("/targets/{target_id}/remove")
    async def targets_remove(request: Request, target_id: str):
        require_role(request, ADMIN)
        registry.remove_target(target_id)
        return RedirectResponse("/targets", status_code=303)

    @app.get("/targets/{target_id}", response_class=HTMLResponse)
    async def target_detail(request: Request, target_id: str):
        session = require_role(request, ADMIN, ANALYST, AUDITOR)
        target = registry.get_target(target_id)
        if target is None:
            raise HTTPException(404, "no such target")
        events, error = await fetch_fresh(target_id)
        runs = trend_runs(events) if events else []
        compliance = evidence_report(events) if events else {}
        return _TEMPLATES.TemplateResponse(
            request, "target_detail.html",
            {"session": session, "target": target, "runs": runs, "compliance": compliance, "fetch_error": error})

    @app.get("/targets/{target_id}/activity", response_class=HTMLResponse)
    async def target_activity(request: Request, target_id: str):
        session = require_role(request, ADMIN, ANALYST)  # evidence-shaped views only for auditor; this is raw
        target = registry.get_target(target_id)
        if target is None:
            raise HTTPException(404, "no such target")
        events, error = await fetch_fresh(target_id)
        activity = [e for e in events if e.get("kind") in ("decision", "containment")] if events else []
        return _TEMPLATES.TemplateResponse(
            request, "activity.html",
            {"session": session, "target": target, "activity": activity, "fetch_error": error})

    @app.get("/users", response_class=HTMLResponse)
    async def users_page(request: Request):
        session = require_role(request, ADMIN)
        return _TEMPLATES.TemplateResponse(request, "users.html",
                                           {"session": session, "users": users.list_all(), "error": None})

    @app.post("/users")
    async def users_add(request: Request, email: str = Form(), password: str = Form(), role: str = Form()):
        session = require_role(request, ADMIN)
        if role not in ROLES:
            return _TEMPLATES.TemplateResponse(
                request, "users.html", {"session": session, "users": users.list_all(), "error": "unknown role"},
                status_code=400)
        users.add(uuid.uuid4().hex, email, hash_password(password), role, time.time())
        return RedirectResponse("/users", status_code=303)

    return app
