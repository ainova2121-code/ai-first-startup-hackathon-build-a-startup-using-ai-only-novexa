"""A real, live-streaming demo page: triggers an actual ``Assessment.run()`` against the real
LedgerPilot target and streams genuine events to the browser over SSE as they happen -- no
Artifact sandbox, no scripted data. See ``purpleteam.demo`` for the same run from the command
line; this reuses its exact construction, never a parallel implementation.

    uv run uvicorn --factory purpleteam.live_demo:app --port 8090

Needs a configured target model, same as ``purpleteam.demo``: set LEDGERPILOT_LLM_API_KEY or
HF_TOKEN (see .env.example), and an access code in DEMO_ACCESS_CODE: every route sits behind its login
(``purpleteam.demo_auth``), so the page can be put on a public URL. No database: a single-operator demo tool,
not the multi-tenant console.

Source fixes are written to the real files under ``ledgerpilot/`` (auto-approved only when the
rescan *and* the independent invariant both pass -- see ``purpleteam.source_fix``). Every original
is snapshotted first, and ``POST /restore`` puts every edited file back in one step.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import AsyncIterator
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import SecretStr

from ledgerpilot.utils.config import Settings
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.console.events import Broadcaster
from purpleteam.demo_auth import install_login
from purpleteam.drift_api import drift_routes
from purpleteam.live_run import MODES, OPERATOR_DIR, TARGET_REPO, assess, discovery_event, found_events  # noqa: F401
from purpleteam.run_history import Run, RunStore
from purpleteam.targets.ledgerpilot import reload_source

KEEPALIVE_SECONDS = 20
STATIC_DIR = Path(__file__).parent / "live_demo_static"


class _RunState:
    def __init__(self) -> None:
        self.broadcaster = Broadcaster()
        self.running = False
        self.events: list[dict] = []  # this run's events so far, replayed to a client that (re)connects late
        self.run: Run | None = None  # where this run's evidence is kept
        self.runs: RunStore | None = None  # every run, for the last approved decisions to check against
        self.mode = "full"  # static | full | advanced (purpleteam.live_run)

    def publish(self, payload: dict) -> None:
        self.events.append(payload)
        if self.run is not None:
            self.run.record(payload)
        self.broadcaster.publish(payload)


def create_app(snapshots: SourceSnapshots | None = None, target_repo: Path = TARGET_REPO,
               runs: RunStore | None = None, access_code: SecretStr | None = None) -> FastAPI:
    state = _RunState()
    snapshots = snapshots or SourceSnapshots(OPERATOR_DIR / "source_snapshots.json")
    runs = runs or RunStore(OPERATOR_DIR / "runs")
    runs.mark_interrupted()  # this process is the only one that runs them, and it has only just started
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.run = state
    state.runs = runs
    if access_code is not None:
        install_login(app, access_code)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(drift_routes(runs))

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})  # always the current page

    @app.post("/run")
    async def start_run(mode: str = "full") -> dict:
        if mode not in MODES:
            raise HTTPException(422, f"mode must be one of {', '.join(MODES)}")
        if state.running:
            raise HTTPException(409, "a run is already in progress")
        state.running, state.mode = True, mode
        state.events = []  # a fresh run replays only its own events, never a previous run's
        state.run = runs.new()
        state.publish({"type": "run_started", "run_id": state.run.id, "mode": mode})
        asyncio.create_task(_execute(state, snapshots))
        return {"started": True, "run_id": state.run.id, "mode": mode}

    def _run_or_404(run_id: str) -> Run:
        run = runs.get(run_id)
        if run is None:
            raise HTTPException(404, "no such run")
        return run

    @app.get("/runs")
    def list_runs() -> dict:
        return {"runs": runs.all(), "current": state.run.id if state.run else None}

    @app.get("/runs/{run_id}/events")
    def run_events(run_id: str) -> dict:
        return {"events": _run_or_404(run_id).events()}

    @app.get("/runs/{run_id}/ledger")
    def run_ledger(run_id: str) -> dict:
        return _run_or_404(run_id).ledger()

    @app.get("/runs/{run_id}/ledger/explain")
    def run_ledger_explain(run_id: str) -> dict:
        explained = _run_or_404(run_id).explain()
        if explained is None:
            raise HTTPException(404, "this run has not been sealed yet")
        return explained

    @app.get("/stream")
    async def stream() -> StreamingResponse:
        return StreamingResponse(_sse(state), media_type="text/event-stream")

    @app.get("/source-status")
    def source_status() -> dict:
        return {"modified": [f"{target_repo.name}/{path}" for path in snapshots.modified()]}

    @app.post("/restore")
    def restore() -> dict:
        """Every file the platform edited, back to its exact original bytes, then reloaded so the
        next run (and this process) executes the original code. Refused while a run is editing."""
        if state.running:
            raise HTTPException(409, "a run is in progress; restore once it finishes")
        results = snapshots.restore_all(target_repo)
        reload_source()
        return {"results": [{**r, "path": f"{target_repo.name}/{r['path']}"} for r in results],
                "modified": [f"{target_repo.name}/{path}" for path in snapshots.modified()]}

    return app


async def _execute(state: _RunState, snapshots: SourceSnapshots) -> None:
    """The assessment makes blocking calls (discovery, the target's agents, scanners, model calls), so
    it runs on a worker thread with its own event loop; this server's loop stays free to stream. Each
    event hops back onto this loop, in order, since the broadcaster and the run's record are not
    thread-safe."""
    loop = asyncio.get_running_loop()

    def publish(payload: dict) -> None:
        loop.call_soon_threadsafe(state.publish, payload)

    try:
        await asyncio.to_thread(asyncio.run, assess(state.run, state.runs, snapshots, publish, state.mode))
    except Exception as exc:  # a real failure (no LLM key, target unreachable...) must reach the page, not vanish
        if state.run is not None:
            state.run.write_meta(status="error", finished_at=time.time(), detail=str(exc))
        state.publish({"type": "error", "detail": str(exc)})
    finally:
        state.running = False


async def _sse(state: _RunState) -> AsyncIterator[str]:
    """Replays this run's events-so-far to a client connecting (or reconnecting) mid-run before
    switching to live ones -- without this, a dropped SSE connection (a reload, a network blip;
    browsers auto-reconnect EventSource) would silently lose every event published in between,
    since Broadcaster.subscribe() alone only ever sees what is published after it."""
    # No `await` between these two lines, and state.publish() (append + broadcast) has no `await`
    # either, so nothing can run in the gap between them: an event is either in this backlog
    # snapshot or arrives later on the queue, never both and never neither.
    queue = state.broadcaster.subscribe()
    backlog = list(state.events)
    try:
        for message in backlog:
            yield f"data: {json.dumps(message)}\n\n"
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=KEEPALIVE_SECONDS)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
                continue
            yield f"data: {json.dumps(message)}\n\n"
    finally:
        state.broadcaster.unsubscribe(queue)


def app() -> FastAPI:
    """``uvicorn --factory purpleteam.live_demo:app``: refuses to start without a configured target
    model, the same loud-refusal posture as gateway_main.py/console/main.py -- this page runs a real
    assessment against LedgerPilot's real LLM, so there is nothing honest to show without one."""
    load_dotenv()
    if not Settings().llm_api_key.get_secret_value():
        raise RuntimeError(
            "no target model is configured -- set LEDGERPILOT_LLM_API_KEY or HF_TOKEN (see .env.example). "
            "This page runs a real assessment against LedgerPilot's real LLM; it cannot start without one.")
    code = os.environ.get("DEMO_ACCESS_CODE", "")
    if len(code) < 12:  # it starts real runs, spends model credit and edits files: never left open
        raise RuntimeError("set DEMO_ACCESS_CODE to an access code of at least 12 characters (for example the "
                           "output of: python -c \"import secrets; print(secrets.token_urlsafe(12))\")")
    return create_app(access_code=SecretStr(code))
