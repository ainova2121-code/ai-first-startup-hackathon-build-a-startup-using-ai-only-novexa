"""A real, live-streaming demo page: triggers an actual ``Assessment.run()`` against the real
LedgerPilot target and streams genuine events to the browser over SSE as they happen -- no
Artifact sandbox, no scripted data. See ``purpleteam.demo`` for the same run from the command
line; this reuses its exact construction, never a parallel implementation.

    uv run uvicorn --factory purpleteam.live_demo:app --port 8090

Needs a configured target model, same as ``purpleteam.demo``: set LEDGERPILOT_LLM_API_KEY or
HF_TOKEN (see .env.example). Routes sit behind a passwordless demo login (``purpleteam.demo_auth``); "Log out"
ends the session and restores the target. The synthetic corpus JSON is public for sharing. Run evidence is stored as files. The
LedgerPilot target uses an isolated temporary SQLite database, exposed read-only on the Database page; it is separate
from the multi-tenant console's SQLite store.

Source fixes are written to the real files under ``ledgerpilot/`` (auto-approved only when the
rescan *and* the independent invariant both pass -- see ``purpleteam.source_fix``). Every original
is snapshotted first; each new run restores the platform's previous edits before testing the
vulnerable baseline, and ``POST /restore`` remains available as a manual restore.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import threading
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from ledgerpilot.utils.config import Settings
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.console.events import Broadcaster
from purpleteam.demo_auth import COOKIE, install_login
from purpleteam.drift_api import drift_routes
from purpleteam.inquiry_api import inquiry_routes
from purpleteam.target_api import target_routes
from purpleteam.live_run import (  # noqa: F401
    ATTACK_TYPES, ATTACKER_MODELS, MODEL_ATTACK_TYPES, MODES, ONLY_STATIC, OPERATOR_DIR, TARGET_REPO,
    assess, attacker_key_present, discovery_event, found_events,
)
from purpleteam.run_history import Run, RunStore
from purpleteam.run_control import RunControl
from purpleteam.targets.ledgerpilot import LedgerPilotTarget, reload_source

KEEPALIVE_SECONDS = 20
STATIC_DIR = Path(__file__).parent / "live_demo_static"


def max_unique_prompts() -> int:
    """How many unique prompts an adaptive attack may send a target. Operator-configured only, via
    PURPLETEAM_MAX_UNIQUE_PROMPTS (default 5); duplicates differing just in case/whitespace are skipped
    regardless. Not exposed in the UI -- it is a run-cost knob the operator sets in the environment."""
    load_dotenv()
    try:
        return max(1, int(os.environ.get("PURPLETEAM_MAX_UNIQUE_PROMPTS", "5")))
    except ValueError:
        return 5


class _RunState:
    def __init__(self) -> None:
        self.broadcaster = Broadcaster()
        self.running = False
        self.control: RunControl | None = None
        self.events: list[dict] = []  # this run's events so far, replayed to a client that (re)connects late
        self.run: Run | None = None  # where this run's evidence is kept
        self.runs: RunStore | None = None  # every run, for the last approved decisions to check against
        self.database_target = None  # the exact target instance most recently used by this assessment
        self.database_target_run_id: str | None = None
        self.database_preview: dict | None = None  # genuine seeded SQLite state when no run DB exists yet
        self.database_preview_lock = threading.Lock()
        self.mode = "full"  # static | full | advanced (purpleteam.live_run)
        self.attack_type = "all"
        self.attacker_model = ""  # chosen attacker model for a model-driven run; "" uses the env default
        self.max_unique_prompts = max_unique_prompts()  # set in the environment, not the UI

    def publish(self, payload: dict) -> None:
        self.events.append(payload)
        if self.run is not None:
            self.run.record(payload)
        self.broadcaster.publish(payload)


def create_app(snapshots: SourceSnapshots | None = None, target_repo: Path = TARGET_REPO,
               runs: RunStore | None = None, login: bool = True) -> FastAPI:
    """The live demo app, behind the demo login by default -- however it is started (``app`` or ``create_app``),
    the sign-in page comes first. Only tests that exercise the routes themselves pass ``login=False``."""
    state = _RunState()
    snapshots = snapshots or SourceSnapshots(OPERATOR_DIR / "source_snapshots.json")
    runs = runs or RunStore(OPERATOR_DIR / "runs")
    runs.mark_interrupted()  # this process is the only one that runs them, and it has only just started
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.run = state
    state.runs = runs
    if login:
        install_login(app, landing="/target")  # sign-in opens on the target overview, then the console
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(drift_routes(runs))
    app.include_router(inquiry_routes(runs, busy=lambda: state.running))
    app.include_router(target_routes(STATIC_DIR))

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})  # always the current page

    @app.get("/attack-types")
    def attack_types() -> dict:
        # The UI needs: every attack type, which ones require a model, the preset attacker models, and
        # whether a model-driven run can actually run here (an attacker key is configured).
        return {"types": list(ATTACK_TYPES), "model_attack_types": list(MODEL_ATTACK_TYPES),
                "attacker_models": list(ATTACKER_MODELS), "attacker_key_present": attacker_key_present(),
                "adaptive_enabled": not ONLY_STATIC or attacker_key_present()}

    @app.get("/custom-dataset")       # the dataset browser fetches this
    @app.get("/custom-dataset.json")  # the "View full dataset JSON" link opens this
    def custom_dataset() -> dict:
        """Return the complete checked-in test corpora as JSON for direct viewing or download."""
        dataset_dir = Path(__file__).parent / "attack" / "datasets"

        def read_jsonl(filename: str) -> list[dict]:
            path = dataset_dir / filename
            try:
                rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                        if line.strip()]
            except (OSError, json.JSONDecodeError) as exc:
                raise HTTPException(500, f"could not read the bundled dataset {filename}") from exc
            if not all(isinstance(row, dict) for row in rows):
                raise HTTPException(500, f"the bundled dataset {filename} contains an invalid row")
            return rows

        return {
            "version": "v1",
            "datasets": [
                {
                    "id": "business_claims_v1",
                    "name": "Business claim injection",
                    "file": "business_claims_v1.jsonl",
                    "description": "Synthetic untrusted-text cases that test whether an agent accepts a claimed sensitive-value change.",
                    "scope": "Untrusted user-supplied text; LedgerPilot delivers it through the invoice email body.",
                    "execution_note": "Three authored rows are expanded by the assessment into buried-text and form-field placement variants. The runner substitutes discovered argument labels and a synthetic canary.",
                    "cases": read_jsonl("business_claims_v1.jsonl"),
                },
                {
                    "id": "channel_attacks_v1",
                    "name": "Channel-specific attacks",
                    "file": "channel_attacks_v1.jsonl",
                    "description": "Reviewed cases for indirect tool-output injection, multilingual injection, prompt extraction, and hidden-document text.",
                    "scope": "Rows identify the intended source channel. Some require a matching adapter and are not run by every assessment mode.",
                    "execution_note": "Placeholders such as __CANARY__, __OBJECTIVE__, and __TOOLS_SENTENCE__ are filled by the relevant attack adapter. A listed case is not a guarantee of breach or proof that every workflow executes it.",
                    "cases": read_jsonl("channel_attacks_v1.jsonl"),
                },
            ],
        }

    @app.post("/run")
    async def start_run(mode: str = "full", attack_type: str = "all", attacker_model: str = "") -> dict:
        if mode not in MODES:
            raise HTTPException(422, f"mode must be one of {', '.join(MODES)}")
        if mode == "static" and attack_type != "all":
            raise HTTPException(422, "A quick scan runs no attacks; clear the attack type to run it.")
        if attack_type not in ATTACK_TYPES:
            raise HTTPException(422, f"attack_type must be one of {', '.join(ATTACK_TYPES)}")
        if attacker_model and attacker_model not in ATTACKER_MODELS:
            raise HTTPException(422, f"attacker_model must be one of {', '.join(ATTACKER_MODELS)}")
        if mode != "static" and attack_type in MODEL_ATTACK_TYPES and not (attacker_model or attacker_key_present()):
            raise HTTPException(422, "This run needs an attacker model. Set PURPLETEAM_ATTACKER_KEY "
                                     "(or GROQ_API_KEY) and pick a model.")
        if state.running:
            raise HTTPException(409, "a run is already in progress")
        # Prepare the baseline this run attacks. A prior verified source fix the platform left on disk and
        # nothing has touched since is undone (back to the original vulnerable bytes). A file the operator has
        # since hand-edited is kept and adopted as the new baseline -- they changed the target, so the run
        # discovers, attacks and shows what they now have, never blocks on their edit.
        try:
            source_baseline = snapshots.rebaseline(target_repo)
            reload_source()
        except Exception as exc:
            raise HTTPException(503, "Could not prepare and reload the target source; run not started.") from exc
        state.running, state.mode, state.attack_type = True, mode, attack_type
        state.attacker_model = attacker_model
        state.max_unique_prompts = max_unique_prompts()  # re-read the env so a .env change applies per run
        state.control = RunControl()
        state.events = []  # a fresh run replays only its own events, never a previous run's
        state.run = runs.new()
        state.database_target = None
        state.database_target_run_id = None
        state.database_preview = None  # a new run may use newly restored target source
        state.publish({"type": "run_started", "run_id": state.run.id, "mode": mode, "attack_type": attack_type,
                       "max_unique_prompts": state.max_unique_prompts})
        state.publish({"type": "source_baseline",
                       "restored": [f"{target_repo.name}/{i['path']}" for i in source_baseline if i["status"] == "restored"],
                       "adopted": [f"{target_repo.name}/{i['path']}" for i in source_baseline if i["status"] == "adopted"],
                       "clean": not source_baseline})
        asyncio.create_task(_execute(state, snapshots))
        return {"started": True, "run_id": state.run.id, "mode": mode}

    @app.post("/pause")
    def pause_run() -> dict:
        if not state.running or state.control is None:
            raise HTTPException(409, "there is no active run to pause")
        if state.control.pause_requested:
            raise HTTPException(409, "the run is already pausing or paused")
        if not state.control.pause():
            raise HTTPException(409, "the run is already stopping")
        state.publish({"type": "run_pausing"})
        return {"status": state.control.status}

    @app.post("/resume")
    def resume_run() -> dict:
        if not state.running or state.control is None:
            raise HTTPException(409, "there is no active run to resume")
        if not state.control.pause_requested:
            raise HTTPException(409, "the run is not paused")
        if not state.control.resume():
            raise HTTPException(409, "the run is stopping")
        state.publish({"type": "run_resumed"})
        return {"status": state.control.status}

    @app.post("/stop")
    def stop_run() -> dict:
        if not state.running or state.control is None:
            raise HTTPException(409, "there is no active run to stop")
        if state.control.stop_requested:
            raise HTTPException(409, "the run is already stopping")
        state.control.stop()
        state.publish({"type": "run_stopping"})
        return {"status": state.control.status}

    def _run_or_404(run_id: str) -> Run:
        run = runs.get(run_id)
        if run is None:
            raise HTTPException(404, "no such run")
        return run

    def _database_for(run: Run, view: str = "after") -> dict:
        baseline = run.read_json("database_baseline")  # the seeded starting state, for marking what the run changed
        breach = (run.dir / "database_breach.json").is_file()  # kept the moment an attack breached an unpatched copy
        if view == "breach":
            if not breach:
                raise HTTPException(404, "no attack breached this run, so there is no breach snapshot")
            return {**run.read_json("database_breach"), "run_id": run.id, "live": False, "baseline": baseline,
                    "snapshot_kind": "breach", "breach_available": True}
        if state.database_target is not None and state.database_target_run_id == run.id:
            try:
                snapshot = state.database_target.database_snapshot()
            except sqlite3.OperationalError as exc:
                raise HTTPException(503, "the target database is busy; refresh in a moment") from exc
            return {**snapshot, "run_id": run.id, "live": bool(state.running), "baseline": baseline,
                    "snapshot_kind": "assessment", "breach_available": breach}
        snapshot = run.read_json("database")
        if snapshot is not None:
            return {**snapshot, "run_id": run.id, "live": False, "baseline": baseline,
                    "snapshot_kind": "assessment", "breach_available": breach}
        if baseline is not None:
            # A run that stopped before its final snapshot still has its genuine pre-attack DB state.
            return {**baseline, "run_id": run.id, "live": False, "baseline": None,
                    "snapshot_kind": "run_baseline"}
        raise HTTPException(404, "this run did not create a LedgerPilot database snapshot")

    def _seed_database_preview() -> dict:
        """Show real seeded SQLite rows before a target run exists, without attributing them to a run."""
        if state.database_preview is None:
            with state.database_preview_lock:
                if state.database_preview is None:
                    target = LedgerPilotTarget()
                    state.database_preview = target.database_snapshot()
        return {**state.database_preview, "run_id": None, "live": False, "baseline": None,
                "snapshot_kind": "seed_preview"}

    @app.get("/database")
    def current_database(view: Literal["after", "breach"] = "after") -> dict:
        if state.run is None and view == "breach":
            raise HTTPException(404, "no run yet, so there is no breach snapshot")
        if state.run is None:
            return _seed_database_preview()
        try:
            return _database_for(state.run, view)
        except HTTPException as exc:
            if exc.status_code != 404 or view == "breach":
                raise
            # This is a clearly marked, separate seeded preview (not a fabricated historical run).
            return _seed_database_preview()

    @app.get("/runs/{run_id}/database")
    def run_database(run_id: str, view: Literal["after", "breach"] = "after") -> dict:
        return _database_for(_run_or_404(run_id), view)

    @app.get("/runs")
    def list_runs() -> dict:
        return {"runs": runs.all(), "current": state.run.id if state.run else None,
                "active": state.running, "control_status": state.control.status if state.control else "idle"}

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

    @app.post("/logout")
    def logout() -> Response:
        """End the demo session and put every file the platform edited back to its original bytes, so the
        next visitor starts from the clean target. Refused while a run is editing its files."""
        if state.running:
            raise HTTPException(409, "a run is in progress; log out once it finishes")
        results = snapshots.restore_all(target_repo)
        reload_source()
        response = JSONResponse({"restored": [r["path"] for r in results if r.get("status") == "restored"]})
        response.delete_cookie(COOKIE, httponly=True, samesite="strict")
        return response

    return app


async def _execute(state: _RunState, snapshots: SourceSnapshots) -> None:
    """The assessment makes blocking calls (discovery, the target's agents, scanners, model calls), so
    it runs on a worker thread with its own event loop; this server's loop stays free to stream. Each
    event hops back onto this loop, in order, since the broadcaster and the run's record are not
    thread-safe."""
    loop = asyncio.get_running_loop()

    def publish(payload: dict) -> None:
        loop.call_soon_threadsafe(state.publish, payload)

    def remember_target(target) -> None:
        state.database_target = target
        state.database_target_run_id = state.run.id if state.run is not None else None

    try:
        if state.control is not None:
            state.control.set_notifier(publish)
        await asyncio.to_thread(asyncio.run, assess(state.run, state.runs, snapshots, publish, state.mode,
                                                     state.attack_type, state.control, state.attacker_model,
                                                     state.max_unique_prompts, on_target=remember_target))
    except Exception as exc:  # a real failure (no LLM key, target unreachable...) must reach the page, not vanish
        if state.run is not None:
            state.run.write_meta(status="error", finished_at=time.time(), detail=str(exc))
        state.publish({"type": "error", "detail": str(exc)})
    finally:
        if (state.run is not None and state.database_target is not None
                and state.database_target_run_id == state.run.id):
            try:
                snapshot = state.database_target.database_snapshot()
                state.run.write_json("database", {**snapshot, "run_id": state.run.id, "live": False,
                                                    "snapshot_kind": "assessment"})
            except (OSError, sqlite3.Error):
                try:
                    state.run.write_meta(database_snapshot_status="unavailable")
                except OSError:
                    pass
        state.running = False
        state.control = None


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
    return create_app(login=True)  # passwordless demo login; "Log out" ends the session and restores the target
