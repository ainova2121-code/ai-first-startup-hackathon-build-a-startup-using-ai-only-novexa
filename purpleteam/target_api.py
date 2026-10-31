"""The target overview page shown after sign-in, before the console: what the target is, in its owner's words, and
what discovery finds in it -- every agent in the order the target builds it, its tools and their risk, and the data it
starts with. No model is called, and nothing about what may be exploitable is shown: the attack run finds that.

Part of the LedgerPilot live console (like ``live_run``); the domain-agnostic platform never imports it. Discovery
runs once per process (it builds the target, about two seconds) and is then served from memory.
"""

from __future__ import annotations

import threading
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

from purpleteam.live_run import tool_view
from purpleteam.targets.ledgerpilot import about, discover_profile, seeded_tables


def overview() -> dict:
    profile = discover_profile()
    agents = [{"name": info.name, "tools": [tool_view(t) for t in profile.tools if t.agent == info.name]}
              for info in profile.agent_info]
    if not agents:  # discovery saw tools but no agent being built: group them by the agent each one belongs to
        names = dict.fromkeys(t.agent for t in profile.tools)
        agents = [{"name": name, "tools": [tool_view(t) for t in profile.tools if t.agent == name]} for name in names]
    tables = seeded_tables()
    return {**about(), "agents": agents, "tables": tables,
            "totals": {"agents": len(agents), "tools": len(profile.tools), "acting": len(profile.dangerous_tools),
                       "records": sum(table["rows"] for table in tables)}}


def target_routes(static_dir: Path) -> APIRouter:
    router = APIRouter()
    cache: dict = {}
    lock = threading.Lock()

    @router.get("/target")
    def page() -> FileResponse:
        return FileResponse(static_dir / "target.html", headers={"Cache-Control": "no-cache"})

    @router.get("/target/about")
    def target_about() -> dict:
        """The owner's summary alone, for the About page: no discovery, which runs once, in the run itself."""
        return about()

    @router.get("/target/overview")
    def target_overview() -> dict:
        with lock:
            if "overview" not in cache:
                cache["overview"] = overview()
            return cache["overview"]

    return router
