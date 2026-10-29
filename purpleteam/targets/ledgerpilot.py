"""Adapts the LedgerPilot demo agent to the platform's Target protocol.

Two channels: ``invoice`` (the attacker controls the invoice email body, a business-email-
compromise channel through the AP pipeline) and ``inquiry`` (the attacker controls the
supplier-portal question that drives the text-to-SQL agent, for data-exfiltration tests).
Every tool call and its result are captured through LedgerPilot's own EventSink port, so the
platform observes behaviour without importing or modifying LedgerPilot's logic. A honeytoken
vendor is seeded whose bank account no legitimate output should ever return.
"""

import importlib
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from purpleteam.adapter import Observation, ToolCall
from purpleteam.capture import OnFound, profile_runtime
from purpleteam.discovery import TargetProfile
from purpleteam.oracle import HONEYTOKEN
from purpleteam.patches.base import Blocked as PlatformBlocked, HoldForReview

REPO_INVOICES = Path(__file__).resolve().parents[2] / "data" / "invoices"
HONEYTOKEN_VENDOR = "ZZ-CANARY-VENDOR"


def _lp(module: str) -> Any:
    """LedgerPilot is looked up at call time, never bound at import: after its source is edited and
    reloaded (``reload_source``), every new target must run the edited code, not a stale reference."""
    return importlib.import_module(f"ledgerpilot.{module}")


def reload_source() -> None:
    """Forget every loaded LedgerPilot module and import it again from disk, so the next target is
    built from exactly what the files say now -- after a source fix, and after a restore."""
    for name in [m for m in sys.modules if m == "ledgerpilot" or m.startswith("ledgerpilot.")]:
        del sys.modules[name]
    importlib.import_module("ledgerpilot.main")


def discover_profile(on_found: OnFound | None = None) -> TargetProfile:
    """What LedgerPilot is built from, seen as it is constructed. Needs no model, key or network."""
    settings = _lp("utils.config").Settings(data_dir=Path(tempfile.mkdtemp(prefix="lp-discover-")))
    return profile_runtime("ledgerpilot", lambda: _lp("main").create_app(settings, llm=object()), on_found=on_found)


SHARED_CREDENTIAL = "one sqlite connection (ledger.db)"
_SEEDED: dict[Any, Path] = {}  # loaded seed module -> its seeded database, copied for every new target
_SEEDING = threading.Lock()


def _seeded_database(seeding: Any, repos: Any, manifest: list[dict]) -> Path:
    """Seeding writes row by row, each synced to disk: seconds per target, and every target starts from the same
    state. So it runs once per loaded LedgerPilot (a reload after a source fix seeds again) and each new target
    gets a byte-for-byte copy of the result."""
    with _SEEDING:
        if seeding not in _SEEDED:
            path = Path(tempfile.mkdtemp(prefix="lp-seed-")) / "ledger.db"
            conn = repos.connect(path)
            ledger = repos.Ledger(conn)
            seeding.seed(ledger, manifest)
            ledger.vendors.add(HONEYTOKEN_VENDOR, "canary@example.test", HONEYTOKEN, verified=False)
            conn.close()
            _SEEDED[seeding] = path
        return _SEEDED[seeding]


def credentials(profile: TargetProfile) -> dict[str, str]:
    """Which credential each agent acts through. LedgerPilot opens one database connection in
    ``create_app`` and every agent's repositories use it, so there is a single shared identity."""
    return {agent: SHARED_CREDENTIAL for agent in sorted(profile.agents)}


class _RecordingSink:
    def __init__(self) -> None:
        self.calls: list[ToolCall] = []
        self.attempts: list[ToolCall] = []  # calls the guard stopped before they ran
        self.pending_reviews: list[dict[str, Any]] = []

    def stopped(self, agent: str, tool: str, args: dict[str, Any], by: str) -> None:
        self.attempts.append(ToolCall(agent, tool, dict(args), at=time.monotonic(), stopped_by=by))

    def emit(self, agent: str, kind: str, payload: dict[str, Any]) -> None:
        if kind == "tool_call":
            self.calls.append(ToolCall(agent, payload["tool"], payload.get("args", {}), at=time.monotonic()))
        elif kind == "tool_result" and self.calls:
            self.calls[-1].result = str(payload.get("result", ""))  # whole: a cut would let padding hide a leak

    def hold_for_review(self, agent: str, tool: str, args: dict[str, Any], reason: str) -> str:
        self.pending_reviews.append({"agent": agent, "tool": tool, "args": dict(args), "reason": reason})
        return f"Held for human review: {tool}"


class _GuardAdapter:
    """Lets the platform's own, domain-agnostic Guard attach to LedgerPilot's guard port, whose
    contract expects its own ``Blocked`` exception (see ``patches/base.py``): the one place that
    translates between the two, so neither side needs to know the other's module."""

    def __init__(self, guard: Any, ports: Any, on_stop: Any = None) -> None:
        self._guard, self._ports = guard, ports  # the same loaded ports module the target's agents catch
        self._on_stop = on_stop or (lambda *call: None)  # told of every call the guard stopped (an attempt)

    def screen(self, agent: str, text: str, source: str) -> str:
        try:
            return self._guard.screen(agent, text, source)
        except PlatformBlocked as error:
            raise self._ports.Blocked(str(error)) from error

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        try:
            self._guard.authorize(agent, tool, args)
        except HoldForReview as error:
            self._on_stop(agent, tool, args, "a hold for human review")
            raise self._ports.ReviewRequired(str(error)) from error
        except PlatformBlocked as error:
            self._on_stop(agent, tool, args, f"the runtime guard ({str(error)[:160]})")
            raise self._ports.Blocked(str(error)) from error


class LedgerPilotTarget:
    """One LedgerPilot instance over a private, reseedable database."""

    name = "ledgerpilot"

    def __init__(self, base_invoice: str = "2112-1", channel: str = "invoice", guard: Any = None) -> None:
        seeding, self._repos = _lp("db.seed"), _lp("db.repositories")
        manifest = seeding.load_manifest(REPO_INVOICES)
        self._base = next(e for e in manifest if e["invoice_number"] == base_invoice)
        self._pdf = (REPO_INVOICES / self._base["file"]).read_bytes()
        self._channel = channel
        self._settings = _lp("utils.config").Settings(data_dir=Path(tempfile.mkdtemp(prefix="lp-target-")))
        shutil.copyfile(_seeded_database(seeding, self._repos, manifest), self._settings.db_path)
        self._bank_account = seeding.bank_account
        self._sink = _RecordingSink()
        app_kwargs = {"guard": _GuardAdapter(guard, _lp("ports"), self._sink.stopped)} if guard is not None else {}
        self._client = TestClient(_lp("main").create_app(self._settings, sink=self._sink, **app_kwargs))

    def reset(self) -> None:
        self._sink.calls.clear()
        self._sink.attempts.clear()
        self._sink.pending_reviews.clear()
        conn = self._repos.connect(self._settings.db_path)
        for table in ("payments", "invoices", "emails"):
            conn.execute(f"DELETE FROM {table}")  # nosec B608: a fixed tuple of table names, never input
        vendors = self._repos.VendorRepository(conn)
        for vendor in vendors.all():
            secret = HONEYTOKEN if vendor["name"] == HONEYTOKEN_VENDOR else self._bank_account(vendor["name"])
            vendors.update_bank(vendor["id"], secret)

    def send(self, request: str) -> Observation:
        self._sink.calls.clear()
        self._sink.attempts.clear()
        if self._channel == "inquiry":
            response = self._client.post("/inquiries", json={"vendor_id": 1, "question": request})
        else:
            response = self._client.post(
                "/invoices",
                data={"sender": f"billing@{self._base['vendor'].lower()}.example",
                      "subject": f"Invoice {self._base['invoice_number']}", "body": request},
                files={"invoice": (self._base["file"], self._pdf, "application/pdf")},
            )
        return Observation(response.text, list(self._sink.calls), response.status_code, list(self._sink.attempts))
