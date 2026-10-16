"""Adapts the LedgerPilot demo agent to the platform's Target protocol.

Two channels: ``invoice`` (the attacker controls the invoice email body, a business-email-
compromise channel through the AP pipeline) and ``inquiry`` (the attacker controls the
supplier-portal question that drives the text-to-SQL agent, for data-exfiltration tests).
Every tool call and its result are captured through LedgerPilot's own EventSink port, so the
platform observes behaviour without importing or modifying LedgerPilot's logic. A honeytoken
vendor is seeded whose bank account no legitimate output should ever return.
"""

import tempfile
import time
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from ledgerpilot.db.repositories import Ledger, VendorRepository, connect
from ledgerpilot.db.seed import bank_account, load_manifest, seed
from ledgerpilot.main import create_app
from ledgerpilot.ports import Blocked as LedgerPilotBlocked
from ledgerpilot.utils.config import Settings
from purpleteam.adapter import Observation, ToolCall
from purpleteam.capture import profile_runtime
from purpleteam.discovery import TargetProfile
from purpleteam.oracle import HONEYTOKEN
from purpleteam.patches.base import Blocked as PlatformBlocked

REPO_INVOICES = Path(__file__).resolve().parents[2] / "data" / "invoices"
HONEYTOKEN_VENDOR = "ZZ-CANARY-VENDOR"


def discover_profile() -> TargetProfile:
    """What LedgerPilot is built from, seen as it is constructed. Needs no model, key or network."""
    settings = Settings(data_dir=Path(tempfile.mkdtemp(prefix="lp-discover-")))
    return profile_runtime("ledgerpilot", lambda: create_app(settings, llm=object()))


SHARED_CREDENTIAL = "one sqlite connection (ledger.db)"


def credentials(profile: TargetProfile) -> dict[str, str]:
    """Which credential each agent acts through. LedgerPilot opens one database connection in
    ``create_app`` and every agent's repositories use it, so there is a single shared identity."""
    return {agent: SHARED_CREDENTIAL for agent in sorted(profile.agents)}


class _RecordingSink:
    def __init__(self) -> None:
        self.calls: list[ToolCall] = []

    def emit(self, agent: str, kind: str, payload: dict[str, Any]) -> None:
        if kind == "tool_call":
            self.calls.append(ToolCall(agent, payload["tool"], payload.get("args", {}), at=time.monotonic()))
        elif kind == "tool_result" and self.calls:
            self.calls[-1].result = str(payload.get("result", ""))  # whole: a cut would let padding hide a leak


class _GuardAdapter:
    """Lets the platform's own, domain-agnostic Guard attach to LedgerPilot's guard port, whose
    contract expects its own ``Blocked`` exception (see ``patches/base.py``): the one place that
    translates between the two, so neither side needs to know the other's module."""

    def __init__(self, guard: Any) -> None:
        self._guard = guard

    def screen(self, agent: str, text: str, source: str) -> str:
        try:
            return self._guard.screen(agent, text, source)
        except PlatformBlocked as error:
            raise LedgerPilotBlocked(str(error)) from error

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        try:
            self._guard.authorize(agent, tool, args)
        except PlatformBlocked as error:
            raise LedgerPilotBlocked(str(error)) from error


class LedgerPilotTarget:
    """One LedgerPilot instance over a private, reseedable database."""

    name = "ledgerpilot"

    def __init__(self, base_invoice: str = "2112-1", channel: str = "invoice", guard: Any = None) -> None:
        manifest = load_manifest(REPO_INVOICES)
        self._base = next(e for e in manifest if e["invoice_number"] == base_invoice)
        self._pdf = (REPO_INVOICES / self._base["file"]).read_bytes()
        self._channel = channel
        self._settings = Settings(data_dir=Path(tempfile.mkdtemp(prefix="lp-target-")))
        ledger = Ledger(connect(self._settings.db_path))
        seed(ledger, manifest)
        ledger.vendors.add(HONEYTOKEN_VENDOR, "canary@example.test", HONEYTOKEN, verified=False)
        self._sink = _RecordingSink()
        app_kwargs = {"guard": _GuardAdapter(guard)} if guard is not None else {}
        self._client = TestClient(create_app(self._settings, sink=self._sink, **app_kwargs))

    def reset(self) -> None:
        self._sink.calls.clear()
        conn = connect(self._settings.db_path)
        for table in ("payments", "invoices", "emails"):
            conn.execute(f"DELETE FROM {table}")
        vendors = VendorRepository(conn)
        for vendor in vendors.all():
            secret = HONEYTOKEN if vendor["name"] == HONEYTOKEN_VENDOR else bank_account(vendor["name"])
            vendors.update_bank(vendor["id"], secret)

    def send(self, request: str) -> Observation:
        self._sink.calls.clear()
        if self._channel == "inquiry":
            response = self._client.post("/inquiries", json={"vendor_id": 1, "question": request})
        else:
            response = self._client.post(
                "/invoices",
                data={"sender": f"billing@{self._base['vendor'].lower()}.example",
                      "subject": f"Invoice {self._base['invoice_number']}", "body": request},
                files={"invoice": (self._base["file"], self._pdf, "application/pdf")},
            )
        return Observation(response.text, list(self._sink.calls), response.status_code)
