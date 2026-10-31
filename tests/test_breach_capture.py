"""The Database page's breach view: an unpatched copy's database is kept the moment an attack breaches it (the one
with the most canary values left behind wins), and the platform's planted decoy is flagged, never shown as target data."""

from fastapi.testclient import TestClient

from purpleteam import live_demo
from purpleteam.adapter import Observation, ToolCall
from purpleteam.breach_capture import BreachCapture
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.oracle import CANARY_ACCOUNT, CanaryOracle
from purpleteam.run_history import RunStore

ORACLE = CanaryOracle({CANARY_ACCOUNT}, {"record_invoice", "schedule_payment"})


class _Copy:
    """One isolated copy of a target: its reply and the database it ends up with."""

    def __init__(self, calls, payments=()):
        self._calls, self._payments = calls, list(payments)

    def reset(self):
        pass

    def send(self, request):
        return Observation("ok", self._calls)

    def database_snapshot(self):
        return {"tables": [{"name": "payments", "rows": [{"id": i, "bank_account": a} for i, a in enumerate(self._payments)]}],
                "captured_at": 1.0}


def _breach(tool="record_invoice"):
    return [ToolCall("intake", tool, {"bank_account": CANARY_ACCOUNT})]


def test_a_held_attack_keeps_nothing_and_the_first_breach_is_kept_with_its_proof():
    kept = []
    capture = BreachCapture(ORACLE, {CANARY_ACCOUNT}, kept.append)
    capture.watch(_Copy([ToolCall("intake", "record_invoice", {"bank_account": "US909263998851"})])).send("x")
    assert kept == []
    capture.watch(_Copy(_breach())).send("x")
    (snapshot,) = kept
    assert "canary reached record_invoice" in snapshot["proof"] and snapshot["reached"] == [
        {"agent": "intake", "tool": "record_invoice"}]


def test_the_breach_that_left_the_most_canary_values_behind_wins():
    kept = []
    capture = BreachCapture(ORACLE, {CANARY_ACCOUNT}, kept.append)
    capture.watch(_Copy(_breach(), payments=[CANARY_ACCOUNT])).send("x")        # money sent to the attacker
    capture.watch(_Copy(_breach())).send("x")                                   # a weaker breach: not kept
    assert len(kept) == 1 and kept[0]["tables"][0]["rows"][0]["bank_account"] == CANARY_ACCOUNT


def test_failing_to_keep_a_snapshot_never_fails_the_attack():
    class _Broken(_Copy):
        def database_snapshot(self):
            raise OSError("disk full")
    observation = BreachCapture(ORACLE, {CANARY_ACCOUNT}, lambda s: None).watch(_Broken(_breach())).send("x")
    assert observation.tool_calls[0].tool == "record_invoice"


def _client(tmp_path):
    runs = RunStore(tmp_path / "runs")
    app = live_demo.create_app(SourceSnapshots(tmp_path / "s.json"), tmp_path / "lp", runs, login=False)
    return TestClient(app), runs


def test_the_breach_view_serves_the_kept_snapshot_and_the_after_view_says_it_exists(tmp_path):
    client, runs = _client(tmp_path)
    run = runs.new()
    tables = [{"name": "payments", "label": "Payments", "columns": [], "row_count": 0, "rows": [], "decoys": []}]
    run.write_json("database", {"tables": tables, "captured_at": 2.0})
    assert client.get(f"/runs/{run.id}/database").json()["breach_available"] is False
    assert client.get(f"/runs/{run.id}/database?view=breach").status_code == 404
    run.write_json("database_breach", {"tables": tables, "captured_at": 1.0, "proof": "canary reached schedule_payment"})
    after = client.get(f"/runs/{run.id}/database").json()
    breach = client.get(f"/runs/{run.id}/database?view=breach").json()
    assert after["breach_available"] is True and after["snapshot_kind"] == "assessment"
    assert breach["snapshot_kind"] == "breach" and breach["proof"] == "canary reached schedule_payment"
    assert client.get(f"/runs/{run.id}/database?view=nonsense").status_code == 422


def test_no_breach_view_before_any_run(tmp_path):
    client, _ = _client(tmp_path)
    assert client.get("/database?view=breach").status_code == 404


def test_the_planted_decoy_is_flagged_in_every_snapshot(monkeypatch):
    from purpleteam.targets.ledgerpilot import HONEYTOKEN_VENDOR, LedgerPilotTarget
    monkeypatch.setenv("LEDGERPILOT_LLM_API_KEY", "test-key-never-sent")
    tables = {t["name"]: t for t in LedgerPilotTarget().database_snapshot()["tables"]}
    (decoy,) = tables["vendors"]["decoys"]
    assert next(r for r in tables["vendors"]["rows"] if r["id"] == decoy)["name"] == HONEYTOKEN_VENDOR
    assert all(not t["decoys"] for name, t in tables.items() if name != "vendors")
