"""Run history: a run's signed ledger is kept and re-verified from disk later, and a run id can never be
turned into an arbitrary path."""

from purpleteam.audit.ledger import AuditLedger
from purpleteam.run_history import RunStore


def _sealed_run(tmp_path):
    store = RunStore(tmp_path / "runs")
    run = store.new()
    ledger = AuditLedger(run.ledger_path)
    ledger.append("attacker", "attack", {"id": "probe", "technique": "prompt-injection"})
    ledger.append("oracle", "breach", {"id": "probe", "tool": "pay"})
    run.write_trust(ledger.export_trust())
    run.record({"type": "discovered", "target": "acme"})
    run.write_meta(status="done", safe_to_ship=False)
    return store, run


def test_a_sealed_run_is_reverified_from_disk_and_maps_each_event_to_clauses(tmp_path):
    store, run = _sealed_run(tmp_path)
    view = store.get(run.id).ledger()
    assert view["verification"]["ok"] is True and view["verification"]["anchored"] is True
    assert [e["kind"] for e in view["events"]] == ["attack", "breach"]
    assert "EU AI Act · Art. 15" in view["events"][0]["clauses"]
    assert view["run"]["status"] == "done"


def test_a_tampered_ledger_fails_verification(tmp_path):
    store, run = _sealed_run(tmp_path)
    text = run.ledger_path.read_text().replace('"pay"', '"refund"')
    run.ledger_path.write_text(text)
    assert store.get(run.id).ledger()["verification"]["ok"] is False


def test_an_unsealed_run_says_it_cannot_be_verified_yet(tmp_path):
    store = RunStore(tmp_path / "runs")
    view = store.new().ledger()
    assert view["verification"]["ok"] is None and "not been sealed" in view["verification"]["reason"]


def test_runs_are_listed_newest_first_with_their_meta(tmp_path):
    store, run = _sealed_run(tmp_path)
    assert [r["id"] for r in store.all()] == [run.id]
    assert store.get(run.id).events() == [{"type": "discovered", "target": "acme"}]


def test_a_malformed_or_traversing_run_id_is_never_resolved(tmp_path):
    store, _ = _sealed_run(tmp_path)
    for bad in ("..", "../runs", "x", "20260101T000000-zzzzzz", "", "20260101T000000-abc123/../.."):
        assert store.get(bad) is None


def test_the_last_approved_run_is_the_targets_newest_that_shipped_and_pinned_its_decisions(tmp_path, monkeypatch):
    store = RunStore(tmp_path / "runs")
    clock = iter(range(1000, 2000))
    monkeypatch.setattr("purpleteam.run_history.time.time", lambda: next(clock))
    shipped = store.new()
    shipped.write_json("decisions", {"version": 1, "probes": [], "digest": "d"})
    shipped.write_meta(status="done", safe_to_ship=True, target="acme")
    not_safe = store.new()
    not_safe.write_json("decisions", {"version": 1, "probes": [], "digest": "e"})
    not_safe.write_meta(status="done", safe_to_ship=False, target="acme")
    no_decisions = store.new()
    no_decisions.write_meta(status="done", safe_to_ship=True, target="acme")
    other_target = store.new()
    other_target.write_json("decisions", {"version": 1, "probes": [], "digest": "f"})
    other_target.write_meta(status="done", safe_to_ship=True, target="another-project")
    assert store.last_approved("acme").id == shipped.id  # never another project's decisions
    assert store.last_approved("unknown") is None


def test_a_run_left_running_by_a_stopped_server_is_marked_interrupted(tmp_path):
    store = RunStore(tmp_path / "runs")
    stale, finished = store.new(), store.new()
    finished.write_meta(status="done")
    assert store.mark_interrupted() == [stale.id]
    assert stale.meta()["status"] == "interrupted" and finished.meta()["status"] == "done"
