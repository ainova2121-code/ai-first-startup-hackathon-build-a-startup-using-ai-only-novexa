"""A past run's pinned decisions can be read back, and what-if questions asked of its exact policy."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from purpleteam.decisions import ATTACK, LEGIT, DecisionRecorder, ProbeLog, take_baseline
from purpleteam.defender.policy import policy_data
from purpleteam.defender.selector import Defender, Finding
from purpleteam.discovery import DiscoveredTool, TargetProfile
from purpleteam.drift_api import drift_routes
from purpleteam.patches.base import Blocked
from purpleteam.run_history import RunStore

PROFILE = TargetProfile("fake", [DiscoveredTool("update_vendor_bank", "", {}, "", "write", "vendor"),
                                 DiscoveredTool("lookup_vendor", "", {}, "", "read", "vendor")])
FINDINGS = [Finding("injection_action", "update_vendor_bank", "vendor", "canary reached it")]


def _client(tmp_path, *, tamper=False, policy=True):
    runs = RunStore(tmp_path / "runs")
    run = runs.new()

    def factory():
        return Defender(PROFILE, {}).select_all(FINDINGS).guard

    log = ProbeLog()
    try:
        DecisionRecorder(factory(), log, ATTACK).authorize("vendor", "update_vendor_bank", {"account": "US00ATTACKER0666"})
    except Blocked:
        pass
    DecisionRecorder(factory(), log, LEGIT).authorize("vendor", "lookup_vendor", {"name": "acme"})
    baseline = take_baseline(log, factory, sorted([e["id"], e["hash"]] for e in Defender(PROFILE, {})
                                                  .select_all(FINDINGS).applied))
    if tamper:
        baseline["probes"][0]["outcome"] = "error"
    run.write_json("decisions", baseline)
    if policy:
        run.write_json("policy", policy_data(FINDINGS, PROFILE, {}))
    app = FastAPI()
    app.include_router(drift_routes(runs))
    return TestClient(app), run.id


def test_a_runs_pinned_decisions_are_summarised(tmp_path):
    client, run_id = _client(tmp_path)
    body = client.get(f"/runs/{run_id}/decisions").json()
    assert body["probes"] == 2 and body["origins"] == {"attack": 1, "legit": 1} and "P4" in body["patches"]


def test_removing_the_patch_that_held_the_attack_shows_a_high_severity_flip(tmp_path):
    client, run_id = _client(tmp_path)
    body = client.post(f"/runs/{run_id}/what-if", json={"without": ["P4"]}).json()
    assert body["counts"]["high"] == 1 and body["flips"][0]["tool"] == "update_vendor_bank"
    assert client.post(f"/runs/{run_id}/what-if", json={"without": []}).json()["flips"] == []


def test_what_if_rejects_patches_the_policy_never_had_and_malformed_ids(tmp_path):
    client, run_id = _client(tmp_path)
    assert client.post(f"/runs/{run_id}/what-if", json={"without": ["P99"]}).status_code == 422
    assert client.post(f"/runs/{run_id}/what-if", json={"without": ["../x"]}).status_code == 422


def test_an_altered_decision_file_is_refused(tmp_path):
    client, run_id = _client(tmp_path, tamper=True)
    response = client.post(f"/runs/{run_id}/what-if", json={"without": ["P4"]})
    assert response.status_code == 409 and "altered" in response.json()["detail"]


def test_unknown_runs_and_runs_without_a_policy_are_404(tmp_path):
    client, run_id = _client(tmp_path, policy=False)
    assert client.get("/runs/20990101T000000-abcdef/decisions").status_code == 404
    assert client.post(f"/runs/{run_id}/what-if", json={"without": ["P4"]}).status_code == 404
