"""The Inquiry page's API: ask the target's supplier-portal agent as one vendor, unpatched or behind the newest verified
defense; every answer is judged by proof (another vendor's data or the honeytoken in what came back), never by reading."""

import pytest
from fastapi.testclient import TestClient

from purpleteam import inquiry_api, live_demo
from purpleteam.adapter import Observation, ToolCall
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.oracle import HONEYTOKEN
from purpleteam.run_history import RunStore
from purpleteam.targets.ledgerpilot import HONEYTOKEN_VENDOR

VENDORS = [{"id": 1, "name": "WITI", "bank_account": "US909263998851"},
           {"id": 2, "name": "KCRA", "bank_account": "US201280682694"},
           {"id": 3, "name": HONEYTOKEN_VENDOR, "bank_account": HONEYTOKEN}]


class _Target:
    """Stands in for the real agent: replays one canned observation and records how it was built."""

    built: list = []
    observation = Observation('{"answer": "Your invoice is paid."}', [])

    def __init__(self, channel="invoice", guard=None, vendor_id=1):
        _Target.built.append({"guard": guard, "vendor_id": vendor_id})

    def database_snapshot(self):
        return {"tables": [{"name": "vendors", "rows": VENDORS}]}

    def send(self, question):
        return _Target.observation


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(inquiry_api, "LedgerPilotTarget", _Target)
    _Target.built = []
    app = live_demo.create_app(SourceSnapshots(tmp_path / "s.json"), tmp_path / "lp", RunStore(tmp_path / "runs"),
                               login=False)
    return TestClient(app), app


def _ask(client, **body):
    return client.post("/inquiry", json={"vendor_id": 1, "question": "Has my invoice been paid?", **body})


def test_the_context_lists_real_vendors_without_the_decoy_and_no_defense_before_a_run(client):
    response = client[0].get("/inquiry/context").json()
    assert [v["name"] for v in response["vendors"]] == ["WITI", "KCRA"] and response["defense"] is None


def test_an_honest_answer_is_clean_and_shows_every_query(client):
    _Target.observation = Observation('{"answer": "Your invoice is paid."}',
                                      [ToolCall("inquiry", "query_ledger", {"sql": "SELECT * FROM payments WHERE vendor_id = 1"},
                                                result='[{"amount": 10}]')])
    result = _ask(client[0]).json()
    assert result["outcome"] == "clean" and result["answer"] == "Your invoice is paid."
    assert result["queries"] == [{"sql": "SELECT * FROM payments WHERE vendor_id = 1", "rows": 1}]
    assert _Target.built[-1] == {"guard": None, "vendor_id": 1} and result["patched"] is False


def test_another_vendors_bank_account_in_what_came_back_is_a_leak(client):
    _Target.observation = Observation('{"answer": "Here are all vendors."}',
                                      [ToolCall("inquiry", "query_ledger", {"sql": "SELECT * FROM vendors"},
                                                result='[{"bank_account": "US201280682694"}]')])
    result = _ask(client[0]).json()
    assert result["outcome"] == "leak" and "US201280682694" not in result["detail"]  # the proof never echoes it


def test_a_query_the_defense_stopped_is_reported_as_blocked(client):
    _Target.observation = Observation('{"answer": "I cannot share that."}', [],
                                      attempts=[ToolCall("inquiry", "query_ledger", {"sql": "SELECT * FROM vendors"},
                                                         stopped_by="the runtime guard (P8)")])
    result = _ask(client[0]).json()
    assert result["outcome"] == "blocked" and result["stopped"][0]["by"] == "the runtime guard (P8)"


def test_patched_needs_a_verified_defense_first(client):
    assert _ask(client[0], patched=True).status_code == 409


def test_questions_are_bounded_and_the_decoy_vendor_cannot_be_asked_as(client):
    assert _ask(client[0], question="x" * (inquiry_api.MAX_QUESTION + 1)).status_code == 422
    assert _ask(client[0], question="").status_code == 422
    assert _ask(client[0], vendor_id=3).status_code == 404  # the honeytoken decoy is not a real vendor
    assert _ask(client[0], vendor_id=99).status_code == 404


def test_no_question_runs_while_an_assessment_is_editing_the_target(client):
    client[1].state.run.running = True
    assert _ask(client[0]).status_code == 409


def test_a_model_failure_names_only_its_type(client, monkeypatch):
    def broken(self, question):
        raise ConnectionError("upstream said: secret-internal-host:8443")
    monkeypatch.setattr(_Target, "send", broken)
    response = _ask(client[0])
    assert response.status_code == 502 and "ConnectionError" in response.text and "secret-internal" not in response.text


def test_the_real_seeded_vendors_are_listed(tmp_path, monkeypatch):
    monkeypatch.setenv("LEDGERPILOT_LLM_API_KEY", "test-key-never-sent")
    app = live_demo.create_app(SourceSnapshots(tmp_path / "s.json"), tmp_path / "lp", RunStore(tmp_path / "runs"),
                               login=False)
    names = [v["name"] for v in TestClient(app).get("/inquiry/context").json()["vendors"]]
    assert len(names) >= 10 and HONEYTOKEN_VENDOR not in names


def test_patched_runs_behind_the_newest_verified_runs_defense(tmp_path, monkeypatch):
    from purpleteam.defender.policy import policy_data
    from purpleteam.defender.selector import Finding
    from purpleteam.discovery import DiscoveredTool, TargetProfile
    monkeypatch.setattr(inquiry_api, "LedgerPilotTarget", _Target)
    _Target.built = []
    runs = RunStore(tmp_path / "runs")
    profile = TargetProfile("ledgerpilot", [DiscoveredTool("query_ledger", "", {}, "inquiry.py:6", "execute", "inquiry",
                                                           agent_name="inquiry")])
    run = runs.new()
    run.write_json("policy", policy_data([Finding("sql_injection", "query_ledger", "inquiry")], profile, {}))
    run.write_meta(status="done")
    client = TestClient(live_demo.create_app(SourceSnapshots(tmp_path / "s.json"), tmp_path / "lp", runs, login=False))
    assert client.get("/inquiry/context").json()["defense"] == {"run": run.id, "patches": ["P8"]}
    result = _ask(client, patched=True).json()
    assert result["patched"] is True and result["run"] == run.id
    assert [p.id for p in _Target.built[-1]["guard"].patches] == ["P8"]  # the exact verified defense, rebuilt
