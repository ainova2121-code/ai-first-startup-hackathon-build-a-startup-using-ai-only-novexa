"""The target overview shown after sign-in: the target in its owner's words and what discovery finds -- agents in build
order, their tools and risk, the data it starts with -- with no model call and nothing about what may be exploitable."""

from fastapi.testclient import TestClient

from purpleteam import live_demo
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.run_history import RunStore


def _client(tmp_path, login=False):
    app = live_demo.create_app(SourceSnapshots(tmp_path / "s.json"), tmp_path / "lp", RunStore(tmp_path / "runs"),
                               login=login)
    return TestClient(app, base_url="https://demo.test")


def test_the_overview_describes_the_target_from_its_owner_and_from_discovery(tmp_path, monkeypatch):
    monkeypatch.delenv("LEDGERPILOT_LLM_API_KEY", raising=False)
    monkeypatch.delenv("HF_TOKEN", raising=False)  # no model is needed to describe the target
    data = _client(tmp_path).get("/target/overview").json()
    assert data["title"] == "LedgerPilot" and data["paragraphs"] and "accounts-payable" in data["paragraphs"][0]
    assert [a["name"] for a in data["agents"]] == ["intake", "vendor", "matching", "approval", "payment", "inquiry"]
    vendor = next(a for a in data["agents"] if a["name"] == "vendor")
    assert {t["name"]: t["risk"] for t in vendor["tools"]}["lookup_vendor"] == "read"
    assert data["totals"]["agents"] == 6 and data["totals"]["tools"] == 14 and data["totals"]["acting"] > 0
    assert {t["name"]: t["rows"] for t in data["tables"]}["vendors"] == 15  # the planted decoy vendor is not counted
    assert "findings" not in data and "ZZ-CANARY" not in str(data)  # the run finds weaknesses; this page does not


def test_the_page_is_served_and_a_fresh_sign_in_lands_on_it(tmp_path):
    client = _client(tmp_path, login=True)
    assert client.get("/target", follow_redirects=False).status_code == 401  # behind the login like everything else
    assert client.post("/login", follow_redirects=False).headers["location"] == "/target"
    page = client.get("/target")
    assert page.status_code == 200 and "Open the console" in page.text
    assert client.get("/").status_code == 200  # the console itself is still one click away


def test_the_picker_lists_the_runnable_targets_in_their_owners_words_without_discovery(tmp_path, monkeypatch):
    from purpleteam import target_api
    monkeypatch.setattr(target_api, "discover_profile", lambda: (_ for _ in ()).throw(AssertionError("no discovery")))
    targets = _client(tmp_path).get("/targets").json()
    assert [t["id"] for t in targets] == ["ledgerpilot"]
    assert targets[0]["title"] == "LedgerPilot" and "accounts-payable" in targets[0]["paragraphs"][0]
    assert _client(tmp_path, login=True).get("/targets", follow_redirects=False).status_code == 401
