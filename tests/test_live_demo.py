"""The live demo page: routes, the one-shot restore of edited target files, the discovery payload,
and the SSE generator tested directly (per test_console_sse.py: reading an infinite-generator route
through TestClient hangs, so only the parts that do not need a real stream go through HTTP).
"""

import asyncio

import pytest
from fastapi.testclient import TestClient

from purpleteam import live_demo
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.discovery import AgentInfo, DiscoveredTool, TargetProfile
from purpleteam.run_history import RunStore


@pytest.fixture(autouse=True)
def _no_real_reload(monkeypatch):
    monkeypatch.setattr(live_demo, "reload_source", lambda: None)  # never swap loaded modules in these tests


def _app(tmp_path, repo=None):
    return live_demo.create_app(SourceSnapshots(tmp_path / "snapshots.json"), repo or tmp_path / "ledgerpilot",
                                RunStore(tmp_path / "runs"))


def _client(tmp_path) -> TestClient:
    return TestClient(_app(tmp_path))


def test_index_and_its_static_assets_are_served(tmp_path):
    client = _client(tmp_path)
    response = client.get("/")
    assert response.status_code == 200
    assert "Start run" in response.text and "purpleteam" in response.text
    assert client.get("/static/app.js").status_code == 200 and client.get("/static/app.css").status_code == 200


def test_each_component_is_streamed_the_moment_the_target_constructs_it():
    from purpleteam.targets.ledgerpilot import discover_profile

    streamed = []
    profile = discover_profile(on_found=lambda agent, tools: streamed.extend(live_demo.found_events(agent, tools)))
    agents = [e["name"] for e in streamed if e["type"] == "found_agent"]
    tools = [(e["agent"], e["tool"]["name"]) for e in streamed if e["type"] == "found_tool"]
    assert sorted(agents) == sorted(a.name for a in profile.agent_info)
    assert sorted(tools) == sorted((t.agent, t.name) for t in profile.tools)
    for agent in profile.agent_info:  # each agent arrives before its own tools, never its prompt's text
        first = next(i for i, e in enumerate(streamed) if e["type"] == "found_agent" and e["name"] == agent.name)
        assert all(i > first for i, e in enumerate(streamed) if e["type"] == "found_tool" and e["agent"] == agent.name)
    assert not any(agent.prompt and agent.prompt in str(streamed) for agent in profile.agent_info)


def test_a_traced_target_reports_each_requests_calls_in_order_and_changes_nothing():
    from purpleteam.adapter import Observation, ToolCall, TracedTarget

    class _Target:
        name = "t"

        def send(self, request):
            return Observation("ok", [ToolCall("intake", "read_email", {}), ToolCall("vendor", "lookup_vendor", {})])

    traces = []
    observation = TracedTarget(_Target(), traces.append).send("hi")
    assert traces == [[("intake", "read_email"), ("vendor", "lookup_vendor")]]
    assert observation.reply == "ok" and TracedTarget(_Target(), traces.append).name == "t"


def test_restore_puts_every_edited_target_file_back_in_one_step(tmp_path):
    repo = tmp_path / "ledgerpilot"
    (repo / "db").mkdir(parents=True)
    (repo / "db" / "repositories.py").write_bytes(b"patched\n")  # exactly what the platform wrote
    snapshots = SourceSnapshots(tmp_path / "snapshots.json")
    snapshots.record("db/repositories.py", "original\n", "patched\n")
    client = TestClient(live_demo.create_app(snapshots, repo, RunStore(tmp_path / "runs")))

    assert client.get("/source-status").json() == {"modified": ["ledgerpilot/db/repositories.py"]}
    body = client.post("/restore").json()

    assert body["results"] == [{"path": "ledgerpilot/db/repositories.py", "status": "restored"}]
    assert body["modified"] == [] and (repo / "db" / "repositories.py").read_text() == "original\n"


def test_restore_is_refused_while_a_run_is_editing(tmp_path):
    app = _app(tmp_path)
    app.state.run.running = True
    assert TestClient(app).post("/restore").status_code == 409


def test_the_discovery_event_shows_agents_tools_and_surfaces_but_never_prompt_text():
    profile = TargetProfile("acme", [
        DiscoveredTool("search_docs", "Search the knowledge base. More text.", {}, "docs.py:3", "read", "kb",
                       agent_name="kb", retrieval=True),
        DiscoveredTool("save_memory", "Store a note.", {}, "mem.py:9", "write", "kb", agent_name="kb", memory=True),
    ], [AgentInfo("kb", "SECRET PROMPT TEXT", ("search_docs", "save_memory"))])

    event = live_demo.discovery_event(profile, {"kb": "one db connection"})

    assert event["target"] == "acme" and event["totals"]["retrieval"] == 1 and event["totals"]["memory"] == 1
    (agent,) = event["agents"]
    tools = {t["name"]: t for t in agent["tools"]}
    assert tools["search_docs"]["description"] == "Search the knowledge base" and tools["save_memory"]["memory"]
    assert tools["search_docs"]["source"] == "docs.py:3" and agent["prompt_chars"] == len("SECRET PROMPT TEXT")
    assert "SECRET PROMPT TEXT" not in str(event)


def test_a_second_run_while_one_is_in_progress_is_refused(tmp_path):
    app = _app(tmp_path)
    app.state.run.running = True
    response = TestClient(app).post("/run")
    assert response.status_code == 409


def test_a_run_starts_and_clears_the_in_progress_flag_when_it_finishes(monkeypatch, tmp_path):
    import time

    seen = {}

    async def fake_execute(state, snapshots):
        seen["ran"] = True
        state.running = False

    monkeypatch.setattr(live_demo, "_execute", fake_execute)
    app = _app(tmp_path)
    response = TestClient(app).post("/run")
    assert response.status_code == 200 and response.json()["started"] is True
    run_id = response.json()["run_id"]
    client = TestClient(app)
    assert client.get("/runs").json()["current"] == run_id
    assert client.get(f"/runs/{run_id}/events").json()["events"][0] == {"type": "run_started", "run_id": run_id,
                                                                        "mode": "full"}
    assert client.get("/runs/not-a-run/ledger").status_code == 404
    for _ in range(50):
        if seen.get("ran"):
            break
        time.sleep(0.02)
    assert seen.get("ran") is True  # the background task really ran
    assert app.state.run.running is False


def test_sse_formats_a_published_event_as_a_json_data_frame():
    state = live_demo._RunState()

    async def scenario():
        gen = live_demo._sse(state)

        async def publish_soon():
            await asyncio.sleep(0.02)
            state.publish({"type": "attack_start", "id": "dan_1", "payload": "hello"})

        asyncio.create_task(publish_soon())
        return await gen.__anext__()

    chunk = asyncio.run(asyncio.wait_for(scenario(), timeout=2))
    assert chunk == 'data: {"type": "attack_start", "id": "dan_1", "payload": "hello"}\n\n'


def test_sse_replays_events_already_published_before_this_client_connected():
    """The bug this guards against: a dropped connection (a reload, a network blip -- browsers
    auto-reconnect EventSource) used to silently lose every event published while it was down,
    since a fresh subscribe() only ever sees what is published after it."""
    state = live_demo._RunState()
    state.publish({"type": "attack_start", "id": "dan_1", "payload": "hello"})
    state.publish({"type": "attack_result", "id": "dan_1", "breached": False})

    async def scenario():
        gen = live_demo._sse(state)
        return [await gen.__anext__(), await gen.__anext__()]

    chunks = asyncio.run(asyncio.wait_for(scenario(), timeout=2))
    assert chunks == ['data: {"type": "attack_start", "id": "dan_1", "payload": "hello"}\n\n',
                      'data: {"type": "attack_result", "id": "dan_1", "breached": false}\n\n']


def test_sse_unsubscribes_when_the_connection_is_cancelled():
    state = live_demo._RunState()

    async def scenario():
        gen = live_demo._sse(state)
        task = asyncio.create_task(gen.__anext__())
        await asyncio.sleep(0.02)
        assert len(state.broadcaster._subscribers) == 1
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert len(state.broadcaster._subscribers) == 0

    asyncio.run(asyncio.wait_for(scenario(), timeout=2))


def test_app_factory_refuses_to_start_without_a_configured_target_model(monkeypatch):
    import pytest

    # pydantic-settings reads .env itself regardless of load_dotenv(); an explicit empty env var
    # outranks a .env value (this machine's real .env has a real key, needed for the actual demo).
    monkeypatch.setenv("LEDGERPILOT_LLM_API_KEY", "")
    monkeypatch.setenv("HF_TOKEN", "")
    with pytest.raises(RuntimeError, match="no target model is configured"):
        live_demo.app()
