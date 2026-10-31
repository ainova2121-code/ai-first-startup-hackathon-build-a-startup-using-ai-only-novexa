"""The Showcase suite picks what breached in the target's latest earlier run with a breach, plus attacks that held as
controls, from today's dataset -- and refuses to start when there is nothing to show, never running an empty suite."""

import time

import pytest
from fastapi.testclient import TestClient

from purpleteam import live_demo
from purpleteam.attack.corpus import AttackTemplate
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.run_history import RunStore
from purpleteam.showcase import available, showcase

POOL = [AttackTemplate(f"claim:field:{i}", "claim", f"claim {i}") for i in range(1, 10)] + [
    AttackTemplate("jailbreak:dan:1", "jailbreak", "dan"), AttackTemplate("jailbreak:aim:1", "jailbreak", "aim")]


def _run(runs, results, target="ledgerpilot"):
    run = runs.new()
    run.write_meta(target=target)
    for result_id, outcome, technique in results:
        run.record({"type": "attack_result", "id": result_id, "technique": technique,
                    "breached": outcome == "breached", "outcome": outcome})
    time.sleep(0.01)  # runs are ordered by start time
    return run


def test_it_picks_the_latest_breaches_and_controls_from_other_kinds(tmp_path):
    runs = RunStore(tmp_path)
    _run(runs, [("claim:field:9", "breached", "claim")])  # older: not used
    _run(runs, [(f"claim:field:{i}", "breached", "claim") for i in range(1, 9)]
         + [("claim:field:9", "held", "claim"), ("jailbreak:dan:1", "held", "jailbreak"),
            ("jailbreak:aim:1", "held", "jailbreak"), ("claim:field:1", "breached", "reverify")])
    _run(runs, [("claim:field:1", "inconclusive", "claim")])  # newest, but nothing breached: skipped
    picked = [t.id for t in showcase(runs, "ledgerpilot", POOL)]
    assert picked == [f"claim:field:{i}" for i in range(1, 7)] + ["jailbreak:dan:1", "jailbreak:aim:1"]


def test_another_targets_runs_and_re_attacks_never_count(tmp_path):
    runs = RunStore(tmp_path)
    _run(runs, [("claim:field:1", "breached", "claim")], target="other")
    _run(runs, [("claim:field:1", "breached", "reverify")])
    assert not available(runs, "ledgerpilot")
    with pytest.raises(ValueError, match="no earlier run"):
        showcase(runs, "ledgerpilot", POOL)


def test_starting_a_showcase_with_nothing_to_show_is_refused_before_anything_runs(tmp_path):
    app = live_demo.create_app(SourceSnapshots(tmp_path / "s.json"), tmp_path / "lp", RunStore(tmp_path / "runs"),
                               login=False)
    response = TestClient(app).post("/run?mode=full&attack_type=showcase")
    assert response.status_code == 422 and "Nothing to showcase" in response.json()["detail"]
