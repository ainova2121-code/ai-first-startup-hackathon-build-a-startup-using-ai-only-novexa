"""The gateway trust-anchoring script: re-anchors the trust file in place, appends to a retained
record when given one, and never corrupts the trust file on a failed anchor."""

import importlib.util
import json
import os
from pathlib import Path

import pytest

from fixtures.ledger import make_ledger
from purpleteam.audit import anchor
from purpleteam.audit.anchor import AnchorError, freetsa, verify_anchored_log
from purpleteam.audit.ledger import AuditLedger
from purpleteam.gateway_crypto import save_trust

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "anchor_gateway_trust.py"


def _load():
    spec = importlib.util.spec_from_file_location("anchor_gateway_trust", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _trust_file(tmp_path: Path) -> Path:
    ledger = make_ledger(tmp_path / "audit.jsonl")
    path = tmp_path / "trust.json"
    save_trust(path, ledger.export_trust())
    return path


def test_a_successful_anchor_is_written_back_and_appended_to_the_retained_record(tmp_path, monkeypatch):
    agt = _load()
    trust_path = _trust_file(tmp_path)
    retained = tmp_path / "retained.jsonl"

    monkeypatch.setattr(anchor, "request_anchor",
                        lambda checkpoint, authority, **kw: {"authority": authority.name, "response": "AA=="})

    status = agt.run(trust_path, retained)

    assert status == 0
    saved = json.loads(trust_path.read_text(encoding="utf-8"))
    assert saved["anchors"] == [{"authority": "freetsa", "response": "AA=="}]
    lines = retained.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["checkpoint"] == saved["checkpoint"] and record["anchors"] == saved["anchors"]


def test_without_a_retained_record_the_trust_file_still_gets_the_fresh_anchor(tmp_path, monkeypatch, capsys):
    agt = _load()
    trust_path = _trust_file(tmp_path)
    monkeypatch.setattr(anchor, "request_anchor",
                        lambda checkpoint, authority, **kw: {"authority": authority.name, "response": "AA=="})

    status = agt.run(trust_path)

    assert status == 0
    assert "no retained_record given" in capsys.readouterr().err


def test_every_authority_unreachable_leaves_the_trust_file_untouched(tmp_path, monkeypatch, capsys):
    agt = _load()
    trust_path = _trust_file(tmp_path)
    before = trust_path.read_text(encoding="utf-8")
    monkeypatch.setattr(anchor, "request_anchor", lambda checkpoint, authority, **kw: (_ for _ in ()).throw(
        AnchorError("down")))

    status = agt.run(trust_path)

    assert status == 1 and trust_path.read_text(encoding="utf-8") == before
    assert "down" in capsys.readouterr().err


def test_an_empty_log_with_no_checkpoint_yet_has_nothing_to_anchor(tmp_path, capsys):
    agt = _load()
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps({"keys": {}}), encoding="utf-8")

    assert agt.run(trust_path) == 1
    assert "nothing to anchor" in capsys.readouterr().err


def _anchor(monkeypatch):
    monkeypatch.setattr(anchor, "request_anchor",
                        lambda checkpoint, authority, **kw: {"authority": authority.name, "response": "AA=="})


def test_a_second_anchor_of_a_grown_log_is_accepted(tmp_path, monkeypatch):
    agt = _load()
    _anchor(monkeypatch)
    ledger = make_ledger(tmp_path / "audit.jsonl")
    trust_path = tmp_path / "trust.json"
    save_trust(trust_path, ledger.export_trust())
    retained = tmp_path / "retained.jsonl"
    assert agt.run(trust_path, retained) == 0

    ledger.append("attacker", "attack", {"n": "new"})  # the log grew since the last anchor
    save_trust(trust_path, ledger.export_trust())

    assert agt.run(trust_path, retained) == 0
    assert len(retained.read_text(encoding="utf-8").splitlines()) == 2


def test_a_checkpoint_smaller_than_the_last_retained_one_is_refused(tmp_path, monkeypatch, capsys):
    agt = _load()
    _anchor(monkeypatch)
    trust_path = _trust_file(tmp_path)
    retained = tmp_path / "retained.jsonl"
    assert agt.run(trust_path, retained) == 0
    grown = json.loads(trust_path.read_text(encoding="utf-8"))
    rolled_back = {**grown, "checkpoint": {**grown["checkpoint"], "size": grown["checkpoint"]["size"] - 1}}
    trust_path.write_text(json.dumps(rolled_back), encoding="utf-8")
    before = trust_path.read_text(encoding="utf-8")

    status = agt.run(trust_path, retained)

    assert status == 1 and trust_path.read_text(encoding="utf-8") == before  # left untouched, not laundered
    assert len(retained.read_text(encoding="utf-8").splitlines()) == 1  # no new, misleading entry either
    assert "rollback" in capsys.readouterr().err


def test_a_checkpoint_under_a_different_log_id_is_refused(tmp_path, monkeypatch, capsys):
    agt = _load()
    _anchor(monkeypatch)
    trust_path = _trust_file(tmp_path)
    retained = tmp_path / "retained.jsonl"
    assert agt.run(trust_path, retained) == 0
    swapped = json.loads(trust_path.read_text(encoding="utf-8"))
    swapped["checkpoint"]["log"] = "f" * 32
    trust_path.write_text(json.dumps(swapped), encoding="utf-8")

    status = agt.run(trust_path, retained)

    assert status == 1
    assert "log's id changed" in capsys.readouterr().err


def test_a_corrupt_retained_record_fails_loud_rather_than_being_read_as_empty(tmp_path, monkeypatch):
    agt = _load()
    _anchor(monkeypatch)
    trust_path = _trust_file(tmp_path)
    retained = tmp_path / "retained.jsonl"
    retained.write_text("not json\n", encoding="utf-8")

    with pytest.raises(Exception):
        agt.run(trust_path, retained)


def test_main_needs_one_or_two_positional_arguments(monkeypatch):
    agt = _load()
    monkeypatch.setattr(agt.sys, "argv", ["anchor_gateway_trust.py"])
    with pytest.raises(SystemExit) as excinfo:
        agt._main()
    assert excinfo.value.code == 2


@pytest.mark.skipif(os.environ.get("PURPLETEAM_LIVE_TSA") != "1", reason="live network test; set PURPLETEAM_LIVE_TSA=1")
def test_live_round_trip_actually_anchors_and_verifies(tmp_path):
    agt = _load()
    trust_path = _trust_file(tmp_path)

    assert agt.run(trust_path) == 0

    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    events = AuditLedger(trust_path.parent / "audit.jsonl").events()
    result = verify_anchored_log(events, trust, {"freetsa": freetsa()}, min_anchors=1)
    assert result.ok and result.anchored
