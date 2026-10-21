"""ReasoningDebugLog: the explicit, operator-opted-in place full reasoning text can go — never the
signed ledger (see gateway_policy's "no raw data" rule)."""

import json

from purpleteam.gateway_debug import ReasoningDebugLog


def test_records_reasoning_text_as_a_json_line(tmp_path):
    log = ReasoningDebugLog(tmp_path / "reasoning.jsonl")

    log.record(agent="vendor", model="gpt-5", reasoning="Checking the vendor record first.", redacted=False)

    lines = (tmp_path / "reasoning.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["agent"] == "vendor" and entry["model"] == "gpt-5"
    assert entry["reasoning"] == "Checking the vendor record first." and entry["redacted"] is False
    assert isinstance(entry["ts"], float)


def test_skips_when_there_is_no_reasoning_and_nothing_was_redacted(tmp_path):
    path = tmp_path / "reasoning.jsonl"
    log = ReasoningDebugLog(path)

    log.record(agent="vendor", model="gpt-5", reasoning="", redacted=False)

    assert not path.exists()


def test_redacted_reasoning_is_still_recorded_even_with_no_text(tmp_path):
    path = tmp_path / "reasoning.jsonl"
    log = ReasoningDebugLog(path)

    log.record(agent="vendor", model="claude", reasoning="", redacted=True)

    entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert entry["redacted"] is True and entry["reasoning"] == ""


def test_multiple_records_append_as_separate_lines(tmp_path):
    path = tmp_path / "reasoning.jsonl"
    log = ReasoningDebugLog(path)

    log.record(agent="vendor", model="gpt-5", reasoning="Step one.", redacted=False)
    log.record(agent="matching", model="gpt-5", reasoning="Step two.", redacted=False)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["reasoning"] for line in lines] == ["Step one.", "Step two."]
