"""A persisted regression corpus: every proven breach is kept, deduplicated by content, loaded
back faithfully, and a corrupt store fails loud rather than being read as empty."""

import pytest

from purpleteam.attack.corpus import CorpusResult
from purpleteam.attack.regressions import RegressionCase, case_id, load_regressions, record_breaches, retest_against
from purpleteam.oracle import Verdict


def _breach(kind="injection_action", tool="update_vendor_bank", agent="vendor", payload="attack text") -> CorpusResult:
    return CorpusResult("id", "jailbreak", True, "breached", kind=kind, tool=tool, agent=agent, payload=payload)


class _FakeTarget:
    def __init__(self):
        self.sent, self.resets = [], 0

    def reset(self):
        self.resets += 1

    def send(self, payload):
        return payload


class _FailingTarget(_FakeTarget):
    def send(self, payload):
        raise RuntimeError("target crashed")


class _FakeOracle:
    def __init__(self, reproduces: set[str]) -> None:
        self._reproduces = reproduces

    def judge(self, observation) -> Verdict:
        breached = observation in self._reproduces
        return Verdict(breached, "breached" if breached else "held", kind="k", tool="t", agent="a")


def test_loading_with_no_path_or_a_missing_file_returns_nothing(tmp_path):
    assert load_regressions(None) == []
    assert load_regressions(tmp_path / "does-not-exist.json") == []


def test_recording_with_no_path_is_a_no_op_and_creates_nothing(tmp_path):
    assert record_breaches(None, [_breach()]) == []
    assert list(tmp_path.iterdir()) == []


def test_a_breach_is_recorded_and_loads_back_identically(tmp_path):
    path = tmp_path / "regressions.json"
    added = record_breaches(path, [_breach()])
    assert len(added) == 1
    loaded = load_regressions(path)
    assert loaded == added


def test_recording_the_same_breach_twice_does_not_duplicate(tmp_path):
    path = tmp_path / "regressions.json"
    record_breaches(path, [_breach()])
    second = record_breaches(path, [_breach()])
    assert second == []  # nothing new was added
    assert len(load_regressions(path)) == 1


def test_two_distinct_breaches_produce_two_distinct_cases(tmp_path):
    path = tmp_path / "regressions.json"
    record_breaches(path, [_breach(tool="a"), _breach(tool="b")])
    cases = load_regressions(path)
    assert len(cases) == 2 and cases[0].id != cases[1].id


def test_breaches_with_no_payload_are_skipped(tmp_path):
    path = tmp_path / "regressions.json"
    added = record_breaches(path, [_breach(payload="")])
    assert added == [] and not path.exists()


def test_case_id_is_deterministic_and_content_sensitive():
    first = case_id("k", "t", "a", "p")
    assert case_id("k", "t", "a", "p") == first
    assert case_id("k", "t", "a", "different") != first


def test_a_malformed_store_fails_loud_instead_of_reading_as_empty(tmp_path):
    path = tmp_path / "regressions.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="not readable JSON"):
        load_regressions(path)


def test_a_store_that_is_not_a_list_fails_loud(tmp_path):
    path = tmp_path / "regressions.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="does not hold a list"):
        load_regressions(path)


def test_a_case_missing_a_field_fails_loud(tmp_path):
    path = tmp_path / "regressions.json"
    path.write_text('[{"id": "x", "kind": "k"}]', encoding="utf-8")
    with pytest.raises(ValueError, match="malformed case"):
        load_regressions(path)


def test_recording_several_breaches_at_once_adds_each_once(tmp_path):
    path = tmp_path / "regressions.json"
    added = record_breaches(path, [_breach(tool="a"), _breach(tool="b"), _breach(tool="a")])
    assert len(added) == 2  # the repeated "a" breach is only added once
    assert len(load_regressions(path)) == 2


def test_a_recorded_case_is_a_regressioncase_with_the_right_fields(tmp_path):
    path = tmp_path / "regressions.json"
    (case,) = record_breaches(path, [_breach()])
    assert isinstance(case, RegressionCase)
    assert (case.kind, case.tool, case.agent, case.payload) == ("injection_action", "update_vendor_bank",
                                                                 "vendor", "attack text")


def _case(payload="attack text") -> RegressionCase:
    return RegressionCase(case_id("k", "t", "a", payload), "k", "t", "a", payload)


def test_retest_against_reports_a_case_that_still_reproduces():
    case = _case()
    target, oracle = _FakeTarget(), _FakeOracle(reproduces={case.payload})

    breaches, log = retest_against([case], target, oracle)

    assert len(breaches) == 1 and breaches[0].breached and breaches[0].technique == "regression"
    assert log == [{"id": case.id, "kind": "k", "reproduced": True}]
    assert target.resets == 1  # reset before sending, same as any other re-test


def test_retest_against_does_not_report_a_case_that_no_longer_reproduces():
    case = _case()
    target, oracle = _FakeTarget(), _FakeOracle(reproduces=set())  # nothing reproduces

    breaches, log = retest_against([case], target, oracle)

    assert breaches == []
    assert log == [{"id": case.id, "kind": "k", "reproduced": False}]


def test_retest_against_logs_an_error_without_asserting_a_breach():
    case = _case()
    breaches, log = retest_against([case], _FailingTarget(), _FakeOracle(reproduces={case.payload}))

    assert breaches == []  # an error is never evidence of a breach
    assert log == [{"id": case.id, "kind": "k", "reproduced": None, "error": "RuntimeError"}]


def test_retest_against_handles_several_cases_independently():
    reproduces, held = _case("still vulnerable"), _case("now fixed")
    target, oracle = _FakeTarget(), _FakeOracle(reproduces={"still vulnerable"})

    breaches, log = retest_against([reproduces, held], target, oracle)

    assert [b.id for b in breaches] == [reproduces.id]
    assert [entry["reproduced"] for entry in log] == [True, False]


def test_retest_against_with_no_cases_does_nothing():
    assert retest_against([], _FakeTarget(), _FakeOracle(reproduces=set())) == ([], [])
