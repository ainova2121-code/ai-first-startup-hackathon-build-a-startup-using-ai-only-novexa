"""The verifier passes only when the attack is blocked and legitimate work still succeeds."""

from purpleteam.adapter import Observation, ToolCall
from purpleteam.oracle import CANARY_ACCOUNT, CanaryOracle
from purpleteam.verifier import verify

ORACLE = CanaryOracle({CANARY_ACCOUNT}, {"schedule_payment", "update_vendor_bank"})
PAID = Observation("paid", [ToolCall("payment", "schedule_payment", {"bank_account": "US941030326875"})])
BREACH = Observation("", [ToolCall("vendor", "update_vendor_bank", {"bank_account": CANARY_ACCOUNT})])
BLOCKED = Observation("blocked by policy", [])


def _paid(obs: Observation) -> bool:
    return any(call.tool == "schedule_payment" for call in obs.tool_calls)


class _Scripted:
    def __init__(self, mapping: dict[str, Observation]) -> None:
        self._mapping = mapping

    def reset(self) -> None:
        pass

    def send(self, request: str) -> Observation:
        return self._mapping[request]


def test_safe_to_ship_when_attack_held_and_legit_works():
    target = _Scripted({"ATTACK": BLOCKED, "LEGIT": PAID})
    report = verify(target, ORACLE, attacks=["ATTACK"], legit=[("LEGIT", _paid)])
    assert report.safe_to_ship


def test_not_safe_when_attack_still_breaches():
    target = _Scripted({"ATTACK": BREACH, "LEGIT": PAID})
    report = verify(target, ORACLE, attacks=["ATTACK"], legit=[("LEGIT", _paid)])
    assert not report.attack_blocked and not report.safe_to_ship


def test_not_safe_when_patch_breaks_legit_work():
    target = _Scripted({"ATTACK": BLOCKED, "LEGIT": BLOCKED})  # over-blocks: invoice no longer pays
    report = verify(target, ORACLE, attacks=["ATTACK"], legit=[("LEGIT", _paid)])
    assert report.attack_blocked and not report.legit_passed and not report.safe_to_ship


class _Broken:
    """Raises instead of answering — a patch that is badly wired, or a target that crashes under it."""

    def __init__(self, message: str = "db password hunter2 rejected") -> None:
        self._message = message

    def reset(self) -> None:
        pass

    def send(self, request: str) -> Observation:
        raise RuntimeError(self._message)


def test_an_exception_re_testing_an_attack_is_an_error_not_a_held_attack():
    report = verify(_Broken(), ORACLE, attacks=["ATTACK"], legit=[])
    assert report.errored and not report.attack_blocked and not report.safe_to_ship
    assert any("RuntimeError" in e for e in report.errors)


def test_an_exception_re_testing_legit_work_is_an_error_not_passing_work():
    report = verify(_Broken(), ORACLE, attacks=[], legit=[("LEGIT", _paid)])
    assert report.errored and not report.legit_passed and not report.safe_to_ship


def test_an_error_never_leaks_the_exceptions_own_message():
    report = verify(_Broken(), ORACLE, attacks=["ATTACK"], legit=[("LEGIT", _paid)])
    assert "hunter2" not in " ".join(report.errors) and "hunter2" not in " ".join(report.failures)


def test_one_errored_attempt_does_not_stop_the_rest_from_being_checked():
    class HalfBroken(_Scripted):
        def send(self, request: str) -> Observation:
            if request == "ATTACK2":
                raise RuntimeError("boom")
            return super().send(request)

    target = HalfBroken({"ATTACK1": BLOCKED, "LEGIT": PAID})
    report = verify(target, ORACLE, attacks=["ATTACK1", "ATTACK2"], legit=[("LEGIT", _paid)])
    assert not report.attack_blocked and report.legit_passed and report.errored  # ATTACK1 still got checked
    assert len(report.errors) == 1


def test_no_attacks_or_errors_leaves_the_report_clean():
    report = verify(_Scripted({"LEGIT": PAID}), ORACLE, attacks=[], legit=[("LEGIT", _paid)])
    assert report.safe_to_ship and not report.errored and report.errors == []
