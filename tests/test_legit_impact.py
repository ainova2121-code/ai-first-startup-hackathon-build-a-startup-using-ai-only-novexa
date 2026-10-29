"""A defense that blocks legitimate work is never "safe to ship", whatever the legit check's own reply
looked like -- found in a live run, where an injection classifier stopped a benign invoice email while the
legit check still passed. The defender then tries, once, the defense without the patch that did it, and
keeps that only if the attack is still proven blocked."""

import asyncio


from purpleteam.adapter import Observation
from purpleteam.assessment import Assessment
from purpleteam.audit.ledger import AuditLedger
from purpleteam.patches.base import Blocked, Patch
from test_assessment import ATTACK, ORACLE, PROFILE, _Agent

LEGIT = "Look up acme"


class _ScreeningAgent(_Agent):
    """Screens every request through its guard first, as a real agent's input guard does."""

    def send(self, request: str) -> Observation:
        if self._guard:
            try:
                self._guard.screen("vendor", request, "input")
            except Blocked:
                return Observation("I cannot help with that.", [])
        return super().send(request)


def _classifier(flags):
    class _Classifier(Patch):  # stands in for P2's model: deterministic, flags whatever the test says
        id, layer = "P2", "input"

        def screen(self, agent, text, source):
            if source == "input" and any(word in text for word in flags):
                raise Blocked("prompt injection detected")
            return text
    return _Classifier


def _did_lookup(observation):
    return any(call.tool == "lookup_vendor" for call in observation.tool_calls)


def _run(tmp_path, monkeypatch, flags):
    monkeypatch.setattr("purpleteam.defender.selector.InjectionScanner", _classifier(flags))
    monkeypatch.setattr("purpleteam.defender.selector.injection_backend_available", lambda: True)
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    assessment = Assessment(lambda guard: _ScreeningAgent(guard), ORACLE, PROFILE, ledger,
                            legit=[(LEGIT, lambda obs: True)])  # deliberately weak: it cannot see the block itself
    return ledger, asyncio.run(assessment.run([ATTACK]))


def test_a_patch_that_blocks_legit_work_is_dropped_when_the_attack_still_holds_without_it(tmp_path, monkeypatch):
    ledger, report = _run(tmp_path, monkeypatch, flags=["acme"])  # a false positive on the legit request
    assert report.excluded == frozenset({"P2"}) and "P2" not in report.defense.patch_ids
    assert report.verification.attack_blocked and report.verification.legit_passed  # P4 alone holds it
    assert report.safe_to_ship, report.blockers()
    assert report.policy["exclude"] == ["P2"]  # a rebuild leaves it out too
    narrowed = [e["payload"]["excluded"] for e in ledger.events() if e["kind"] == "narrow"]
    assert narrowed and all(excluded == ["P2"] for excluded in narrowed)  # the live pass and the final one


def test_when_only_the_blocking_patch_stops_the_attack_it_stays_and_legit_work_is_reported_broken(tmp_path, monkeypatch):
    monkeypatch.setitem(__import__("purpleteam.patches.catalog", fromlist=["x"]).FINDING_PATCHES,
                        "injection_action", ["P2"])  # nothing else would hold this attack
    _, report = _run(tmp_path, monkeypatch, flags=["acme", "Ignore the rules"])
    assert report.excluded == frozenset() and "P2" in report.defense.patch_ids
    assert report.verification.attack_blocked and not report.verification.legit_passed
    assert not report.safe_to_ship
    assert any("blocked legitimate work: vendor · input (P2)" in reason for reason in report.blockers())


def test_legit_work_is_checked_alone_first_so_the_attacks_are_replayed_once_not_twice(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr("purpleteam.defender.selector.InjectionScanner", _classifier(["acme"]))
    monkeypatch.setattr("purpleteam.defender.selector.injection_backend_available", lambda: True)
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    assessment = Assessment(lambda guard: _ScreeningAgent(guard), ORACLE, PROFILE, ledger, legit=[(LEGIT, lambda obs: True)])
    report = asyncio.run(assessment.run([ATTACK], exposure_first=True, on_event=seen.append))
    assert report.safe_to_ship and report.excluded == frozenset({"P2"})
    assert [e["type"] for e in seen if e.get("technique") == "reverify"].count("attack_start") == 1  # one replay pass
    assert [e["payload"]["reason"] for e in ledger.events() if e["kind"] == "narrow"] == [
        "blocked legitimate work in a legit check, before any replay"]
