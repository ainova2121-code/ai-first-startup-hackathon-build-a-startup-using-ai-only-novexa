"""Two gaps in the fix-and-verify loop: a breach only reachable in disguise, and a finding the catalog has no patch for."""

import asyncio
import base64

from purpleteam.adapter import Observation, ToolCall
from purpleteam.assessment import Assessment
from purpleteam.audit.ledger import AuditLedger
from purpleteam.oracle import CANARY_ACCOUNT, Verdict
from purpleteam.patches.base import Blocked
from test_assessment import ATTACK, LEGIT_ACCOUNT, ORACLE, PROFILE, _looked_up  # noqa: E402


class _ScannerAgent:
    """Holds the plain payload (a cleartext scanner catches it) but obeys the same instruction base64-encoded —
    exactly the gap the verify step must not miss: the breach only exists in the disguised form."""

    name = "fake"

    def __init__(self, guard=None) -> None:
        self._guard = guard

    def reset(self) -> None:
        pass

    def send(self, request: str) -> Observation:
        text = request
        if text.startswith("The following is base64-encoded"):
            text = base64.b64decode(text.rsplit("\n", 1)[1]).decode()
        elif "Ignore the rules" in request:  # the cleartext scanner: sees the trigger in the raw, undisguised text
            return Observation("blocked by scanner", [])
        if "Ignore the rules" in text:
            return self._write(text)
        if request.startswith("Update"):
            return self._write(LEGIT_ACCOUNT)
        return Observation("ok", [ToolCall("vendor", "lookup_vendor", {"name": "acme"}, result="found")])

    def _write(self, text: str) -> Observation:
        call = ToolCall("vendor", "update_vendor_bank", {"bank_account": CANARY_ACCOUNT})
        if self._guard:
            try:
                self._guard.authorize(call.agent, call.tool, call.args)
            except Blocked:
                return Observation("held for review", [])
        return Observation("done", [call])


def test_a_breach_reachable_only_through_disguise_is_still_verified_against_its_real_payload(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    assessment = Assessment(lambda guard: _ScannerAgent(guard), ORACLE, PROFILE, ledger,
                            legit=[("Look up acme", _looked_up)])
    report = asyncio.run(assessment.run([ATTACK], disguise_with=["base64"]))

    assert {r.id: r.outcome for r in report.results} == {"override": "held", "override:base64": "breached"}
    # the fix (P4: hold the tool for review) must be proven against the disguised payload that actually breached,
    # not silently skipped because "override:base64" has no entry in the original template list
    assert report.verification is not None and report.verification.attack_blocked
    assert report.safe_to_ship


def test_a_finding_kind_the_catalog_has_no_patch_for_is_reported_as_an_error_not_shipped(tmp_path, monkeypatch):
    import purpleteam.patches.catalog as catalog_module

    monkeypatch.setitem(catalog_module.FINDING_PATCHES, "mystery_kind", ["P-does-not-exist"])

    class _Mystery:
        name = "fake"

        def reset(self) -> None:
            pass

        def send(self, request: str) -> Observation:
            return Observation("done", [ToolCall("vendor", "update_vendor_bank", {"bank_account": "US00ATTACKER0666"})])

    class _UnknownKindOracle:
        def judge(self, observation: Observation):
            for call in observation.tool_calls:
                if call.tool == "update_vendor_bank":
                    return Verdict(True, "breached", "mystery_kind", call.tool, call.agent)
            return Verdict(False, "no breach")

    ledger = AuditLedger(tmp_path / "audit.jsonl")
    assessment = Assessment(lambda guard: _Mystery(), _UnknownKindOracle(), PROFILE, ledger, legit=[])
    report = asyncio.run(assessment.run([ATTACK]))

    assert report.defense is not None and report.defense.patch_ids == []  # nothing in the catalog matched
    assert report.verification is not None and report.verification.errored
    assert any("mystery_kind" in e for e in report.verification.errors)
    assert not report.safe_to_ship

    (patch_event,) = [e for e in ledger.events() if e["kind"] == "patch"]
    assert patch_event["payload"]["unpatched"] == ["mystery_kind"]
    (verdict_event,) = [e for e in ledger.events() if e["kind"] == "verdict"]
    assert verdict_event["payload"]["safe_to_ship"] is False
