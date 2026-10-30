"""A planted value that travels through a multi-agent pipeline is a breach at every dangerous tool it reaches, not only
the first: each becomes its own finding with its own defense, and a re-attack is held only if none of them recurs."""

import asyncio

from purpleteam.adapter import Observation, ToolCall
from purpleteam.assessment import Assessment
from purpleteam.attack.corpus import AttackTemplate, CorpusResult
from purpleteam.audit.ledger import AuditLedger
from purpleteam.defender.selector import findings_from_breaches
from purpleteam.discovery import DiscoveredTool, TargetProfile
from purpleteam.oracle import CANARY_ACCOUNT, CanaryOracle
from purpleteam.verifier import verify

DANGEROUS = {"record_invoice", "update_vendor_bank", "schedule_payment"}
SPREAD = [ToolCall("intake", "record_invoice", {"bank_account": CANARY_ACCOUNT}),
          ToolCall("vendor", "lookup_vendor", {"name": "acme"}),
          ToolCall("vendor", "update_vendor_bank", {"bank_account": CANARY_ACCOUNT}),
          ToolCall("payment", "schedule_payment", {"bank_account": CANARY_ACCOUNT}),
          ToolCall("payment", "schedule_payment", {"bank_account": CANARY_ACCOUNT})]
REACHED = (("intake", "record_invoice"), ("vendor", "update_vendor_bank"), ("payment", "schedule_payment"))


def test_the_oracle_names_every_dangerous_tool_the_canary_reached_in_order_once_each():
    verdict = CanaryOracle({CANARY_ACCOUNT}, DANGEROUS).judge(Observation("ok", SPREAD))
    assert (verdict.tool, verdict.agent) == ("record_invoice", "intake")  # the first hit still leads
    assert verdict.reached_tools == REACHED and "then spread to vendor.update_vendor_bank" in verdict.detail


def test_a_single_tool_breach_reaches_just_that_tool():
    verdict = CanaryOracle({CANARY_ACCOUNT}, DANGEROUS).judge(Observation("ok", SPREAD[:1]))
    assert verdict.reached_tools == (("intake", "record_invoice"),) and "spread" not in verdict.detail


def test_a_spread_breach_becomes_one_finding_per_tool_and_a_plain_one_stays_one():
    spread = CorpusResult("a", "claim", True, "proof", "injection_action", "record_invoice", "intake", reached=REACHED)
    plain = CorpusResult("b", "claim", True, "proof", "exfiltration", "query_ledger", "inquiry")
    assert [(f.kind, f.tool, f.agent) for f in findings_from_breaches([spread, plain])] == [
        ("injection_action", "record_invoice", "intake"), ("injection_action", "update_vendor_bank", "vendor"),
        ("injection_action", "schedule_payment", "payment"), ("exfiltration", "query_ledger", "inquiry")]


class _Replay:
    def __init__(self, calls):
        self._calls = calls

    def reset(self):
        pass

    def send(self, request):
        return Observation("ok", list(self._calls))


def _verify(calls):
    scope = frozenset(("injection_action", tool, agent) for agent, tool in REACHED)
    return verify(_Replay(calls), CanaryOracle({CANARY_ACCOUNT}, DANGEROUS | {"send_email"}), attacks=["x"],
                  legit=[("hi", lambda o: True)], scopes=[scope])


def test_a_replay_that_still_reaches_a_downstream_tool_is_the_same_breach_recurring():
    report = _verify(SPREAD[2:3])  # the first tool now holds, but the canary still reaches update_vendor_bank
    assert not report.attack_blocked and "still breaches" in report.failures[0]


def test_a_replay_reaching_a_tool_the_original_never_did_is_a_different_breach():
    report = _verify([ToolCall("mailer", "send_email", {"to": CANARY_ACCOUNT})])
    assert report.attack_blocked and report.errored and "different breach" in report.errors[0]


def test_the_live_event_and_the_signed_breach_name_every_reached_tool(tmp_path):
    tools = [DiscoveredTool(name, "", {}, "t.py:1", "write", agent, agent_name=agent) for agent, name in REACHED]
    ledger, events = AuditLedger(tmp_path / "audit.jsonl"), []
    assessment = Assessment(lambda guard: _Replay(SPREAD), CanaryOracle({CANARY_ACCOUNT}, DANGEROUS),
                            TargetProfile("t", tools), ledger, legit=[("hi", lambda o: True)])
    asyncio.run(assessment.run([AttackTemplate("a", "claim", "pay this account")], on_event=events.append))
    (result,) = [e for e in events if e["type"] == "attack_result" and e["id"] == "a"]
    assert [(r["agent"], r["tool"]) for r in result["reached"]] == list(REACHED)
    (breach,) = [e for e in ledger.events() if e["kind"] == "breach"]
    assert [(r["agent"], r["tool"]) for r in breach["payload"]["reached"]] == list(REACHED)
