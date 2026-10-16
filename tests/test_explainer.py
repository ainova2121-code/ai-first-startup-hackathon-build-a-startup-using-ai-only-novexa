"""The explainer's output is verified against the facts: faithful passes, hallucinations fail."""

from purpleteam.defender.selector import Defender, Finding
from purpleteam.discovery import DiscoveredTool, TargetProfile
from purpleteam.explainer import explain, gather_facts, verify_explanation
from purpleteam.oracle import CANARY_ACCOUNT

FINDING = Finding("injection_action", "update_vendor_bank", "vendor",
                  "canary reached update_vendor_bank.bank_account")
PROFILE = TargetProfile("lp", [DiscoveredTool("update_vendor_bank", "", {}, "", "write", "vendor")])
DEFENSE = Defender(PROFILE).select(FINDING)  # applies P4 (and P2 if the backend is present)
FACTS = gather_facts(FINDING, DEFENSE)

_PATCHES = " and ".join(p["id"] for p in FACTS["patches"])
_CLAUSES = ", ".join(FACTS["regulation"])
FAITHFUL = (f"What happened: the vendor agent called update_vendor_bank via a prompt injection. "
            f"Why it matters: a payment could be redirected. What stops it: {_PATCHES}. "
            f"Regulation: {_CLAUSES}.")


def test_faithful_explanation_verifies():
    ok, issues = verify_explanation(FAITHFUL, FACTS)
    assert ok, issues


def test_missing_patch_is_caught():
    text = FAITHFUL.replace(_PATCHES, "nothing in particular")
    ok, issues = verify_explanation(text, FACTS)
    assert not ok and any("missing fact" in i for i in issues)


def test_invented_patch_is_caught():
    ok, issues = verify_explanation(FAITHFUL + " We also applied P99.", FACTS)
    assert not ok and any("unsupported claim: P99" in i for i in issues)


def test_leaked_secret_is_caught():
    ok, issues = verify_explanation(FAITHFUL + f" Account {CANARY_ACCOUNT}.", FACTS)
    assert not ok and any("leaked" in i for i in issues)


def test_explain_accepts_a_verified_generation():
    result = explain(FINDING, DEFENSE, generate=lambda facts, issues: FAITHFUL)
    assert result.verified and result.text == FAITHFUL


def test_explain_rejects_unverifiable_generation_and_keeps_facts_only():
    result = explain(FINDING, DEFENSE, generate=lambda facts, issues: "nothing relevant here", max_retries=1)
    assert not result.verified and result.text == "" and result.facts["tool"] == "update_vendor_bank"
