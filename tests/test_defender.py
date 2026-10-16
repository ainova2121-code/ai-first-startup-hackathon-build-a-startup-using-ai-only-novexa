"""The defender selects catalog patches for a finding and composes a guard that blocks it.

These cover the deterministic patches and selection; the LLM Guard injection scanner (P2) loads
its model lazily and is exercised in the live verification, not here.
"""

import pytest

from purpleteam.defender.selector import Defender, Finding
from purpleteam.discovery import DiscoveredTool, TargetProfile
from purpleteam.patches.base import Blocked
from purpleteam.patches.rules import ArgumentAllowlist, SqlFirewall, ToolGate


def _raises_blocked(fn) -> bool:
    with pytest.raises(Blocked):
        fn()
    return True


def test_tool_gate_blocks_only_its_tools():
    gate = ToolGate({"update_vendor_bank"})
    assert _raises_blocked(lambda: gate.authorize("vendor", "update_vendor_bank", {"bank_account": "X"}))
    gate.authorize("vendor", "lookup_vendor", {"name": "a"})  # does not raise


def test_argument_allowlist_blocks_unverified_value():
    rule = ArgumentAllowlist("schedule_payment", "bank_account", {"US941030326875"})
    rule.authorize("payment", "schedule_payment", {"bank_account": "US941030326875"})  # ok
    assert _raises_blocked(
        lambda: rule.authorize("payment", "schedule_payment", {"bank_account": "US00ATTACKER0666"})
    )


def test_sql_firewall_allows_scoped_select_only():
    firewall = SqlFirewall({"query_ledger"}, tables={"invoices"})
    firewall.authorize("inq", "query_ledger", {"sql": "SELECT * FROM invoices"})  # ok
    for bad in ("SELECT * FROM vendors", "SELECT 1; DROP TABLE invoices",
                "UPDATE vendors SET bank_account=1", "not sql at all"):
        assert _raises_blocked(lambda s=bad: firewall.authorize("inq", "query_ledger", {"sql": s}))


def test_defender_blocks_the_breached_tool():
    profile = TargetProfile("lp", [DiscoveredTool("update_vendor_bank", "", {}, "", "write", "vendor")])
    defense = Defender(profile).select(Finding("injection_action", "update_vendor_bank", "vendor"))
    # P4 (the tool gate) always applies; P2 (the LLM Guard scanner) only when its backend is loadable.
    assert "P4" in defense.patch_ids
    assert _raises_blocked(
        lambda: defense.guard.authorize("vendor", "update_vendor_bank", {"bank_account": "X"})
    )
    assert all(p["hash"] for p in defense.applied)  # patches pinned by code hash for the audit trail


# --- secrets: redaction (P9) and the egress guard (P10) ------------------------------------------

from fixtures.fake_secrets import FORMATS  # noqa: E402
from purpleteam.oracle import HONEYTOKEN  # noqa: E402
from purpleteam.patches.rules import EgressGuard  # noqa: E402
from purpleteam.patches.scanners import OutputRedactor  # noqa: E402
from purpleteam.secrets import SecretFinder  # noqa: E402

LEAK_PROFILE = TargetProfile("lp", [
    DiscoveredTool("send_email", "", {}, "", "external", "notifier"),
    DiscoveredTool("lookup_vendor", "", {}, "", "read", "vendor"),
    DiscoveredTool("query_ledger", "", {}, "", "execute", "inquiry"),
])
FACTS = {"secrets": {HONEYTOKEN}}


def test_egress_guard_blocks_secrets_in_arguments_and_names_only_the_kind():
    guard = EgressGuard({"send_email"}, SecretFinder(known=[HONEYTOKEN]))
    guard.authorize("n", "send_email", {"to": "a@b.test", "body": "quarterly numbers attached"})  # clean
    guard.authorize("n", "lookup_vendor", {"name": HONEYTOKEN})  # not an outbound tool it guards
    for body in (f"token {HONEYTOKEN}", FORMATS["aws_access_key"], f"see {HONEYTOKEN.encode().hex()}"):
        with pytest.raises(Blocked) as blocked:
            guard.authorize("n", "send_email", {"body": body})
        assert HONEYTOKEN not in str(blocked.value) and body not in str(blocked.value)
    with pytest.raises(Blocked, match="too large"):
        guard.authorize("n", "send_email", {"body": "a" * 2_000_000})


def test_an_egress_leak_finding_guards_every_tool():
    defense = Defender(LEAK_PROFILE, FACTS).select(Finding("egress_leak", "lookup_vendor", "vendor"))
    assert "P10" in defense.patch_ids
    for tool in ("send_email", "lookup_vendor", "query_ledger"):  # a secret can leave through any text-taking tool
        with pytest.raises(Blocked):
            defense.guard.authorize("a", tool, {"body": f"x {HONEYTOKEN}"})
    defense.guard.authorize("a", "send_email", {"body": "a normal message"})


def test_an_exfiltration_finding_redacts_known_secrets_formats_and_the_old_account_pattern():
    defense = Defender(LEAK_PROFILE, FACTS).select(Finding("exfiltration", "query_ledger", "inquiry"))
    assert "P9" in defense.patch_ids
    leaky = f"{HONEYTOKEN} {FORMATS['github_token']} US941030326875 fine"
    built = next(p for p in defense.guard.patches if p.id == "P9")  # the injection scanner is a separate patch
    redacted = built.screen("inquiry", leaky, "tool_result")
    assert all(secret not in redacted for secret in (HONEYTOKEN, FORMATS["github_token"], "US941030326875"))
    assert redacted.startswith("[redacted]")
    redactor = OutputRedactor(SecretFinder(known=[HONEYTOKEN]))
    assert redactor.screen("inquiry", leaky, "input") == leaky  # untrusted input is the injection scanner's job
    with pytest.raises(Blocked, match="too large"):
        redactor.screen("inquiry", "a" * 2_000_000, "output")


def test_select_all_merges_leak_findings_without_duplicating_global_patches():
    findings = [Finding("exfiltration", "query_ledger", "inquiry"), Finding("egress_leak", "send_email", "notifier"),
                Finding("egress_leak", "lookup_vendor", "vendor")]
    defense = Defender(LEAK_PROFILE, FACTS).select_all(findings)
    assert defense.patch_ids.count("P9") == 1 and defense.patch_ids.count("P10") == 1  # both are whole-target patches


def test_a_known_secret_too_short_to_detect_is_rejected_not_silently_ignored():
    with pytest.raises(ValueError):
        Defender(LEAK_PROFILE, {"secrets": {"abc"}}).select(Finding("egress_leak", "send_email"))
