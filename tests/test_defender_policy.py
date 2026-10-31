"""A saved defender policy rebuilds the exact same guard — same patches, same enforce/allow
behaviour — without ever needing the live TargetProfile or facts again. Signed so an edited file
is detected rather than silently loaded as if it were still what a human approved."""

import json

import pytest

from purpleteam.audit.keys import AgentKeyring
from purpleteam.defender.policy import load_guard, save_policy
from purpleteam.decisions import Probe, decide
from purpleteam.defender.selector import Defender, Finding
from purpleteam.discovery import DiscoveredTool, TargetProfile
from purpleteam.identity import PermissionManifest
from purpleteam.patches.base import Blocked

PROFILE = TargetProfile("fake", [
    DiscoveredTool("update_vendor_bank", "", {}, "", "write", "vendor"),
    DiscoveredTool("lookup_vendor", "", {}, "", "read", "vendor"),
    DiscoveredTool("run_query", "", {}, "", "execute", "reports"),
])


def _rebuilt(findings, facts=None, tmp_path=None, keyring=None):
    keyring = keyring or AgentKeyring()
    original = Defender(PROFILE, facts).select_all(findings)
    path = tmp_path / "policy.json"
    save_policy(path, findings, PROFILE, facts, keyring)
    rebuilt = load_guard(path, keyring.public_keys()["defender"]).guard
    return original, rebuilt, path


def test_a_tool_gate_patch_blocks_the_same_tool_after_a_round_trip(tmp_path):
    findings = [Finding("injection_action", "update_vendor_bank", "vendor", "canary reached it")]
    original, rebuilt, _ = _rebuilt(findings, tmp_path=tmp_path)

    assert set(original.patch_ids) & {"P4"} == {"P4"}
    with pytest.raises(Blocked):
        rebuilt.authorize("vendor", "update_vendor_bank", {})
    rebuilt.authorize("vendor", "lookup_vendor", {})  # a different tool is never blocked by P4


@pytest.mark.parametrize("level", [1, 2])
def test_an_escalated_defense_rebuilds_into_exactly_the_guard_that_was_verified(tmp_path, level):
    """Before: the escalation level was never saved, so a gateway enforced the weaker level-0 defense."""
    profile = TargetProfile("fake", [*PROFILE.tools, DiscoveredTool("pay_vendor", "", {}, "", "write", "vendor")])
    findings = [Finding("injection_action", "update_vendor_bank", "vendor", "canary reached it")]
    verified = Defender(profile, {}, escalation=level).select_all(findings).guard
    keyring = AgentKeyring()
    save_policy(tmp_path / "p.json", findings, profile, {}, keyring, escalation=level)
    loaded = load_guard(tmp_path / "p.json", keyring.public_keys()["defender"]).guard

    probes = [Probe("authorize", agent, tool, "{}") for agent in ("vendor", "reports")
              for tool in ("update_vendor_bank", "pay_vendor", "lookup_vendor", "run_query")]
    assert [decide(loaded, p) for p in probes] == [decide(verified, p) for p in probes]
    assert decide(loaded, Probe("authorize", "vendor", "pay_vendor", "{}"))[0] != "allow"  # the widened scope


def test_a_manifest_backed_patch_round_trips_through_to_dict(tmp_path):
    manifest = PermissionManifest({"vendor": frozenset({"lookup_vendor"})})
    findings = [Finding("excess_privilege", "update_vendor_bank", "vendor", "not permitted")]
    facts = {"manifest": manifest}
    original, rebuilt, _ = _rebuilt(findings, facts, tmp_path)

    assert "P11" in original.patch_ids
    with pytest.raises(Blocked):
        rebuilt.authorize("vendor", "update_vendor_bank", {})
    rebuilt.authorize("vendor", "lookup_vendor", {})  # permitted by the manifest, never blocked


def test_sql_firewall_is_rebuilt_from_the_profiles_execute_tools(tmp_path):
    findings = [Finding("sql_injection", "run_query", "reports", "unsafe SQL")]
    original, rebuilt, _ = _rebuilt(findings, tmp_path=tmp_path)

    assert "P8" in original.patch_ids
    with pytest.raises(Blocked):
        rebuilt.authorize("reports", "run_query", {"sql": "DROP TABLE t"})
    rebuilt.authorize("reports", "run_query", {"sql": "SELECT 1"})  # a safe query is allowed


def test_business_facts_like_tables_round_trip(tmp_path):
    findings = [Finding("sql_injection", "run_query", "reports", "unsafe SQL")]
    facts = {"tables": ["invoices"]}
    original, rebuilt, _ = _rebuilt(findings, facts, tmp_path)

    rebuilt.authorize("reports", "run_query", {"sql": "SELECT * FROM invoices"})  # allowlisted table
    with pytest.raises(Blocked):
        rebuilt.authorize("reports", "run_query", {"sql": "SELECT * FROM secrets"})  # not allowlisted


def test_save_policy_writes_atomically_leaving_no_temp_file(tmp_path):
    findings = [Finding("injection_action", "update_vendor_bank", "vendor", "x")]
    _, _, path = _rebuilt(findings, tmp_path=tmp_path)
    leftovers = [p for p in tmp_path.iterdir() if p != path]
    assert leftovers == []


def test_a_malformed_policy_file_fails_loud(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text('{"no": "findings key"}', encoding="utf-8")
    with pytest.raises(ValueError, match="not signed"):
        load_guard(path, AgentKeyring().public_keys().get("defender", {}))


def test_an_empty_finding_list_produces_a_no_op_guard_that_blocks_nothing(tmp_path):
    keyring = AgentKeyring()
    path = tmp_path / "policy.json"
    save_policy(path, [], PROFILE, {}, keyring)
    guard = load_guard(path, keyring.public_keys()["defender"]).guard
    guard.authorize("vendor", "update_vendor_bank", {})  # nothing to block, so nothing is blocked


def test_an_edited_policy_fails_to_load_instead_of_silently_weakening_enforcement(tmp_path):
    """The real bug this fixes: removing the one finding that justified a patch must be detected,
    not silently accepted as if a human had approved the now-unprotected policy."""
    findings = [Finding("injection_action", "update_vendor_bank", "vendor", "canary reached it")]
    keyring = AgentKeyring()
    path = tmp_path / "policy.json"
    save_policy(path, findings, PROFILE, {}, keyring)

    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["policy"]["findings"] = []  # an attacker (or a careless edit) strips the finding
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(ValueError, match="invalid signature"):
        load_guard(path, keyring.public_keys()["defender"])


def test_a_policy_signed_by_an_untrusted_key_is_rejected(tmp_path):
    findings = [Finding("injection_action", "update_vendor_bank", "vendor", "canary reached it")]
    signer, attacker = AgentKeyring(), AgentKeyring()
    attacker.kid("defender")  # force a key into existence so there is something (wrong) to pin
    path = tmp_path / "policy.json"
    save_policy(path, findings, PROFILE, {}, signer)

    with pytest.raises(ValueError, match="not trusted"):
        load_guard(path, attacker.public_keys()["defender"])  # the gateway pinned a different key


SECRET = "HTK-POLICY-SECRET-0001"
LEAK = [Finding("egress_leak", "update_vendor_bank", "vendor", "secret left")]


def test_secrets_are_never_written_in_plaintext(tmp_path):
    with pytest.raises(ValueError, match="plaintext"):
        save_policy(tmp_path / "p.json", LEAK, PROFILE, {"secrets": [SECRET]}, AgentKeyring())

    keyring = AgentKeyring()
    save_policy(tmp_path / "p.json", LEAK, PROFILE, {"secrets": [SECRET]}, keyring, secrets_key="op-key")
    assert SECRET not in (tmp_path / "p.json").read_text()
    guard = load_guard(tmp_path / "p.json", keyring.public_keys()["defender"], secrets_key="op-key").guard
    with pytest.raises(Blocked):
        guard.authorize("vendor", "lookup_vendor", {"note": SECRET})  # the decrypted secret is enforced


def test_encrypted_secrets_need_the_right_key_to_load(tmp_path):
    keyring = AgentKeyring()
    save_policy(tmp_path / "p.json", LEAK, PROFILE, {"secrets": [SECRET]}, keyring, secrets_key="op-key")
    with pytest.raises(ValueError, match="GATEWAY_POLICY_SECRETS_KEY"):
        load_guard(tmp_path / "p.json", keyring.public_keys()["defender"])
    with pytest.raises(ValueError, match="cannot decrypt"):
        load_guard(tmp_path / "p.json", keyring.public_keys()["defender"], secrets_key="wrong")


def test_a_policy_approved_against_different_patch_code_refuses_to_load(tmp_path, monkeypatch):
    """A valid signature must not let an upgrade silently rebuild an old approval into new behaviour."""
    findings = [Finding("injection_action", "update_vendor_bank", "vendor", "canary reached it")]
    keyring = AgentKeyring()
    save_policy(tmp_path / "p.json", findings, PROFILE, {}, keyring)
    from purpleteam.oversight import HumanReviewGate
    monkeypatch.setattr(HumanReviewGate, "code_hash", lambda self: "changed-code")
    with pytest.raises(ValueError, match="different patch catalog or patch code"):
        load_guard(tmp_path / "p.json", keyring.public_keys()["defender"])


def test_a_policy_with_no_signature_fields_is_rejected(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"policy": {"findings": []}}), encoding="utf-8")
    with pytest.raises(ValueError, match="not signed"):
        load_guard(path, {})


def test_operator_redaction_patterns_round_trip_into_the_rebuilt_output_redactor(tmp_path):
    findings = [Finding("exfiltration", "lookup_vendor", "vendor", "leak")]
    original, rebuilt, path = _rebuilt(findings, {"redact_patterns": [r"\bMRN-\d{6}\b"]}, tmp_path)
    assert json.loads(path.read_text())["policy"]["facts"]["redact_patterns"] == [r"\bMRN-\d{6}\b"]
    # Through the rebuilt redactor itself: where P2's classifier is installed it may refuse this text first.
    redactor = next(patch for patch in rebuilt.patches if patch.id == "P9")
    assert "MRN-123456" not in redactor.screen("vendor", "record MRN-123456", "tool_result")
