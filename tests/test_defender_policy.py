"""A saved defender policy rebuilds the exact same guard — same patches, same enforce/allow
behaviour — without ever needing the live TargetProfile or facts again. Signed so an edited file
is detected rather than silently loaded as if it were still what a human approved."""

import json

import pytest

from purpleteam.audit.keys import AgentKeyring
from purpleteam.defender.policy import load_guard, save_policy
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


def test_a_policy_with_no_signature_fields_is_rejected(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"policy": {"findings": []}}), encoding="utf-8")
    with pytest.raises(ValueError, match="not signed"):
        load_guard(path, {})
