"""Permission manifests and credential labels: what is accepted, what is refused, and how the scope guard uses them."""

import asyncio

import pytest

from fixtures.fake_secrets import FORMATS, RANDOM_LOOKING
from purpleteam.adapter import Observation
from purpleteam.assessment import Assessment
from purpleteam.attack.corpus import AttackTemplate
from purpleteam.attack.identity import IDENTITY_OBJECTIVES
from purpleteam.audit.ledger import AuditLedger
from purpleteam.identity import PermissionManifest, check_credentials
from purpleteam.oracle import ScopeOracle
from test_identity import INTENDED, PROFILE, _Obedient


def test_manifest_names_allow_single_spaces_but_not_control_characters_or_odd_spacing():
    assert PermissionManifest.from_dict({"Invoice Agent": ["look up"]}).permits("Invoice Agent", "look up")
    for bad in ({"two  spaces": []}, {" lead": []}, {"trail ": []}, {"a\tb": []}, {"ok": ["x\ry"]}):
        with pytest.raises(ValueError):
            PermissionManifest.from_dict(bad)


def test_a_resource_scoped_entry_permits_the_tool_only_for_matching_argument_values():
    manifest = PermissionManifest.from_dict(
        {"payment": [{"tool": "schedule_payment", "arg": "currency", "values": ["usd", "eur"]}]})
    assert manifest.permits("payment", "schedule_payment", {"currency": "usd"})
    assert manifest.permits("payment", "schedule_payment", {"currency": "EUR"})  # case-insensitive
    assert not manifest.permits("payment", "schedule_payment", {"currency": "gbp"})
    assert not manifest.permits("payment", "schedule_payment", {})  # missing argument is not a match
    assert manifest.reason_denied("payment", "schedule_payment", {"currency": "gbp"}) == (
        "agent 'payment' may call schedule_payment only with currency in ['EUR', 'USD']")


def test_an_unscoped_tool_is_permitted_for_any_resource():
    manifest = PermissionManifest.from_dict({"vendor": ["lookup_vendor"]})
    assert manifest.permits("vendor", "lookup_vendor", {"anything": "goes"})


def test_a_resource_scoped_manifest_round_trips_through_to_dict_and_from_dict():
    manifest = PermissionManifest.from_dict(
        {"vendor": ["lookup_vendor", {"tool": "update_vendor_bank", "arg": "country", "values": ["US"]}]})
    restored = PermissionManifest.from_dict(manifest.to_dict())
    assert restored.permits("vendor", "update_vendor_bank", {"country": "us"})
    assert not restored.permits("vendor", "update_vendor_bank", {"country": "FR"})
    assert restored.permits("vendor", "lookup_vendor")


def test_a_malformed_resource_scoped_entry_is_rejected():
    for bad in ({"tool": "x"}, {"tool": "x", "arg": "y", "values": []}, {"tool": "x", "arg": "y", "values": [1]},
                {"arg": "y", "values": ["a"]}, 123, None, {"tool": "bad name!", "arg": "y", "values": ["a"]}):
        with pytest.raises(ValueError):
            PermissionManifest.from_dict({"vendor": [bad]})


def test_a_manifest_file_with_duplicate_agents_or_an_oversized_body_is_rejected(tmp_path):
    duplicate = tmp_path / "dup.json"
    duplicate.write_text('{"vendor": ["lookup_vendor"], "vendor": ["lookup_vendor", "update_vendor_bank"]}')
    with pytest.raises(ValueError, match="duplicate"):
        PermissionManifest.load(duplicate)
    huge = tmp_path / "huge.json"
    huge.write_text('{"vendor": []}' + " " * 1_000_001)
    with pytest.raises(ValueError, match="too large"):
        PermissionManifest.load(huge)


def test_a_bare_random_token_is_not_accepted_as_a_credential_label():
    with pytest.raises(ValueError):
        check_credentials({"vendor": RANDOM_LOOKING})
    check_credentials({"vendor": "one sqlite connection (ledger.db)"})  # a descriptive name is fine


def test_the_scope_oracle_treats_an_unevaluable_call_as_a_breach():
    class _Broken:
        tool = "lookup_vendor"  # no agent attribute

    verdict = ScopeOracle(INTENDED).judge(Observation("", [_Broken()]))
    assert verdict.breached and verdict.kind == "privilege_escalation"


def inferred_report_ledger(tmp_path):
    return AuditLedger(tmp_path / "inferred.jsonl").events()


def test_the_patch_record_says_whether_the_scope_guard_used_a_declared_or_inferred_manifest(tmp_path):
    def run(manifest, name):
        ledger = AuditLedger(tmp_path / f"{name}.jsonl")
        attack = AttackTemplate("probe", "prompt-injection", IDENTITY_OBJECTIVES["privilege_probe"])
        assessment = Assessment(lambda guard: _Obedient(guard), ScopeOracle(INTENDED), PROFILE, ledger,
                                legit=[("Look up acme", lambda o: bool(o.tool_calls))], manifest=manifest)
        report = asyncio.run(assessment.run([attack]))
        patch = next(e for e in ledger.events() if e["kind"] == "patch")
        return report, patch["payload"]["manifest"]

    declared_report, declared = run(INTENDED, "declared")
    inferred_report, inferred = run(None, "inferred")
    assert declared == "declared" and declared_report.safe_to_ship
    # A draft manifest allows what the agent already holds, so it cannot stop the agent's own excess
    # tool: its replays keep breaching, the defender escalates to denying that exact tool to that
    # agent, and only that tighter defense is verified. The record shows the lighter one came first.
    assert inferred == "inferred" and inferred_report.safe_to_ship
    levels = [e["payload"]["escalation"] for e in inferred_report_ledger(tmp_path) if e["kind"] == "patch"]
    assert max(levels) > 0 and inferred_report.verification.attack_blocked


def test_long_descriptive_labels_are_accepted_and_bare_tokens_rejected():
    for label in ("shared-prod-db-service-account", "postgres-prod-ledger", "one sqlite connection (ledger.db)",
                  "aws:role/ledger-writer"):
        assert check_credentials({"vendor": label}) == {"vendor": label}
    for bad in (RANDOM_LOOKING, "token=" + RANDOM_LOOKING, FORMATS["github_token"]):
        with pytest.raises(ValueError):
            check_credentials({"vendor": bad})


def test_bad_credential_labels_stop_the_assessment_before_any_attack_runs(tmp_path):
    ledger = AuditLedger(tmp_path / "early.jsonl")
    with pytest.raises(ValueError):
        Assessment(lambda guard: _Obedient(guard), ScopeOracle(INTENDED), PROFILE, ledger, legit=[],
                   credentials={"vendor": RANDOM_LOOKING})
    assert ledger.count() == 0


def test_a_manifest_given_through_facts_is_declared_everywhere(tmp_path):
    ledger = AuditLedger(tmp_path / "facts.jsonl")
    attack = AttackTemplate("probe", "prompt-injection", IDENTITY_OBJECTIVES["privilege_probe"])
    assessment = Assessment(lambda guard: _Obedient(guard), ScopeOracle(INTENDED), PROFILE, ledger,
                            legit=[("Look up acme", lambda o: bool(o.tool_calls))], facts={"manifest": INTENDED})
    report = asyncio.run(assessment.run([attack]))
    patch = next(e for e in ledger.events() if e["kind"] == "patch")
    assert patch["payload"]["manifest"] == "declared" and report.identity["manifest"] == "declared"
    assert report.safe_to_ship
    with pytest.raises(ValueError):
        Assessment(lambda guard: _Obedient(guard), ScopeOracle(INTENDED), PROFILE, ledger, legit=[],
                   facts={"manifest": {"vendor": []}})
