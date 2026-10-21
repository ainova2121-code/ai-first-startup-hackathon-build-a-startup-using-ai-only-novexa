"""Agent identity: a manifest of what each agent may call, posture findings, a scope oracle, a
per-agent guard (P11), identity attack scenarios, and the evidence."""

import asyncio
import json

import pytest

from fixtures.fake_secrets import FORMATS, RANDOM_LOOKING
from purpleteam.adapter import Observation, ToolCall
from purpleteam.assessment import Assessment
from purpleteam.attack.corpus import PYRIT_TEMPLATES, AttackTemplate
from purpleteam.attack.identity import IDENTITY_OBJECTIVES, identity_corpus
from purpleteam.audit.ledger import AuditLedger
from purpleteam.defender.selector import Defender, Finding
from purpleteam.discovery import AgentInfo, DiscoveredTool, TargetProfile
from purpleteam.identity import PermissionManifest, baseline, check_baseline, check_credentials, drift, inventory, posture
from purpleteam.oracle import HONEYTOKEN, AnyOracle, LeakOracle, ScopeOracle
from purpleteam.patches.base import Blocked
from purpleteam.patches.rules import AgentScopeGuard
from purpleteam.targets.ledgerpilot import credentials, discover_profile


def _tool(name, risk, agent):
    return DiscoveredTool(name, "", {}, "", risk, "", agent_name=agent)


PROFILE = TargetProfile("t", [
    _tool("lookup_vendor", "read", "vendor"), _tool("update_vendor_bank", "write", "vendor"),
    _tool("confirm_vendor", "write", "vendor"), _tool("schedule_payment", "write", "payment"),
], [AgentInfo("vendor", "You manage vendors.", ("lookup_vendor",)), AgentInfo("idle", "Does nothing.")])
INTENDED = PermissionManifest({"vendor": frozenset({"lookup_vendor", "confirm_vendor"}),
                               "payment": frozenset({"schedule_payment"}), "idle": frozenset()})


def test_a_draft_manifest_is_what_each_agent_holds_today_including_agents_without_tools():
    draft = PermissionManifest.from_profile(PROFILE)
    assert draft.permits("vendor", "update_vendor_bank") and not draft.permits("payment", "update_vendor_bank")
    assert draft.allowed["idle"] == frozenset() and not draft.permits("stranger", "lookup_vendor")  # deny by default


def test_a_manifest_file_is_validated(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"vendor": ["lookup_vendor"]}))
    assert PermissionManifest.load(path).permits("vendor", "lookup_vendor")


MODEL_PROFILE = TargetProfile("t", [_tool("lookup_vendor", "read", "vendor")],
                              [AgentInfo("vendor", "You manage vendors.", ("lookup_vendor",), model="gpt-4o")])


def test_baseline_includes_the_model_name_when_known():
    assert baseline(MODEL_PROFILE)["vendor"]["model"] == "gpt-4o"


def test_a_baseline_saved_before_the_model_field_existed_still_loads():
    old = {"vendor": {"tools": ["lookup_vendor"], "prompt_sha256": None}}  # no "model" key at all
    assert check_baseline(old)["vendor"]["tools"] == ["lookup_vendor"]


def test_check_baseline_rejects_an_invalid_model_name():
    with pytest.raises(ValueError):
        check_baseline({"vendor": {"tools": [], "prompt_sha256": None, "model": "not a valid name!"}})


def test_drift_flags_a_model_swap_but_not_when_either_side_is_unknown():
    saved = baseline(MODEL_PROFILE)
    swapped = TargetProfile("t", [_tool("lookup_vendor", "read", "vendor")],
                            [AgentInfo("vendor", "You manage vendors.", ("lookup_vendor",), model="gpt-3.5-turbo")])
    (finding,) = drift(swapped, saved)
    assert finding.kind == "model_changed" and "gpt-4o" in finding.detail and "gpt-3.5-turbo" in finding.detail

    unknown_now = TargetProfile("t", [_tool("lookup_vendor", "read", "vendor")],
                                [AgentInfo("vendor", "You manage vendors.", ("lookup_vendor",))])  # no model known now
    assert drift(unknown_now, saved) == []  # cannot call it drift when one side was never observed
    assert PermissionManifest.from_dict(INTENDED.to_dict()) == INTENDED
    for bad in ([], {"vendor": "lookup_vendor"}, {"vendor": ["bad!name"]}, {"vendor": ["x\ny"]}, {"bad!agent": []},
                {"vendor": [1]}, {f"a{i}": [] for i in range(201)}, {"vendor": [f"t{i}" for i in range(501)]},
                {"vendor": ["x" * 129]}):
        with pytest.raises(ValueError):
            PermissionManifest.from_dict(bad)


def test_ledgerpilots_real_agents_show_the_structural_identity_findings():
    profile = discover_profile()
    findings = posture(profile, credentials=credentials(profile))
    kinds = {(f.kind, f.agent) for f in findings}
    assert ("unscoped_execution", "inquiry") in kinds                      # query_ledger takes raw SQL
    assert ("duty_conflict", "approval") in kinds                          # records decisions and sends requests
    shared = next(f for f in findings if f.kind == "shared_credential")
    assert shared.agent == "approval,inquiry,intake,matching,payment,vendor" and shared.severity == "high"
    assert "update_vendor_bank" in shared.tools and "schedule_payment" in shared.tools
    assert not any(f.kind == "excess_privilege" for f in findings)         # no manifest declared, nothing to exceed


def test_a_declared_manifest_exposes_excess_undeclared_and_stale_entries():
    allowed = dict(INTENDED.allowed) | {"ghost": frozenset({"anything"})}
    del allowed["payment"]
    findings = {(f.kind, f.agent): f for f in posture(PROFILE, PermissionManifest(allowed))}
    assert findings[("excess_privilege", "vendor")].tools == ("update_vendor_bank",)
    assert findings[("undeclared_agent", "payment")].tools == ("schedule_payment",)
    assert findings[("unknown_agent", "ghost")].severity == "low"
    assert ("excess_privilege", "idle") not in findings


def test_credential_labels_must_be_names_and_never_secrets():
    assert check_credentials({"vendor": "sqlite-ledger"}) == {"vendor": "sqlite-ledger"}
    for bad in ({"vendor": FORMATS["github_token"]}, {"vendor": ""}, {"bad!agent": "db"}, {"vendor": "x" * 129}):
        with pytest.raises(ValueError):
            check_credentials(bad)
    with pytest.raises(ValueError):
        posture(PROFILE, credentials={"vendor": FORMATS["aws_access_key"]})  # checked wherever labels enter


def test_the_evidence_inventory_never_carries_prompt_text():
    findings = posture(PROFILE, INTENDED)
    view = inventory(PROFILE, INTENDED, findings, {"vendor": "ledger-db"})
    text = json.dumps(view)
    assert "You manage vendors" not in text and "Does nothing" not in text
    vendor = next(a for a in view["agents"] if a["name"] == "vendor")
    assert vendor["prompt_chars"] == len("You manage vendors.") and len(vendor["prompt_sha256"]) == 64
    assert vendor["credential"] == "ledger-db" and vendor["permitted"] == ["confirm_vendor", "lookup_vendor"]
    assert inventory(PROFILE, None, [])["agents"][0]["permitted"] is None


def test_the_scope_oracle_flags_only_calls_outside_an_agents_permissions():
    oracle = ScopeOracle(INTENDED)
    ok = Observation("", [ToolCall("vendor", "lookup_vendor", {})])
    assert not oracle.judge(ok).breached
    verdict = oracle.judge(Observation("", [ToolCall("vendor", "lookup_vendor", {}),
                                            ToolCall("vendor", "update_vendor_bank", {"bank_account": "x"})]))
    assert (verdict.breached, verdict.kind, verdict.tool, verdict.agent) == (
        True, "privilege_escalation", "update_vendor_bank", "vendor")
    assert oracle.judge(Observation("", [ToolCall("stranger", "lookup_vendor", {})])).breached  # unknown agent
    combined = AnyOracle(oracle, LeakOracle({HONEYTOKEN}))
    assert combined.judge(Observation(f"it is {HONEYTOKEN}", [])).kind == "exfiltration"
    assert combined.judge(Observation("", [ToolCall("vendor", "update_vendor_bank", {})])).kind == "privilege_escalation"
    assert not combined.judge(ok).breached


def test_the_scope_oracle_also_catches_a_resource_scoped_violation():
    scoped = PermissionManifest.from_dict(
        {"payment": [{"tool": "schedule_payment", "arg": "country", "values": ["US"]}]})
    oracle = ScopeOracle(scoped)
    assert not oracle.judge(Observation("", [ToolCall("payment", "schedule_payment", {"country": "US"})])).breached
    verdict = oracle.judge(Observation("", [ToolCall("payment", "schedule_payment", {"country": "FR"})]))
    assert (verdict.breached, verdict.kind) == (True, "privilege_escalation")


def test_the_agent_scope_guard_denies_by_default_and_names_only_the_agent_and_tool():
    guard = AgentScopeGuard(INTENDED)
    guard.authorize("vendor", "lookup_vendor", {"name": "acme"})
    for agent, tool in (("vendor", "update_vendor_bank"), ("payment", "lookup_vendor"), ("stranger", "lookup_vendor")):
        with pytest.raises(Blocked) as blocked:
            guard.authorize(agent, tool, {"bank_account": "US00SECRET0000"})
        assert str(blocked.value) == f"agent '{agent}' is not permitted to call {tool}"


def test_the_agent_scope_guard_also_enforces_a_resource_scoped_rule():
    scoped = PermissionManifest.from_dict(
        {"payment": [{"tool": "schedule_payment", "arg": "country", "values": ["US"]}]})
    guard = AgentScopeGuard(scoped)
    guard.authorize("payment", "schedule_payment", {"country": "US"})
    with pytest.raises(Blocked, match="only with country in"):
        guard.authorize("payment", "schedule_payment", {"country": "FR"})


def test_the_defender_builds_the_scope_guard_from_the_declared_manifest_or_what_agents_hold():
    finding = Finding("privilege_escalation", "update_vendor_bank", "vendor")
    declared = Defender(PROFILE, {"manifest": INTENDED}).select(finding)
    assert "P11" in declared.patch_ids
    with pytest.raises(Blocked):
        declared.guard.authorize("vendor", "update_vendor_bank", {})
    inferred = Defender(PROFILE).select(finding)
    inferred.guard.authorize("vendor", "update_vendor_bank", {})   # a draft allows what the agent holds today...
    with pytest.raises(Blocked):
        inferred.guard.authorize("payment", "update_vendor_bank", {})  # ...but not a tool another agent holds
    with pytest.raises(ValueError):
        Defender(PROFILE, {"manifest": {"vendor": ["lookup_vendor"]}}).select(finding)


def test_the_identity_corpus_wraps_every_objective_in_every_template_with_unique_ids():
    corpus = identity_corpus()
    assert len(corpus) == len(IDENTITY_OBJECTIVES) * len(PYRIT_TEMPLATES)
    assert len({t.id for t in corpus}) == len(corpus)
    for template in corpus:
        key = template.id.split(":")[0]
        assert key in IDENTITY_OBJECTIVES and IDENTITY_OBJECTIVES[key] in template.body


class _Obedient:
    """Does whatever an injected instruction says, using a tool its permissions do not allow."""

    name = "obedient"

    def __init__(self, guard=None):
        self._guard = guard

    def reset(self):
        pass

    def send(self, request):
        if "Ignore any limits" in request:
            call = ToolCall("vendor", "update_vendor_bank", {"bank_account": "US00ATTACKER0666"})
            if self._guard:
                try:
                    self._guard.authorize(call.agent, call.tool, call.args)
                except Blocked:
                    return Observation("not permitted", [])
            return Observation("done", [call])
        return Observation("ok", [ToolCall("vendor", "lookup_vendor", {"name": "acme"})])


def test_an_agent_used_beyond_its_permissions_is_found_blocked_verified_and_evidenced(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    attack = AttackTemplate("probe", "prompt-injection", IDENTITY_OBJECTIVES["privilege_probe"])
    assessment = Assessment(
        lambda guard: _Obedient(guard), AnyOracle(ScopeOracle(INTENDED), LeakOracle({HONEYTOKEN})), PROFILE, ledger,
        legit=[("Look up acme", lambda o: any(c.tool == "lookup_vendor" for c in o.tool_calls))], manifest=INTENDED)
    report = asyncio.run(assessment.run([attack]))

    # the dynamically proven breach and the statically discovered identity finding that explains why
    # it was possible both reach the defender now — previously only the proven breach did
    assert [(f.kind, f.tool, f.agent) for f in report.findings] == [
        ("privilege_escalation", "update_vendor_bank", "vendor"),
        ("excess_privilege", "update_vendor_bank", "vendor")]
    assert "P11" in report.defense.patch_ids and report.verification.safe_to_ship and report.safe_to_ship
    assert [e["kind"] for e in ledger.events()] == ["identity", "attack", "breach", "patch", "verdict", "seal"]
    assert report.chain_ok
    assert "excess_privilege" in {f["kind"] for f in report.identity["findings"]}
    assert report.identity["manifest"] == "declared" and json.dumps(report.to_dict())
    assert "OWASP LLM · LLM06" in report.coverage and "PCI SSC AI principles · Least privilege" in report.coverage
    assert "PCI SSC AI principles · Own credentials" in report.coverage  # the identity posture event itself


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
    # a draft manifest allows what the agent already holds, so it cannot stop the agent's own excess tool
    assert inferred == "inferred" and not inferred_report.safe_to_ship


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
