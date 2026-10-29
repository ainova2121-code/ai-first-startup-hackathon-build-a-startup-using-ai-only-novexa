"""The production gateway entry point: built entirely from the environment, refuses to start with
no provider configured, and issues working bootstrap keys since GatewayKeys has no persistent store."""

import json

import pytest

from purpleteam.gateway_main import app, build_app


def _configure_provider(monkeypatch) -> None:
    monkeypatch.setenv("GATEWAY_OPENAI_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("GATEWAY_OPENAI_KEY", "sk-test-key")
    monkeypatch.setenv("GATEWAY_REDACTOR_SECRET", "a long random owner-kept secret")


def test_no_provider_configured_refuses_to_start(monkeypatch):
    for var in ("GATEWAY_OPENAI_URL", "GATEWAY_OPENAI_KEY", "GATEWAY_ANTHROPIC_URL",
               "GATEWAY_ANTHROPIC_KEY", "GATEWAY_GEMINI_URL", "GATEWAY_GEMINI_KEY"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(RuntimeError, match="at least one provider"):
        build_app()


def test_one_configured_provider_is_enough(monkeypatch):
    monkeypatch.setenv("GATEWAY_OPENAI_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("GATEWAY_OPENAI_KEY", "sk-test-key")
    app = build_app()
    assert {r.path for r in app.routes if hasattr(r, "path")} >= {"/profile", "/v1/chat/completions"}


def test_required_hardware_signing_without_a_ledger_refuses_to_start(monkeypatch):
    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_HARDWARE_SIGNING", "required")
    monkeypatch.delenv("GATEWAY_LEDGER_PATH", raising=False)
    monkeypatch.delenv("GATEWAY_KEYRING_DIR", raising=False)
    monkeypatch.delenv("GATEWAY_TRUST_FILE", raising=False)
    with pytest.raises(RuntimeError, match="GATEWAY_LEDGER_PATH, GATEWAY_KEYRING_DIR, GATEWAY_TRUST_FILE"):
        build_app()


def test_required_hardware_signing_with_only_some_of_the_three_still_refuses(monkeypatch, tmp_path):
    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_HARDWARE_SIGNING", "required")
    monkeypatch.setenv("GATEWAY_LEDGER_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.delenv("GATEWAY_KEYRING_DIR", raising=False)
    monkeypatch.delenv("GATEWAY_TRUST_FILE", raising=False)
    with pytest.raises(RuntimeError, match="GATEWAY_KEYRING_DIR, GATEWAY_TRUST_FILE"):
        build_app()


def test_hardware_signing_not_required_does_not_need_a_ledger(monkeypatch):
    _configure_provider(monkeypatch)
    monkeypatch.delenv("GATEWAY_HARDWARE_SIGNING", raising=False)
    monkeypatch.delenv("GATEWAY_LEDGER_PATH", raising=False)
    assert build_app() is not None


def test_enforce_without_a_policy_file_refuses_to_start(monkeypatch):
    """GATEWAY_ENFORCE must never silently no-op: an operator asking for real enforcement, with
    no policy configured to load, must get a loud refusal, not a quiet observe-only gateway."""
    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_ENFORCE", "true")
    monkeypatch.delenv("GATEWAY_POLICY_FILE", raising=False)
    with pytest.raises(RuntimeError, match="GATEWAY_POLICY_FILE"):
        build_app()


def _trust_file(tmp_path, keyring) -> str:
    import json

    keyring.kid("defender")  # force a key into existence so public_keys() actually has one
    path = tmp_path / "policy_trust.json"
    path.write_text(json.dumps(keyring.public_keys()["defender"]), encoding="utf-8")
    return str(path)


def test_enforce_without_a_policy_trust_file_refuses_to_start(monkeypatch, tmp_path):
    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_ENFORCE", "true")
    monkeypatch.setenv("GATEWAY_POLICY_FILE", str(tmp_path / "policy.json"))
    monkeypatch.delenv("GATEWAY_POLICY_TRUST_FILE", raising=False)
    with pytest.raises(RuntimeError, match="GATEWAY_POLICY_TRUST_FILE"):
        build_app()


def test_enforce_with_a_broken_policy_file_refuses_to_start(monkeypatch, tmp_path):
    from purpleteam.audit.keys import AgentKeyring

    _configure_provider(monkeypatch)
    path = tmp_path / "policy.json"
    path.write_text('{"not": "a valid policy"}', encoding="utf-8")
    monkeypatch.setenv("GATEWAY_ENFORCE", "true")
    monkeypatch.setenv("GATEWAY_POLICY_FILE", str(path))
    monkeypatch.setenv("GATEWAY_POLICY_TRUST_FILE", _trust_file(tmp_path, AgentKeyring()))
    with pytest.raises(RuntimeError, match="could not be loaded"):
        build_app()


def test_enforce_with_a_policy_signed_by_an_untrusted_key_refuses_to_start(monkeypatch, tmp_path):
    from purpleteam.audit.keys import AgentKeyring
    from purpleteam.defender.policy import save_policy
    from purpleteam.defender.selector import Finding
    from purpleteam.discovery import DiscoveredTool, TargetProfile

    profile = TargetProfile("t", [DiscoveredTool("transfer_funds", "", {}, "", "write", "vendor")])
    finding = Finding("injection_action", "transfer_funds", "vendor", "canary reached it")
    path = tmp_path / "policy.json"
    save_policy(path, [finding], profile, {}, AgentKeyring())  # signed by a key nobody pinned

    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_ENFORCE", "true")
    monkeypatch.setenv("GATEWAY_POLICY_FILE", str(path))
    monkeypatch.setenv("GATEWAY_POLICY_TRUST_FILE", _trust_file(tmp_path, AgentKeyring()))  # a different key
    with pytest.raises(RuntimeError, match="could not be loaded"):
        build_app()


def test_enforce_with_a_real_policy_file_attaches_a_guard_that_actually_blocks(monkeypatch, tmp_path):
    from purpleteam.audit.keys import AgentKeyring
    from purpleteam.defender.policy import save_policy
    from purpleteam.defender.selector import Finding
    from purpleteam.discovery import DiscoveredTool, TargetProfile
    from purpleteam.patches.base import Blocked

    profile = TargetProfile("t", [DiscoveredTool("transfer_funds", "", {}, "", "write", "vendor")])
    finding = Finding("injection_action", "transfer_funds", "vendor", "canary reached it")
    keyring = AgentKeyring()
    path = tmp_path / "policy.json"
    save_policy(path, [finding], profile, {}, keyring)

    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_ENFORCE", "true")
    monkeypatch.setenv("GATEWAY_POLICY_FILE", str(path))
    monkeypatch.setenv("GATEWAY_POLICY_TRUST_FILE", _trust_file(tmp_path, keyring))

    from purpleteam.gateway_main import _policy

    policy = _policy()
    assert policy is not None
    guard = policy.guard
    with pytest.raises(Blocked):
        guard.authorize("vendor", "transfer_funds", {})  # the exact patch the saved policy chose
    guard.authorize("vendor", "some_other_tool", {})  # never blocked: not what the policy covers

    app = build_app()  # the same policy, now wired all the way through to create_gateway
    assert app is not None


def _baseline_and_new_policy(monkeypatch, tmp_path, new_findings):
    """An approved policy's pinned decisions, and a new signed policy built from ``new_findings``."""
    from purpleteam.audit.keys import AgentKeyring
    from purpleteam.decisions import ATTACK, DecisionRecorder, ProbeLog, take_baseline
    from purpleteam.defender.policy import save_policy
    from purpleteam.defender.selector import Defender, Finding
    from purpleteam.discovery import DiscoveredTool, TargetProfile
    from purpleteam.patches.base import Blocked

    profile = TargetProfile("t", [DiscoveredTool("transfer_funds", "", {}, "", "write", "vendor")])
    approved = [Finding("injection_action", "transfer_funds", "vendor", "canary reached it")]
    log = ProbeLog()
    with pytest.raises(Blocked):
        DecisionRecorder(Defender(profile, {}).select_all(approved).guard, log, ATTACK).authorize(
            "vendor", "transfer_funds", {"to": "attacker"})
    baseline = take_baseline(log, lambda: Defender(profile, {}).select_all(approved).guard)
    (tmp_path / "decisions.json").write_text(json.dumps(baseline), encoding="utf-8")

    keyring = AgentKeyring()
    save_policy(tmp_path / "policy.json", new_findings(approved), profile, {}, keyring)
    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_ENFORCE", "true")
    monkeypatch.setenv("GATEWAY_POLICY_FILE", str(tmp_path / "policy.json"))
    monkeypatch.setenv("GATEWAY_POLICY_TRUST_FILE", _trust_file(tmp_path, keyring))
    monkeypatch.setenv("GATEWAY_DECISION_BASELINE", str(tmp_path / "decisions.json"))
    monkeypatch.setenv("GATEWAY_DECISION_DIGEST", baseline["digest"])


def test_a_new_policy_that_drops_a_decision_stopping_an_attack_refuses_to_start(monkeypatch, tmp_path):
    _baseline_and_new_policy(monkeypatch, tmp_path, lambda approved: [])  # the new policy forgot the finding
    from purpleteam.gateway_main import _policy

    with pytest.raises(RuntimeError, match="loosens 1 approved decision"):
        _policy()


def test_a_new_policy_that_keeps_every_approved_decision_starts(monkeypatch, tmp_path):
    _baseline_and_new_policy(monkeypatch, tmp_path, lambda approved: approved)
    from purpleteam.gateway_main import _policy

    assert _policy() is not None


def test_a_decision_baseline_that_is_not_the_pinned_one_refuses_to_start(monkeypatch, tmp_path):
    _baseline_and_new_policy(monkeypatch, tmp_path, lambda approved: approved)
    monkeypatch.setenv("GATEWAY_DECISION_DIGEST", "0" * 64)
    from purpleteam.gateway_main import _policy

    with pytest.raises(RuntimeError, match="not the one pinned"):
        _policy()


def test_live_containment_needs_enforcement_and_a_manifest_declaring_policy(monkeypatch, tmp_path):
    from purpleteam.audit.keys import AgentKeyring
    from purpleteam.defender.policy import save_policy
    from purpleteam.defender.selector import Finding
    from purpleteam.discovery import DiscoveredTool, TargetProfile

    profile = TargetProfile("t", [DiscoveredTool("transfer_funds", "", {}, "", "write", "vendor")])
    finding = Finding("sql_injection", "transfer_funds", "vendor", "unsafe SQL")  # no manifest in facts
    keyring = AgentKeyring()
    path = tmp_path / "policy.json"
    save_policy(path, [finding], profile, {}, keyring)

    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_ENFORCE", "true")
    monkeypatch.setenv("GATEWAY_POLICY_FILE", str(path))
    monkeypatch.setenv("GATEWAY_POLICY_TRUST_FILE", _trust_file(tmp_path, keyring))
    monkeypatch.setenv("GATEWAY_LIVE_CONTAINMENT", "true")

    with pytest.raises(RuntimeError, match="GATEWAY_LIVE_CONTAINMENT"):
        build_app()


def test_live_containment_builds_once_enforcement_and_a_manifest_are_both_present(monkeypatch, tmp_path):
    from purpleteam.audit.keys import AgentKeyring
    from purpleteam.defender.policy import save_policy
    from purpleteam.defender.selector import Finding
    from purpleteam.discovery import DiscoveredTool, TargetProfile
    from purpleteam.identity import PermissionManifest

    profile = TargetProfile("t", [DiscoveredTool("transfer_funds", "", {}, "", "write", "vendor")])
    finding = Finding("injection_action", "transfer_funds", "vendor", "canary reached it")
    manifest = PermissionManifest({"vendor": frozenset({"transfer_funds"})})
    keyring = AgentKeyring()
    path = tmp_path / "policy.json"
    save_policy(path, [finding], profile, {"manifest": manifest}, keyring)

    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_ENFORCE", "true")
    monkeypatch.setenv("GATEWAY_POLICY_FILE", str(path))
    monkeypatch.setenv("GATEWAY_POLICY_TRUST_FILE", _trust_file(tmp_path, keyring))
    monkeypatch.setenv("GATEWAY_LIVE_CONTAINMENT", "true")

    assert build_app() is not None


def test_enforce_unset_runs_observe_only_as_before(monkeypatch):
    _configure_provider(monkeypatch)
    monkeypatch.delenv("GATEWAY_ENFORCE", raising=False)
    assert build_app() is not None


def test_the_real_entry_point_refuses_plain_http_without_an_explicit_ack(monkeypatch):
    _configure_provider(monkeypatch)
    monkeypatch.delenv("GATEWAY_TLS_TERMINATED_UPSTREAM", raising=False)
    with pytest.raises(RuntimeError, match="GATEWAY_TLS_TERMINATED_UPSTREAM"):
        app()


def test_the_real_entry_point_starts_once_tls_termination_is_acknowledged(monkeypatch):
    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_TLS_TERMINATED_UPSTREAM", "true")
    assert app() is not None


@pytest.mark.parametrize("value,expected", [("1", True), ("true", True), ("YES", True),
                                            ("0", False), ("false", False), ("", False)])
def test_bool_env_parsing(monkeypatch, value, expected):
    from purpleteam.gateway_main import _bool

    monkeypatch.setenv("TEST_FLAG", value)
    assert _bool("TEST_FLAG", not expected) == expected


def test_bool_env_falls_back_to_the_default_when_unset(monkeypatch):
    from purpleteam.gateway_main import _bool

    monkeypatch.delenv("TEST_FLAG", raising=False)
    assert _bool("TEST_FLAG", True) is True and _bool("TEST_FLAG", False) is False
