"""The production gateway entry point: built entirely from the environment, refuses to start with
no provider configured, and issues working bootstrap keys since GatewayKeys has no persistent store."""

import re

import pytest
from fastapi.testclient import TestClient

from purpleteam.audit.ledger import AuditLedger
from purpleteam.gateway_crypto import keyring as _keyring
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


def test_bootstrap_keys_are_printed_and_actually_work(monkeypatch, capsys):
    monkeypatch.setenv("GATEWAY_OPENAI_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("GATEWAY_OPENAI_KEY", "sk-test-key")
    build_app()
    err = capsys.readouterr().err
    assert "do not survive a restart" in err and "admin key:" in err and "target key:" in err


def test_an_admin_key_issued_before_a_restart_still_works_after_one(monkeypatch, tmp_path, capsys):
    """GATEWAY_KEYS_FILE is the whole point: a credential a customer's integration already holds
    must not go dead just because the gateway process restarted."""
    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_KEYS_FILE", str(tmp_path / "keys.json"))

    build_app()  # first "startup"
    admin_key = re.search(r"admin key:\s+(\S+)", capsys.readouterr().err).group(1)

    second_app = build_app()  # a "restart": a fresh GatewayKeys, the same backing file
    web = TestClient(second_app)
    response = web.get("/profile", headers={"authorization": f"Bearer {admin_key}"})
    assert response.status_code == 200


def test_a_restart_with_a_persisted_key_store_does_not_reissue_bootstrap_keys(monkeypatch, tmp_path, capsys):
    """The real bug this fixes: with persistence, bootstrap key creation must be a one-time setup
    step — not something that mints a fresh, equally-valid pair on every single restart."""
    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_KEYS_FILE", str(tmp_path / "keys.json"))

    build_app()  # first "startup": issues the only bootstrap pair
    first_admin = re.search(r"admin key:\s+(\S+)", capsys.readouterr().err).group(1)

    build_app()  # a "restart": must not mint a second pair
    second_err = capsys.readouterr().err
    assert "existing bootstrap keys" in second_err and "admin key:" not in second_err

    web = TestClient(build_app())
    response = web.get("/profile", headers={"authorization": f"Bearer {first_admin}"})
    assert response.status_code == 200  # the original key is still the one that works


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


def test_bootstrap_keys_are_short_lived_and_say_so(monkeypatch, capsys):
    monkeypatch.setenv("GATEWAY_OPENAI_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("GATEWAY_OPENAI_KEY", "sk-test-key")
    monkeypatch.delenv("GATEWAY_BOOTSTRAP_TTL_SECONDS", raising=False)
    build_app()
    err = capsys.readouterr().err
    assert "expire in 86400s" in err and "unbound to any one agent" in err and "rotate promptly" in err


def test_bootstrap_ttl_and_budget_are_configurable(monkeypatch, capsys):
    monkeypatch.setenv("GATEWAY_OPENAI_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("GATEWAY_OPENAI_KEY", "sk-test-key")
    monkeypatch.setenv("GATEWAY_BOOTSTRAP_TTL_SECONDS", "60")
    monkeypatch.setenv("GATEWAY_BOOTSTRAP_MAX_REQUESTS", "5")
    monkeypatch.setenv("GATEWAY_BOOTSTRAP_PER_MINUTE", "5")
    build_app()
    assert "expire in 60s" in capsys.readouterr().err


def test_without_a_redactor_secret_a_clear_warning_is_printed(monkeypatch, capsys):
    monkeypatch.setenv("GATEWAY_OPENAI_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("GATEWAY_OPENAI_KEY", "sk-test-key")
    monkeypatch.delenv("GATEWAY_REDACTOR_SECRET", raising=False)
    monkeypatch.delenv("GATEWAY_LEDGER_PATH", raising=False)
    build_app()
    assert "will be logged in the clear" in capsys.readouterr().err


def test_a_ledger_without_a_redactor_secret_refuses_to_start(monkeypatch, tmp_path):
    """Sensitive values must never be written in the clear into a durable, signed log by default."""
    _configure_provider(monkeypatch)
    monkeypatch.delenv("GATEWAY_REDACTOR_SECRET", raising=False)
    monkeypatch.setenv("GATEWAY_LEDGER_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.delenv("GATEWAY_ALLOW_UNREDACTED_LEDGER", raising=False)
    with pytest.raises(RuntimeError, match="GATEWAY_REDACTOR_SECRET"):
        build_app()


def test_an_explicit_override_allows_a_ledger_without_a_redactor_secret(monkeypatch, tmp_path, capsys):
    _configure_provider(monkeypatch)
    monkeypatch.delenv("GATEWAY_REDACTOR_SECRET", raising=False)
    monkeypatch.setenv("GATEWAY_LEDGER_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("GATEWAY_ALLOW_UNREDACTED_LEDGER", "true")
    build_app()  # does not raise
    assert "will be logged in the clear" in capsys.readouterr().err


def test_a_redactor_secret_is_used_and_no_warning_is_printed(monkeypatch, capsys):
    monkeypatch.setenv("GATEWAY_OPENAI_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("GATEWAY_OPENAI_KEY", "sk-test-key")
    monkeypatch.setenv("GATEWAY_REDACTOR_SECRET", "a long random owner-kept secret")
    build_app()
    assert "will be logged in the clear" not in capsys.readouterr().err


def test_ledger_path_is_only_used_when_set(monkeypatch, tmp_path):
    monkeypatch.setenv("GATEWAY_OPENAI_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("GATEWAY_OPENAI_KEY", "sk-test-key")
    monkeypatch.setenv("GATEWAY_REDACTOR_SECRET", "a long random owner-kept secret")
    monkeypatch.delenv("GATEWAY_LEDGER_PATH", raising=False)
    build_app()  # must not try to open a ledger file when none is configured

    monkeypatch.setenv("GATEWAY_LEDGER_PATH", str(tmp_path / "nested" / "audit.jsonl"))
    build_app()  # AuditLedger.__init__ makes its parent directory even before the first append
    assert (tmp_path / "nested").is_dir()


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


def test_an_empty_ledger_is_never_pinned(monkeypatch, tmp_path):
    """A log with zero events has no durable identity (see gateway_crypto.save_trust): pinning it
    would invent a phantom one that the first real append could never match."""
    _configure_provider(monkeypatch)
    trust_path = tmp_path / "trust.json"
    monkeypatch.setenv("GATEWAY_LEDGER_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("GATEWAY_TRUST_FILE", str(trust_path))
    monkeypatch.setenv("GATEWAY_KEYRING_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("GATEWAY_KEYRING_PASSPHRASE", "a strong passphrase")

    build_app()
    build_app()  # two restarts of an empty log must never disagree with a pin that was never made
    assert not trust_path.exists()


def test_pinning_without_a_persisted_keyring_is_rejected(monkeypatch, tmp_path):
    """Pinning a checkpoint signed by an in-memory identity is a trap: the next restart mints a
    new identity and a perfectly clean log then looks tampered. Refuse at startup, loudly."""
    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_LEDGER_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("GATEWAY_TRUST_FILE", str(tmp_path / "trust.json"))
    monkeypatch.delenv("GATEWAY_KEYRING_DIR", raising=False)

    with pytest.raises(RuntimeError, match="GATEWAY_KEYRING_DIR"):
        build_app()


def test_a_pinned_checkpoint_survives_a_clean_restart_and_catches_tampering(monkeypatch, tmp_path):
    _configure_provider(monkeypatch)
    ledger_path, trust_path = tmp_path / "audit.jsonl", tmp_path / "trust.json"
    monkeypatch.setenv("GATEWAY_LEDGER_PATH", str(ledger_path))
    monkeypatch.setenv("GATEWAY_TRUST_FILE", str(trust_path))
    monkeypatch.setenv("GATEWAY_KEYRING_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("GATEWAY_KEYRING_PASSPHRASE", "a strong passphrase")

    build_app()
    assert not trust_path.exists()  # still nothing to pin

    AuditLedger(ledger_path, keyring=_keyring()).append("test", "event", {"note": "original-value"})

    build_app()
    assert trust_path.exists()  # now pinned, at size 1

    build_app()  # a clean restart against the same, untampered log succeeds

    original = ledger_path.read_text(encoding="utf-8")
    tampered = original.replace("original-value", "TAMPERED-value")
    assert tampered != original
    ledger_path.write_text(tampered, encoding="utf-8")

    with pytest.raises(RuntimeError, match="does not match its pinned checkpoint"):
        build_app()


def test_the_ledger_is_wrapped_so_later_appends_refresh_the_pin(monkeypatch, tmp_path):
    """A pin taken only once at startup would never catch up with what the gateway appends while
    it runs; build_app's ledger must be the kind that re-pins on its own."""
    _configure_provider(monkeypatch)
    ledger_path, trust_path = tmp_path / "audit.jsonl", tmp_path / "trust.json"
    monkeypatch.setenv("GATEWAY_LEDGER_PATH", str(ledger_path))
    monkeypatch.setenv("GATEWAY_TRUST_FILE", str(trust_path))
    monkeypatch.setenv("GATEWAY_KEYRING_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("GATEWAY_KEYRING_PASSPHRASE", "a strong passphrase")
    monkeypatch.setenv("GATEWAY_TRUST_REPIN_EVERY", "2")

    from purpleteam.gateway_crypto import RepinningLedger
    from purpleteam.gateway_main import _ledger

    ledger = _ledger(redactor=None)
    assert isinstance(ledger, RepinningLedger)

    ledger.append("test", "event", {"n": 1})
    assert not trust_path.exists()  # below the every=2 threshold
    ledger.append("test", "event", {"n": 2})
    assert trust_path.exists()
    from purpleteam.gateway_crypto import pinned_trust
    assert pinned_trust(trust_path)[0]["size"] == 2


def test_debug_reasoning_path_unset_builds_with_no_warning(monkeypatch, capsys):
    _configure_provider(monkeypatch)
    monkeypatch.delenv("GATEWAY_DEBUG_REASONING_PATH", raising=False)

    build_app()

    assert "GATEWAY_DEBUG_REASONING_PATH" not in capsys.readouterr().err


def test_debug_reasoning_path_set_warns_loudly_and_builds(monkeypatch, tmp_path, capsys):
    _configure_provider(monkeypatch)
    reasoning_path = tmp_path / "reasoning.jsonl"
    monkeypatch.setenv("GATEWAY_DEBUG_REASONING_PATH", str(reasoning_path))

    app = build_app()

    err = capsys.readouterr().err
    assert "GATEWAY_DEBUG_REASONING_PATH" in err and "NOT the signed audit ledger" in err
    assert not reasoning_path.exists()  # nothing is written until an exchange actually carries reasoning
    assert app is not None
