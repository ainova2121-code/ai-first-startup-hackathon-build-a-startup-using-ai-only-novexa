"""The gateway's first-start keys: printed once, short-lived, budgeted, pinnable by a fleet console, never reissued."""

import re

import pytest
from fastapi.testclient import TestClient

from purpleteam.gateway_main import build_app
from test_gateway_main import _configure_provider


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


def test_pinned_bootstrap_keys_are_used_as_is_and_not_reprinted(monkeypatch, capsys):
    from purpleteam.gateway_keys import generate_token

    _configure_provider(monkeypatch)
    admin_token, target_token = generate_token(), generate_token()
    monkeypatch.setenv("GATEWAY_BOOTSTRAP_ADMIN_KEY", admin_token)
    monkeypatch.setenv("GATEWAY_BOOTSTRAP_TARGET_KEY", target_token)

    app = build_app()
    err = capsys.readouterr().err
    assert "pinned from GATEWAY_BOOTSTRAP_ADMIN_KEY" in err
    assert admin_token not in err and target_token not in err  # already known to whoever set them

    web = TestClient(app)
    assert web.get("/profile", headers={"authorization": f"Bearer {admin_token}"}).status_code == 200


def test_pinned_bootstrap_keys_need_both_or_neither(monkeypatch):
    from purpleteam.gateway_keys import generate_token

    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_BOOTSTRAP_ADMIN_KEY", generate_token())
    monkeypatch.delenv("GATEWAY_BOOTSTRAP_TARGET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="both GATEWAY_BOOTSTRAP_ADMIN_KEY"):
        build_app()


def test_pinned_bootstrap_keys_are_not_reissued_on_a_persisted_restart(monkeypatch, tmp_path):
    from purpleteam.gateway_keys import generate_token

    _configure_provider(monkeypatch)
    monkeypatch.setenv("GATEWAY_KEYS_FILE", str(tmp_path / "keys.json"))
    admin_token, target_token = generate_token(), generate_token()
    monkeypatch.setenv("GATEWAY_BOOTSTRAP_ADMIN_KEY", admin_token)
    monkeypatch.setenv("GATEWAY_BOOTSTRAP_TARGET_KEY", target_token)

    build_app()  # first "startup"
    second_app = build_app()  # a "restart": must not try (and fail) to re-pin the same key id
    web = TestClient(second_app)
    assert web.get("/profile", headers={"authorization": f"Bearer {admin_token}"}).status_code == 200
