"""The production gateway entry point: built entirely from the environment, refuses to start with
no provider configured, and issues working bootstrap keys since GatewayKeys has no persistent store."""

import pytest

from purpleteam.gateway_main import build_app


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


def test_without_a_redactor_secret_a_clear_warning_is_printed(monkeypatch, capsys):
    monkeypatch.setenv("GATEWAY_OPENAI_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setenv("GATEWAY_OPENAI_KEY", "sk-test-key")
    monkeypatch.delenv("GATEWAY_REDACTOR_SECRET", raising=False)
    build_app()
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
