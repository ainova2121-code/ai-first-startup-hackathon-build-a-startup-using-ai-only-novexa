"""The gateway's audit ledger at startup: redaction required or explicitly waived, pinning, and the debug log."""


import pytest

from purpleteam.audit.ledger import AuditLedger
from purpleteam.gateway_crypto import keyring as _keyring
from purpleteam.gateway_main import build_app
from test_gateway_main import _configure_provider


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
