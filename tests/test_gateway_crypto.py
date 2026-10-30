"""Production cryptographic config: a persisted keyring by default, loud failure on
misconfiguration, hardware-signing policy, and the pinned-trust file helpers."""

import pytest

from purpleteam.audit.hardware_signer import SignerUnavailable
from purpleteam.audit.keys import AgentKeyring
from purpleteam.audit.ledger import AuditLedger
from purpleteam.gateway_crypto import RepinningLedger, hardware, keyring, pinned_trust, save_trust


def test_no_directory_returns_an_ephemeral_keyring_and_warns(monkeypatch, capsys):
    monkeypatch.delenv("GATEWAY_KEYRING_DIR", raising=False)
    monkeypatch.delenv("GATEWAY_REQUIRE_PERSISTENT_KEYS", raising=False)
    result = keyring()
    assert isinstance(result, AgentKeyring)
    assert "in-memory" in capsys.readouterr().err


def test_no_directory_with_required_persistence_refuses(monkeypatch):
    monkeypatch.delenv("GATEWAY_KEYRING_DIR", raising=False)
    monkeypatch.setenv("GATEWAY_REQUIRE_PERSISTENT_KEYS", "true")
    with pytest.raises(RuntimeError, match="GATEWAY_KEYRING_DIR"):
        keyring()


def test_a_directory_with_a_direct_passphrase_persists_the_same_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_KEYRING_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("GATEWAY_KEYRING_PASSPHRASE", "a strong passphrase")
    first = keyring()
    first.kid("gateway")  # forces a key generation on first use
    second = keyring()
    assert second.public_keys() == first.public_keys()


def test_a_directory_with_a_passphrase_file_also_persists(tmp_path, monkeypatch):
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text("a strong passphrase\n")
    monkeypatch.setenv("GATEWAY_KEYRING_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("GATEWAY_KEYRING_PASSPHRASE_FILE", str(passphrase_file))
    monkeypatch.delenv("GATEWAY_KEYRING_PASSPHRASE", raising=False)
    first = keyring()
    first.kid("gateway")
    second = keyring()
    assert second.public_keys() == first.public_keys()


def test_both_passphrase_sources_at_once_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_KEYRING_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("GATEWAY_KEYRING_PASSPHRASE", "one")
    monkeypatch.setenv("GATEWAY_KEYRING_PASSPHRASE_FILE", str(tmp_path / "unused"))
    with pytest.raises(RuntimeError, match="only one"):
        keyring()


def test_a_directory_with_no_passphrase_at_all_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_KEYRING_DIR", str(tmp_path / "keys"))
    monkeypatch.delenv("GATEWAY_KEYRING_PASSPHRASE", raising=False)
    monkeypatch.delenv("GATEWAY_KEYRING_PASSPHRASE_FILE", raising=False)
    with pytest.raises(RuntimeError, match="no passphrase was given"):
        keyring()


def test_allow_classical_history_is_required_to_load_a_pre_pq_keyring(tmp_path, monkeypatch):
    directory, passphrase = tmp_path / "keys", b"a strong passphrase"
    classical = AgentKeyring(directory, passphrase, pq=False)
    classical.kid("gateway")

    monkeypatch.setenv("GATEWAY_KEYRING_DIR", str(directory))
    monkeypatch.setenv("GATEWAY_KEYRING_PASSPHRASE", passphrase.decode())
    monkeypatch.delenv("GATEWAY_KEYRING_ALLOW_CLASSICAL_HISTORY", raising=False)
    with pytest.raises(ValueError, match="classical-only key"):
        keyring()

    monkeypatch.setenv("GATEWAY_KEYRING_ALLOW_CLASSICAL_HISTORY", "true")
    assert keyring() is not None  # does not raise


def test_hardware_signing_is_off_by_default_and_needs_no_hardware(monkeypatch):
    monkeypatch.delenv("GATEWAY_HARDWARE_SIGNING", raising=False)
    assert hardware() is None  # real resolve_signer; "off" never touches a TPM


def test_an_unknown_hardware_policy_is_rejected(monkeypatch):
    monkeypatch.setenv("GATEWAY_HARDWARE_SIGNING", "sometimes")
    with pytest.raises(RuntimeError, match="must be one of"):
        hardware()


def test_hardware_policy_and_key_name_are_passed_through(monkeypatch, capsys):
    monkeypatch.setenv("GATEWAY_HARDWARE_SIGNING", "preferred")
    monkeypatch.setenv("GATEWAY_HARDWARE_KEY_NAME", "my-checkpoint-key")
    seen = {}

    def fake_resolve(policy, name):
        seen["policy"], seen["name"] = policy, name
        return "a-fake-signer", "a note about what happened"

    result = hardware(resolve=fake_resolve)
    assert result == "a-fake-signer"
    assert seen == {"policy": "preferred", "name": "my-checkpoint-key"}
    assert "a note about what happened" in capsys.readouterr().err


def test_hardware_required_but_unavailable_propagates(monkeypatch):
    monkeypatch.setenv("GATEWAY_HARDWARE_SIGNING", "required")

    def fake_resolve(policy, name):
        raise SignerUnavailable("no TPM here")

    with pytest.raises(SignerUnavailable):
        hardware(resolve=fake_resolve)


def test_pinned_trust_with_no_path_or_a_missing_file_returns_nothing(tmp_path):
    assert pinned_trust(None) == (None, None)
    assert pinned_trust(tmp_path / "does-not-exist.json") == (None, None)


def test_save_then_load_trust_round_trips(tmp_path):
    path = tmp_path / "nested" / "trust.json"
    trust = {"checkpoint": {"size": 3, "root": "abc"}, "hardware": {"kid1": {"kind": "tpm2"}}}
    save_trust(path, trust)
    assert pinned_trust(path) == (trust["checkpoint"], trust["hardware"])


def test_save_trust_with_no_path_does_not_raise():
    save_trust(None, {"checkpoint": {}})  # no-op, must not error


def test_save_trust_writes_atomically_leaving_no_temp_file_behind(tmp_path):
    path = tmp_path / "trust.json"
    save_trust(path, {"checkpoint": {"size": 1}})
    leftovers = [p for p in tmp_path.iterdir() if p != path]
    assert leftovers == []


def test_a_corrupt_trust_file_fails_loud_instead_of_being_read_as_no_pin_yet(tmp_path):
    path = tmp_path / "trust.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="not readable JSON"):
        pinned_trust(path)


def test_a_trust_file_that_is_not_an_object_fails_loud(tmp_path):
    path = tmp_path / "trust.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(RuntimeError, match="does not hold the expected object"):
        pinned_trust(path)


def test_an_unknown_hardware_backend_is_rejected(monkeypatch):
    monkeypatch.setenv("GATEWAY_HARDWARE_SIGNING", "preferred")
    monkeypatch.setenv("GATEWAY_HARDWARE_BACKEND", "quantum")
    with pytest.raises(RuntimeError, match="GATEWAY_HARDWARE_BACKEND must be one of"):
        hardware()


def test_the_default_backend_is_tpm_and_passes_no_opener(monkeypatch):
    """Existing (pre-multi-backend) callers of ``resolve`` never see an ``opener`` kwarg."""
    monkeypatch.setenv("GATEWAY_HARDWARE_SIGNING", "preferred")
    monkeypatch.delenv("GATEWAY_HARDWARE_BACKEND", raising=False)
    seen = {}

    def fake_resolve(policy, name):
        seen["called"] = True
        return None, "no opener kwarg was passed"

    hardware(resolve=fake_resolve)
    assert seen["called"]


def test_the_pkcs11_backend_passes_a_callable_opener_to_resolve(monkeypatch):
    monkeypatch.setenv("GATEWAY_HARDWARE_SIGNING", "preferred")
    monkeypatch.setenv("GATEWAY_HARDWARE_BACKEND", "pkcs11")
    seen = {}

    def fake_resolve(policy, name, *, opener=None):
        seen["opener"] = opener
        return None, "ok"

    hardware(resolve=fake_resolve)
    assert callable(seen["opener"])


def test_the_kms_backend_passes_a_callable_opener_to_resolve(monkeypatch):
    monkeypatch.setenv("GATEWAY_HARDWARE_SIGNING", "preferred")
    monkeypatch.setenv("GATEWAY_HARDWARE_BACKEND", "kms")
    seen = {}

    def fake_resolve(policy, name, *, opener=None):
        seen["opener"] = opener
        return None, "ok"

    hardware(resolve=fake_resolve)
    assert callable(seen["opener"])


def test_backend_config_is_only_read_when_the_opener_actually_runs(monkeypatch):
    """GATEWAY_HARDWARE_SIGNING=off (the default) must never touch GATEWAY_PKCS11_* at all, even
    with a typo'd or missing config and GATEWAY_HARDWARE_BACKEND=pkcs11 set."""
    monkeypatch.delenv("GATEWAY_HARDWARE_SIGNING", raising=False)
    monkeypatch.setenv("GATEWAY_HARDWARE_BACKEND", "pkcs11")
    monkeypatch.delenv("GATEWAY_PKCS11_MODULE", raising=False)
    assert hardware() is None  # does not raise despite missing PKCS#11 config


def test_pkcs11_backend_without_module_env_vars_fails_loudly_when_used(monkeypatch):
    monkeypatch.setenv("GATEWAY_HARDWARE_SIGNING", "required")
    monkeypatch.setenv("GATEWAY_HARDWARE_BACKEND", "pkcs11")
    monkeypatch.delenv("GATEWAY_PKCS11_MODULE", raising=False)
    monkeypatch.delenv("GATEWAY_PKCS11_TOKEN", raising=False)
    monkeypatch.delenv("GATEWAY_PKCS11_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GATEWAY_PKCS11_MODULE"):
        hardware()  # real resolve_signer calls the real opener under "required"


def test_pkcs11_pin_needs_exactly_one_source(monkeypatch, tmp_path):
    from purpleteam.gateway_crypto import _pkcs11_pin

    monkeypatch.delenv("GATEWAY_PKCS11_PIN", raising=False)
    monkeypatch.delenv("GATEWAY_PKCS11_PIN_FILE", raising=False)
    with pytest.raises(RuntimeError, match="needs a PIN"):
        _pkcs11_pin()

    monkeypatch.setenv("GATEWAY_PKCS11_PIN", "1234")
    monkeypatch.setenv("GATEWAY_PKCS11_PIN_FILE", str(tmp_path / "unused"))
    with pytest.raises(RuntimeError, match="only one"):
        _pkcs11_pin()

    monkeypatch.delenv("GATEWAY_PKCS11_PIN_FILE", raising=False)
    assert _pkcs11_pin().get_secret_value() == "1234"


def test_pkcs11_pin_file_is_read_and_stripped(monkeypatch, tmp_path):
    from purpleteam.gateway_crypto import _pkcs11_pin

    pin_file = tmp_path / "pin.txt"
    pin_file.write_text("5678\n")
    monkeypatch.delenv("GATEWAY_PKCS11_PIN", raising=False)
    monkeypatch.setenv("GATEWAY_PKCS11_PIN_FILE", str(pin_file))
    assert _pkcs11_pin().get_secret_value() == "5678"


def test_kms_backend_without_key_fails_loudly_when_used(monkeypatch):
    monkeypatch.setenv("GATEWAY_HARDWARE_SIGNING", "required")
    monkeypatch.setenv("GATEWAY_HARDWARE_BACKEND", "kms")
    monkeypatch.delenv("GATEWAY_KMS_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GATEWAY_KMS_KEY"):
        hardware()


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_repinning_ledger_pins_after_the_event_count_threshold(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl", keyring=keyring())
    trust_path = tmp_path / "trust.json"
    wrapped = RepinningLedger(ledger, trust_path, every=3, seconds=10_000, clock=_FakeClock())

    wrapped.append("attacker", "attack", {"id": 1})
    assert pinned_trust(trust_path)[0]["size"] == 1  # a log's first event is pinned at once
    wrapped.append("attacker", "attack", {"id": 2})
    wrapped.append("attacker", "attack", {"id": 3})
    assert pinned_trust(trust_path)[0]["size"] == 1  # below the threshold
    wrapped.append("attacker", "attack", {"id": 4})
    assert pinned_trust(trust_path)[0]["size"] == 4


def test_repinning_ledger_pins_after_the_time_threshold(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl", keyring=keyring())
    trust_path = tmp_path / "trust.json"
    clock = _FakeClock()
    wrapped = RepinningLedger(ledger, trust_path, every=1_000_000, seconds=60, clock=clock)

    wrapped.append("attacker", "attack", {"id": 1})
    wrapped.append("attacker", "attack", {"id": 2})
    assert pinned_trust(trust_path)[0]["size"] == 1  # only the first event; well below the count threshold
    clock.now = 61
    wrapped.append("attacker", "attack", {"id": 3})
    assert pinned_trust(trust_path)[0]["size"] == 3


def test_repinning_ledger_delegates_every_other_attribute(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl", keyring=keyring())
    wrapped = RepinningLedger(ledger, tmp_path / "trust.json", every=1_000_000, seconds=1_000_000)

    wrapped.append("attacker", "attack", {"id": 1})
    assert wrapped.count() == 1 and wrapped.events() == ledger.events() and wrapped.verify().ok
