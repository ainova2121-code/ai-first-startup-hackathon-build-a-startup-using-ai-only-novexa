"""FleetRegistry: a registered gateway's admin key is encrypted at rest, decrypted only for the
poller's own use, never returned by the listing/lookup methods anything else reads."""

from purpleteam.console import crypto
from purpleteam.console.db.repositories import TargetRepository, connect
from purpleteam.console.registry import FleetRegistry

KEY = crypto.derive_key("a console secret")


def _registry(tmp_path, key=KEY):
    return FleetRegistry(TargetRepository(connect(tmp_path / "console.db")), key)


def test_the_secret_never_appears_in_storage(tmp_path):
    registry = _registry(tmp_path)
    target_id = registry.add_target("demo", "https://gw.example", "ptgw_abc_super-secret-value")

    raw = registry._targets.get(target_id)
    assert b"super-secret-value" not in raw["admin_key_enc"]

    base_url, key = registry.credentials_for(target_id)
    assert (base_url, key) == ("https://gw.example", "ptgw_abc_super-secret-value")


def test_list_and_get_never_return_the_key(tmp_path):
    registry = _registry(tmp_path)
    registry.add_target("demo", "https://gw.example", "ptgw_abc_secret")

    for target in registry.list_targets():
        assert not hasattr(target, "admin_key") and not hasattr(target, "admin_key_enc")
    target = registry.get_target(registry.list_targets()[0].id)
    assert not hasattr(target, "admin_key") and not hasattr(target, "admin_key_enc")


def test_credentials_for_an_unknown_target_is_none(tmp_path):
    registry = _registry(tmp_path)
    assert registry.credentials_for("nonexistent") is None


def test_a_wrong_key_cannot_decrypt_another_console_instance_secret(tmp_path):
    registry = _registry(tmp_path, key=KEY)
    target_id = registry.add_target("demo", "https://gw.example", "ptgw_abc_secret")

    wrong_key = crypto.derive_key("a different secret")
    other = FleetRegistry(registry._targets, wrong_key)
    try:
        other.credentials_for(target_id)
        assert False, "should have failed to decrypt"
    except ValueError:
        pass


def test_remove_and_poll_result_round_trip(tmp_path):
    registry = _registry(tmp_path)
    target_id = registry.add_target("demo", "https://gw.example", "ptgw_abc_secret")

    registry.record_poll_result(target_id, log_id="abc", last_seq=3, status="ok", last_error=None)
    target = registry.get_target(target_id)
    assert (target.log_id, target.last_seq, target.status) == ("abc", 3, "ok")

    registry.remove_target(target_id)
    assert registry.get_target(target_id) is None


def test_status_round_trips_through_the_registry(tmp_path):
    registry = _registry(tmp_path)
    target_id = registry.add_target("demo", "https://gw.example", "ptgw_abc_secret")

    registry.set_status(target_id, size=3, safe_to_ship=True, sealed_at=1000.0, breach_kinds_json="[]")
    assert registry.get_status(target_id)["size"] == 3
