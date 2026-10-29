"""Gateway keys across restarts: what the store keeps, forgets and refuses, and pinned tokens."""

import pytest

from purpleteam.gateway_keys import (
    ADMIN, TARGET, FileKeyStore, GatewayKeys, generate_token)
from test_gateway_keys import Clock, _bearer, _keys, _refused


def test_a_key_issued_before_a_restart_still_authenticates_after_one(tmp_path):
    store = FileKeyStore(tmp_path / "keys.json")
    first, clock = GatewayKeys(store=store), Clock()
    token = first.issue("ci bot", TARGET, ttl_seconds=3600, max_requests=10, agent="vendor")

    second = GatewayKeys(store=store, clock=clock)  # a fresh process, same store: a "restart"
    grant = second.authenticate(_bearer(token), TARGET)
    assert (grant.label, grant.role, grant.agent) == ("ci bot", TARGET, "vendor")


def test_an_empty_or_missing_store_loads_nothing(tmp_path):
    store = FileKeyStore(tmp_path / "does-not-exist.json")
    keys = GatewayKeys(store=store)
    assert _refused(keys, _bearer("ptgw_aaaaaaaa_x")).status == 401


def test_has_active_label_is_true_only_for_a_live_non_revoked_key():
    keys, clock = _keys()
    assert keys.has_active_label("bootstrap-admin") is False
    token = keys.issue("bootstrap-admin", ADMIN, ttl_seconds=60, max_requests=10)
    assert keys.has_active_label("bootstrap-admin") is True

    key_id = token.split("_")[1]
    keys.revoke(key_id)
    assert keys.has_active_label("bootstrap-admin") is False


def test_has_active_label_is_false_once_the_key_expires():
    keys, clock = _keys()
    keys.issue("bootstrap-admin", ADMIN, ttl_seconds=60, max_requests=10)
    clock.now += 61
    assert keys.has_active_label("bootstrap-admin") is False


def test_a_revoked_key_stays_revoked_across_a_restart(tmp_path):
    store = FileKeyStore(tmp_path / "keys.json")
    first = GatewayKeys(store=store)
    token = first.issue("t", TARGET, ttl_seconds=3600, max_requests=10)
    key_id = token.split("_")[1]
    first.revoke(key_id)

    second = GatewayKeys(store=store)
    assert _refused(second, _bearer(token)).reason == "revoked"


def test_an_expired_key_is_not_loaded_back(tmp_path):
    store = FileKeyStore(tmp_path / "keys.json")
    clock = Clock()
    first = GatewayKeys(store=store, clock=clock)
    token = first.issue("t", TARGET, ttl_seconds=60, max_requests=10)
    clock.now += 61  # now expired

    second = GatewayKeys(store=store, clock=clock)
    assert _refused(second, _bearer(token)).status == 401


def test_usage_counters_start_fresh_after_a_restart_not_frozen_at_the_old_budget(tmp_path):
    store = FileKeyStore(tmp_path / "keys.json")
    first = GatewayKeys(store=store)
    token = first.issue("t", TARGET, ttl_seconds=3600, max_requests=1, per_minute=1000)
    first.authenticate(_bearer(token), TARGET)  # spends the only request this process knew about
    assert _refused(first, _bearer(token)).reason == "budget"

    second = GatewayKeys(store=store)  # a restart must not remember that spend
    grant = second.authenticate(_bearer(token), TARGET)
    assert grant.label == "t"


def test_without_a_store_nothing_is_written_to_disk(tmp_path):
    keys = GatewayKeys()  # store=None, the default: unchanged from before this feature existed
    keys.issue("t", TARGET, ttl_seconds=60, max_requests=10)
    assert list(tmp_path.iterdir()) == []


def test_issuing_prunes_expired_keys_from_the_store_too(tmp_path):
    path = tmp_path / "keys.json"
    store = FileKeyStore(path)
    clock = Clock()
    keys = GatewayKeys(store=store, clock=clock)
    keys.issue("short-lived", TARGET, ttl_seconds=60, max_requests=10)
    clock.now += 61
    keys.issue("another", TARGET, ttl_seconds=60, max_requests=10)  # triggers pruning of the dead one

    saved = store.load_all()
    assert len(saved) == 1 and list(saved.values())[0]["label"] == "another"


def test_a_malformed_store_fails_loud_instead_of_silently_loading_no_keys(tmp_path):
    path = tmp_path / "keys.json"
    path.write_text('{"abc": {"digest": "not valid"}}', encoding="utf-8")
    with pytest.raises(ValueError, match="malformed record"):
        GatewayKeys(store=FileKeyStore(path))


def test_file_key_store_round_trips_save_and_delete(tmp_path):
    store = FileKeyStore(tmp_path / "keys.json")
    store.save("abc", {"label": "t"})
    assert store.load_all() == {"abc": {"label": "t"}}
    store.delete("abc")
    assert store.load_all() == {}


def test_file_key_store_writes_atomically_leaving_no_temp_file(tmp_path):
    store = FileKeyStore(tmp_path / "keys.json")
    store.save("abc", {"label": "t"})
    leftovers = [p for p in tmp_path.iterdir() if p.name != "keys.json"]
    assert leftovers == []


# -- Pinned tokens: a caller (a fleet console) that must already know a key before this process
# starts, instead of this process minting one and the caller finding out after the fact --

def test_generate_token_is_correctly_shaped_and_unique():
    a, b = generate_token(), generate_token()
    assert a != b
    for token in (a, b):
        prefix, key_id, secret = token.split("_", 2)
        assert prefix == "ptgw" and len(key_id) == 8 and len(secret) > 20


def test_issuing_with_a_pinned_token_returns_that_exact_value_and_it_authenticates():
    keys, _ = _keys()
    pinned = generate_token()
    issued = keys.issue("bootstrap-admin", ADMIN, ttl_seconds=60, max_requests=10, token=pinned)
    assert issued == pinned
    grant = keys.authenticate(_bearer(pinned), ADMIN)
    assert grant.label == "bootstrap-admin"


def test_a_pinned_token_with_the_wrong_shape_is_rejected():
    keys, _ = _keys()
    for bad in ("not-a-token", "ptgw_onlyonepart", "wrongprefix_abcd1234_secret", "ptgw__secret", "ptgw_abcd1234_"):
        with pytest.raises(ValueError, match="must look like"):
            keys.issue("k", TARGET, ttl_seconds=60, max_requests=10, token=bad)


def test_pinning_a_token_whose_key_id_is_already_in_use_is_rejected():
    keys, _ = _keys()
    pinned = generate_token()
    keys.issue("first", ADMIN, ttl_seconds=60, max_requests=10, token=pinned)
    with pytest.raises(ValueError, match="already in use"):
        keys.issue("second", ADMIN, ttl_seconds=60, max_requests=10, token=pinned)


def test_a_pinned_token_is_persisted_and_survives_a_restart(tmp_path):
    store = FileKeyStore(tmp_path / "keys.json")
    pinned = generate_token()
    first = GatewayKeys(store=store)
    first.issue("bootstrap-admin", ADMIN, ttl_seconds=3600, max_requests=10, token=pinned)

    second = GatewayKeys(store=store)
    grant = second.authenticate(_bearer(pinned), ADMIN)
    assert grant.label == "bootstrap-admin"
