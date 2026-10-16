"""The ledger resists truncation, rewrites, key games and concurrent writers — given pinned trust."""

import hashlib
import threading

import pytest

from fixtures.ledger import log_lines, make_ledger, rewrite_log
from purpleteam.audit.hashing import inclusion_path, merkle_root, verify_inclusion
from purpleteam.audit.keys import AgentKeyring
from purpleteam.audit.ledger import AuditLedger, LedgerCorrupt
from purpleteam.audit.verify import verify_log, verify_proof


def test_every_leaf_of_every_tree_size_has_a_valid_inclusion_proof():
    for size in range(1, 18):
        hashes = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(size)]
        root = merkle_root(hashes)
        for index in range(size):
            path = inclusion_path(hashes, index)
            assert verify_inclusion(hashes[index], index, size, path, root)
            assert not verify_inclusion(hashes[index], (index + 1) % size, size, path, root) or size == 1
            assert not verify_inclusion(hashes[index][::-1], index, size, path, root)


def test_hostile_proof_inputs_are_rejected_not_raised():
    hashes = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(4)]
    root = merkle_root(hashes)
    assert not verify_inclusion(hashes[0], 0, 4, ["not-hex"], root)
    assert not verify_inclusion(hashes[0], 0, 4, ["00" * 32] * 200, root)
    assert not verify_inclusion(hashes[0], 9, 4, [], root)


def test_tail_truncation_is_only_caught_with_a_pinned_checkpoint(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl")
    trust = ledger.export_trust()
    rewrite_log(ledger, log_lines(ledger)[:-1])

    assert ledger.verify().ok and not ledger.verify().anchored  # internal consistency cannot see it
    caught = ledger.verify(trust)
    assert not caught.ok and "truncated" in caught.reason


def test_intact_log_is_anchored_by_its_checkpoint(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl")
    trust = ledger.export_trust()
    ledger.append("attacker", "attack", {"n": 99})  # growth after the checkpoint is legitimate
    result = ledger.verify(trust)
    assert result.ok and result.anchored


def test_rewrite_with_fresh_keys_fails_against_pinned_keys(tmp_path):
    original = make_ledger(tmp_path / "audit.jsonl")
    forged = make_ledger(tmp_path / "forged.jsonl")  # attacker signs a clean-looking log with new keys
    result = verify_log(forged.events(), original.export_trust())
    assert not result.ok and "signature" in result.reason


def test_rewrite_with_stolen_keys_fails_against_the_checkpoint(tmp_path):
    keyring = AgentKeyring()
    original = make_ledger(tmp_path / "audit.jsonl", keyring)
    trust = original.export_trust()
    log_id = trust["checkpoint"]["log"]
    forged = AuditLedger(tmp_path / "forged.jsonl", keyring=keyring, log_id=log_id)  # same keys and id, altered history
    for i in range(5):
        forged.append("attacker" if i % 2 == 0 else "oracle", "attack", {"n": i + 100})
    result = verify_log(forged.events(), trust)
    assert not result.ok and "rewritten" in result.reason


def test_removed_or_reordered_events_are_detected(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl")
    lines = log_lines(ledger)
    rewrite_log(ledger, lines[:2] + lines[3:])
    assert not ledger.verify().ok and "sequence" in ledger.verify().reason


def test_a_seal_that_misstates_the_log_is_detected(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl", events=3)
    ledger.append("audit", "seal", {"merkle_root": "f" * 64})
    assert "seal" in ledger.verify().reason


def test_a_trust_bundle_with_a_swapped_key_is_rejected(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl")
    trust = ledger.export_trust()
    trust["keys"]["attacker"] = {kid: "00" * 32 for kid in trust["keys"]["attacker"]}
    result = ledger.verify(trust)
    assert not result.ok and "malformed" in result.reason


def test_one_event_is_provable_without_the_rest_of_the_log(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl", events=7)
    trust = ledger.export_trust()
    proof = ledger.prove(3, size=trust["checkpoint"]["size"])
    assert verify_proof(proof, trust)

    proof["event"] = {**proof["event"], "payload": {"n": 1234}}
    assert not verify_proof(proof, trust)
    assert not verify_proof({**ledger.prove(3), "size": 2}, trust)


def test_rotation_keeps_old_events_verifiable(tmp_path):
    keyring = AgentKeyring()
    ledger = AuditLedger(tmp_path / "audit.jsonl", keyring=keyring)
    ledger.append("attacker", "attack", {"n": 1})
    old_kid = keyring.kid("attacker")
    new_kid = keyring.rotate("attacker")
    ledger.append("attacker", "attack", {"n": 2})

    assert old_kid != new_kid
    assert [e["kid"] for e in ledger.events()] == [old_kid, new_kid]
    assert ledger.verify().ok and set(keyring.public_keys()["attacker"]) == {old_kid, new_kid}


def test_stored_keys_are_encrypted_and_survive_a_restart(tmp_path):
    with pytest.raises(ValueError):
        AgentKeyring(tmp_path / "keys")  # refuses to write private keys in the clear

    keys = tmp_path / "keys"
    first = AgentKeyring(keys, passphrase=b"correct horse")
    ledger = AuditLedger(tmp_path / "audit.jsonl", keyring=first)
    ledger.append("attacker", "attack", {"n": 1})
    first.rotate("attacker")

    assert all(b"ENCRYPTED PRIVATE KEY" in p.read_bytes() for p in keys.glob("*.pem"))
    restarted = AuditLedger(tmp_path / "audit.jsonl", keyring=AgentKeyring(keys, b"correct horse"))
    restarted.append("attacker", "attack", {"n": 2})
    assert restarted.verify().ok
    with pytest.raises(ValueError):
        AgentKeyring(keys, passphrase=b"wrong")


def test_actor_names_cannot_escape_the_key_directory(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl", keyring=AgentKeyring(tmp_path / "keys", b"pw"))
    with pytest.raises(ValueError):
        ledger.append("../../evil", "attack", {})
    assert ledger.count() == 0 and not list(tmp_path.rglob("evil*"))


def test_concurrent_writers_keep_one_valid_log(tmp_path):
    keyring = AgentKeyring()
    path = tmp_path / "audit.jsonl"

    def write(worker: int) -> None:
        ledger = AuditLedger(path, keyring=keyring)
        for i in range(8):
            ledger.append(f"agent{worker}", "attack", {"n": i})

    threads = [threading.Thread(target=write, args=(w,)) for w in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    ledger = AuditLedger(path, keyring=keyring)
    assert [e["seq"] for e in ledger.events()] == list(range(32))
    assert ledger.verify().ok


def test_a_partial_trailing_record_is_refused_not_extended(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl", events=3)
    with ledger.path.open("ab") as handle:
        handle.write(b'{"seq": 3, "ts"')  # a crash mid-write
    assert not ledger.verify().ok
    with pytest.raises(LedgerCorrupt):
        ledger.append("attacker", "attack", {"n": 4})
