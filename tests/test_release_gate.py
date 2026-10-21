"""The release gate: a bare verify().ok is never enough — a checkpoint must actually be present,
actually anchor the log, actually be hardware-signed, and actually cover the exact build."""

import pytest

from purpleteam.audit.hardware_signer import SoftwareP256Signer
from purpleteam.audit.ledger import AuditLedger
from purpleteam.audit.release_gate import (
    bind_release, require_build_covered, require_hardware_backed_checkpoint, require_no_containment_escalations)

REVISION = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
DIGEST = "0" * 64
OTHER_DIGEST = "1" * 64


class _FakeTpmSigner(SoftwareP256Signer):
    """Real P-256 crypto (inherited), but claims the ``tpm2`` kind — exactly what a real TPM
    signer would report, without needing real hardware for the test."""

    kind = "tpm2"


def test_bind_release_rejects_a_bad_revision_or_digest(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    with pytest.raises(ValueError, match="revision"):
        bind_release(ledger, "has a space", DIGEST)
    with pytest.raises(ValueError, match="digest"):
        bind_release(ledger, REVISION, "not-hex")


def test_bind_release_appends_a_signed_event(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    event = bind_release(ledger, REVISION, DIGEST)
    assert event["actor"] == "release" and event["kind"] == "build"
    assert event["payload"] == {"revision": REVISION, "digest": DIGEST}


def test_no_checkpoint_in_the_trust_bundle_fails(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("attacker", "attack", {"id": 1})
    assert require_hardware_backed_checkpoint(ledger, {}).ok is False
    result = require_hardware_backed_checkpoint(ledger, {})
    assert "no checkpoint" in result.reason


def test_a_software_only_checkpoint_is_rejected(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("attacker", "attack", {"id": 1})
    trust = ledger.export_trust()  # no hardware= on this ledger at all
    result = require_hardware_backed_checkpoint(ledger, trust)
    assert result.ok is False and "hardware-protected key" in result.reason


def test_a_software_kind_hardware_signer_is_still_rejected(tmp_path):
    """SoftwareP256Signer honestly reports kind="software"; that must never pass a hardware gate."""
    ledger = AuditLedger(tmp_path / "audit.jsonl", hardware=SoftwareP256Signer())
    ledger.append("attacker", "attack", {"id": 1})
    trust = ledger.export_trust()
    result = require_hardware_backed_checkpoint(ledger, trust)
    assert result.ok is False and "hardware-protected key" in result.reason


def test_a_genuinely_hardware_signed_checkpoint_passes(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl", hardware=_FakeTpmSigner())
    ledger.append("attacker", "attack", {"id": 1})
    trust = ledger.export_trust()
    result = require_hardware_backed_checkpoint(ledger, trust)
    assert result.ok is True and result.hardware == "tpm2"


def test_a_tampered_log_fails_even_with_a_hardware_signed_checkpoint(tmp_path):
    path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(path, hardware=_FakeTpmSigner())
    ledger.append("attacker", "attack", {"note": "original-value"})
    trust = ledger.export_trust()
    original = path.read_text(encoding="utf-8")
    tampered = original.replace("original-value", "TAMPERED-value")
    assert tampered != original  # the replace must have actually matched something
    path.write_text(tampered, encoding="utf-8")
    reopened = AuditLedger(path, hardware=_FakeTpmSigner())
    assert require_hardware_backed_checkpoint(reopened, trust).ok is False


def test_build_coverage_fails_without_any_release_event(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl", hardware=_FakeTpmSigner())
    ledger.append("attacker", "attack", {"id": 1})
    trust = ledger.export_trust()
    result = require_build_covered(ledger, trust, revision=REVISION, digest=DIGEST)
    assert result.ok is False and "no checkpointed release event" in result.reason


def test_build_coverage_fails_for_a_different_revision_or_digest(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl", hardware=_FakeTpmSigner())
    bind_release(ledger, REVISION, DIGEST)
    trust = ledger.export_trust()
    assert require_build_covered(ledger, trust, revision=REVISION, digest=OTHER_DIGEST).ok is False
    assert require_build_covered(ledger, trust, revision="f" * 40, digest=DIGEST).ok is False


def test_build_coverage_passes_when_the_checkpoint_covers_the_matching_release_event(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl", hardware=_FakeTpmSigner())
    bind_release(ledger, REVISION, DIGEST)
    trust = ledger.export_trust()
    result = require_build_covered(ledger, trust, revision=REVISION, digest=DIGEST)
    assert result.ok is True and result.hardware == "tpm2"


def test_a_release_event_appended_after_the_checkpoint_is_not_counted_as_covered(tmp_path):
    """The binding must be inside the checkpointed size, not merely present somewhere in the file —
    otherwise a build could be bound AFTER the checkpoint that is supposed to vouch for it. A
    different revision is bound first only so the "release" actor's key already exists in the
    trust snapshot — isolating the size check from an unrelated "unknown key" failure."""
    ledger = AuditLedger(tmp_path / "audit.jsonl", hardware=_FakeTpmSigner())
    bind_release(ledger, "0" * 40, OTHER_DIGEST)
    trust = ledger.export_trust()  # checkpoint covers only the line above
    bind_release(ledger, REVISION, DIGEST)  # not covered by the checkpoint taken just before this
    result = require_build_covered(ledger, trust, revision=REVISION, digest=DIGEST)
    assert result.ok is False and "no checkpointed release event" in result.reason


def _validated(tmp_path, decisions=1, escalate=False, min_decisions=1, name="audit.jsonl"):
    ledger = AuditLedger(tmp_path / name, hardware=_FakeTpmSigner())
    bind_release(ledger, REVISION, DIGEST)
    for i in range(decisions):
        ledger.append("gateway", "decision", {"action": "tool_call", "tool": "lookup_vendor", "policy": ""})
    if escalate:
        ledger.append("gateway", "containment", {"level": "tool_denied", "agent": "vendor", "tool": "transfer_funds",
                                                  "kind": "injection_action", "reason": "x"})
    trust = ledger.export_trust()
    return require_no_containment_escalations(ledger, trust, revision=REVISION, digest=DIGEST,
                                              min_decisions=min_decisions)


def test_passes_a_build_whose_validation_window_had_real_traffic_and_no_escalations(tmp_path):
    result = _validated(tmp_path, decisions=3)
    assert result.ok is True and result.hardware == "tpm2"


def test_fails_a_build_whose_window_included_any_containment_escalation(tmp_path):
    result = _validated(tmp_path, decisions=3, escalate=True)
    assert result.ok is False and "tool_denied" in result.reason and "transfer_funds" in result.reason


def test_a_window_with_no_gateway_decisions_proves_nothing_and_fails(tmp_path):
    result = _validated(tmp_path, decisions=0)
    assert result.ok is False and "0 gateway decision" in result.reason


def test_min_decisions_is_configurable(tmp_path):
    assert _validated(tmp_path, decisions=2, min_decisions=3, name="a.jsonl").ok is False
    assert _validated(tmp_path, decisions=3, min_decisions=3, name="b.jsonl").ok is True


def test_only_the_window_after_this_build_was_bound_counts(tmp_path):
    """Traffic and even an escalation from an earlier build's window must not fail (or pass) a
    later, different build's gate — each build's validation window is its own evidence."""
    ledger = AuditLedger(tmp_path / "audit.jsonl", hardware=_FakeTpmSigner())
    ledger.append("gateway", "decision", {"action": "tool_call", "tool": "lookup_vendor", "policy": ""})
    ledger.append("gateway", "containment", {"level": "credential_revoked", "agent": "old", "tool": "x",
                                             "kind": "identity_mismatch", "reason": "from an earlier build"})
    bind_release(ledger, REVISION, DIGEST)
    ledger.append("gateway", "decision", {"action": "tool_call", "tool": "lookup_vendor", "policy": ""})
    trust = ledger.export_trust()

    result = require_no_containment_escalations(ledger, trust, revision=REVISION, digest=DIGEST)

    assert result.ok is True
