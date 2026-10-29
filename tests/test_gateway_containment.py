"""LiveContainment on its own: what it permits before and after an escalation, and what each
level actually does (or deliberately does not do)."""

from purpleteam.gateway_containment import LiveContainment
from purpleteam.gateway_keys import GatewayKeys
from purpleteam.identity import PermissionManifest

PLAIN = PermissionManifest({"vendor": frozenset({"update_vendor_bank", "lookup_vendor"})})


def test_permits_is_true_for_anything_not_yet_narrowed():
    containment = LiveContainment(PLAIN)
    assert containment.permits("vendor", "update_vendor_bank", {})


def test_tool_denied_narrows_only_that_one_tool():
    containment = LiveContainment(PLAIN)
    event = containment.observe_block("injection_action", "vendor", "update_vendor_bank")
    assert event.level == "tool_denied"
    assert not containment.permits("vendor", "update_vendor_bank", {})
    assert containment.permits("vendor", "lookup_vendor", {})


def test_a_declared_resource_rule_is_enforced_without_any_narrowing_event():
    scoped = PermissionManifest.from_dict(
        {"vendor": [{"tool": "update_vendor_bank", "arg": "country", "values": ["US"]}]})
    containment = LiveContainment(scoped)

    event = containment.observe_block("injection_action", "vendor", "update_vendor_bank")

    assert event.level == "resource_denied"
    assert containment.permits("vendor", "update_vendor_bank", {"country": "US"})
    assert not containment.permits("vendor", "update_vendor_bank", {"country": "FR"})


def test_held_for_review_changes_nothing_and_is_not_auto_applied():
    containment = LiveContainment(PLAIN)
    event = containment.observe_block("injection_action", "vendor", "update_vendor_bank", relied_on=True)
    assert event.level == "held_for_review"
    assert containment.permits("vendor", "update_vendor_bank", {})  # unchanged: a human decides this one


def test_an_identity_breach_revokes_the_credential_on_the_first_offense():
    keys = GatewayKeys()
    token = keys.issue("k", "target", ttl_seconds=3600, max_requests=10, agent="vendor")
    key_id = token.split("_", 2)[1]
    containment = LiveContainment(PLAIN, keys)

    event = containment.observe_block("identity_mismatch", "vendor", "lookup_vendor", key_id)

    assert event.level == "credential_revoked"
    assert not keys.is_active(key_id)


def test_credential_revoked_without_a_keyring_or_key_id_reports_nothing():
    containment = LiveContainment(PLAIN)  # no keys passed in
    assert containment.observe_block("identity_mismatch", "vendor", "lookup_vendor") is None

    containment2 = LiveContainment(PLAIN, GatewayKeys())
    assert containment2.observe_block("identity_mismatch", "vendor", "lookup_vendor", key_id=None) is None


def test_revoking_an_already_gone_key_reports_nothing_rather_than_raising():
    keys = GatewayKeys()
    containment = LiveContainment(PLAIN, keys)
    assert containment.observe_block("identity_mismatch", "vendor", "lookup_vendor", key_id="nope") is None


def test_repeating_an_already_tool_denied_call_reports_nothing_further():
    keys = GatewayKeys()
    token = keys.issue("k", "target", ttl_seconds=3600, max_requests=10, agent="vendor")
    key_id = token.split("_", 2)[1]
    containment = LiveContainment(PLAIN, keys)

    first = containment.observe_block("injection_action", "vendor", "update_vendor_bank", key_id)
    assert first.level == "tool_denied"

    for _ in range(5):
        assert containment.observe_block("injection_action", "vendor", "update_vendor_bank", key_id) is None
    assert keys.is_active(key_id)  # repeats of an already-closed door are not new breaches
