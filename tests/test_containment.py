"""The containment escalation ladder: the narrowest level a proven breach actually calls for,
and the manifest update (when there is one) that level produces."""

from purpleteam.defender.containment import ContainmentLevel, decide, escalate
from purpleteam.identity import PermissionManifest

PLAIN = PermissionManifest({"vendor": frozenset({"lookup_vendor", "update_vendor_bank"})})
SCOPED = PermissionManifest.from_dict(
    {"vendor": [{"tool": "update_vendor_bank", "arg": "country", "values": ["US"]}]})


def test_a_declared_resource_allowlist_means_enforcing_it_is_enough():
    level = decide("injection_action", "vendor", "update_vendor_bank", SCOPED)
    assert level == ContainmentLevel.RESOURCE_DENIED
    assert escalate(level, "vendor", "update_vendor_bank", SCOPED) == SCOPED  # nothing to change


def test_no_declared_allowlist_means_denying_the_whole_tool_not_guessing_a_value():
    level = decide("injection_action", "vendor", "update_vendor_bank", PLAIN)
    assert level == ContainmentLevel.TOOL_DENIED

    updated = escalate(level, "vendor", "update_vendor_bank", PLAIN)

    assert not updated.permits("vendor", "update_vendor_bank")
    assert updated.permits("vendor", "lookup_vendor")  # the rest of the agent's access is untouched


def test_a_relied_on_tool_is_held_for_review_instead_of_denied_outright():
    level = decide("injection_action", "vendor", "update_vendor_bank", PLAIN, relied_on=True)
    assert level == ContainmentLevel.HELD_FOR_REVIEW
    assert escalate(level, "vendor", "update_vendor_bank", PLAIN) is None  # a catalog patch, not a manifest edit


def test_a_repeat_offender_is_revoked_outright_even_with_a_declared_allowlist():
    level = decide("injection_action", "vendor", "update_vendor_bank", SCOPED, prior_breaches=2)
    assert level == ContainmentLevel.CREDENTIAL_REVOKED
    assert escalate(level, "vendor", "update_vendor_bank", SCOPED) is None  # a keyring action, not a manifest edit


def test_an_identity_level_breach_is_revoked_regardless_of_the_tool():
    assert decide("identity_mismatch", "vendor", "lookup_vendor", PLAIN) == ContainmentLevel.CREDENTIAL_REVOKED
    assert decide("unauthenticated_agent", "vendor", "lookup_vendor", PLAIN) == ContainmentLevel.CREDENTIAL_REVOKED


def test_tool_denied_also_clears_any_stale_resource_rule_for_that_pair():
    updated = escalate(ContainmentLevel.TOOL_DENIED, "vendor", "update_vendor_bank", SCOPED)
    assert ("vendor", "update_vendor_bank") not in updated.resources


def test_levels_order_narrowest_to_widest():
    assert (ContainmentLevel.RESOURCE_DENIED < ContainmentLevel.TOOL_DENIED
           < ContainmentLevel.HELD_FOR_REVIEW < ContainmentLevel.CREDENTIAL_REVOKED)
