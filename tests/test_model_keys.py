"""The platform's own models find their key without depending on any target's configuration: the role's own
variable first, then the shared platform key, and the demo target's variable only as a legacy fallback."""

from purpleteam.model_keys import ATTACKER_KEYS, LEGACY, SHARED, missing_key, platform_key


def test_the_roles_own_key_wins_then_the_shared_platform_key_then_the_legacy_one(monkeypatch):
    for name in (*ATTACKER_KEYS, SHARED, LEGACY):
        monkeypatch.delenv(name, raising=False)
    assert platform_key(*ATTACKER_KEYS) == ""
    monkeypatch.setenv(LEGACY, "legacy")
    assert platform_key(*ATTACKER_KEYS) == "legacy"  # an existing demo setup keeps working
    monkeypatch.setenv(SHARED, "shared")
    assert platform_key(*ATTACKER_KEYS) == "shared"
    monkeypatch.setenv("GROQ_API_KEY", "role")
    assert platform_key(*ATTACKER_KEYS) == "role"


def test_the_error_names_the_platforms_own_variables_never_a_targets():
    message = missing_key("attacker-model", *ATTACKER_KEYS)
    assert SHARED in message and "PURPLETEAM_ATTACKER_KEY" in message and LEGACY not in message
