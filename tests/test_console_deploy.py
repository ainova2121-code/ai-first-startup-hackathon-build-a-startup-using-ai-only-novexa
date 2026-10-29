"""plan_deployment: the paste-and-run self-host command a fleet console hands an operator."""

from purpleteam.console.deploy import plan_deployment
from purpleteam.gateway_keys import GatewayKeys, TARGET, ADMIN


def test_plan_targets_the_given_domain_over_https():
    plan = plan_deployment("gateway.acme.example")
    assert plan.base_url == "https://gateway.acme.example"


def test_admin_and_target_keys_are_distinct_and_correctly_shaped():
    plan = plan_deployment("gateway.acme.example")
    assert plan.admin_key != plan.target_key
    for token in (plan.admin_key, plan.target_key):
        prefix, key_id, secret = token.split("_", 2)  # the url-safe secret may itself contain "_"
        assert prefix == "ptgw" and len(key_id) == 8 and secret


def test_the_script_embeds_both_keys_the_domain_and_a_redactor_secret():
    plan = plan_deployment("gateway.acme.example")
    assert "GATEWAY_DOMAIN=gateway.acme.example" in plan.script
    assert f"GATEWAY_BOOTSTRAP_ADMIN_KEY={plan.admin_key}" in plan.script
    assert f"GATEWAY_BOOTSTRAP_TARGET_KEY={plan.target_key}" in plan.script
    assert "GATEWAY_REDACTOR_SECRET=" in plan.script
    assert "GATEWAY_OPENAI_KEY=" in plan.script  # left blank -- the platform never sees this


def test_two_plans_never_reuse_a_secret():
    a, b = plan_deployment("gw-a.example"), plan_deployment("gw-b.example")
    assert len({a.admin_key, a.target_key, b.admin_key, b.target_key}) == 4


def test_the_generated_keys_actually_authenticate_once_issued_by_a_gateway():
    """The whole point: whatever this hands back must be exactly what gateway_bootstrap.bootstrap_keys
    would accept via GATEWAY_BOOTSTRAP_ADMIN_KEY/GATEWAY_BOOTSTRAP_TARGET_KEY."""
    plan = plan_deployment("gateway.acme.example")
    keys = GatewayKeys()
    keys.issue("bootstrap-admin", ADMIN, ttl_seconds=3600, max_requests=10, token=plan.admin_key)
    keys.issue("bootstrap-target", TARGET, ttl_seconds=3600, max_requests=10, token=plan.target_key)
    assert keys.authenticate(f"Bearer {plan.admin_key}", ADMIN).label == "bootstrap-admin"
    assert keys.authenticate(f"Bearer {plan.target_key}", TARGET).label == "bootstrap-target"
