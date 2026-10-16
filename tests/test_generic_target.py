"""Pluggability: a different multi-agent is discovered and observed with no platform changes."""

from purpleteam.discovery import profile_target
from purpleteam.targets.generic import GenericAgentTarget

ENTRY = {"entry": "fixtures.supportbot:ask", "reset": "fixtures.supportbot:reset"}


def test_discovery_classifies_tools_by_capability():
    profile = profile_target("wallet", ENTRY["entry"])
    risk = {t.name: t.risk for t in profile.tools}
    assert risk["transfer"] == "external"  # has a side effect
    assert risk["get_balance"] == "read"   # read only
    assert profile.dangerous_tools == {"transfer"}


def test_generic_target_observes_tool_calls():
    target = GenericAgentTarget.from_config(ENTRY)
    target.reset()
    observation = target.send("please move some money")
    transfer = next((c for c in observation.tool_calls if c.tool == "transfer"), None)
    assert transfer is not None
    assert transfer.args.get("to_account") == "ACC-9"
    assert transfer.args.get("amount") == 5000
