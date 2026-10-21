"""The discovery sandbox: a target's own code runs in a child process, never this one — success,
failure, a hang, noisy stdout, and the platform's own environment are all proven isolated."""

import os
import time
from pathlib import Path

import pytest

from purpleteam.capture import DiscoveryError
from purpleteam.sandbox import discover_sandboxed
from purpleteam.targets.ledgerpilot import discover_profile as ledgerpilot_discover_profile

RUNTIME = "fixtures.sandbox_target"
# pytest puts tests/ on sys.path for its own collection; a spawned subprocess does not inherit that,
# so every call here opts PYTHONPATH in explicitly to make "fixtures.*" importable in the child too.
TESTS_DIR = str(Path(__file__).resolve().parent)


def _discover(entry: str, **kwargs):
    env = {"PYTHONPATH": TESTS_DIR, **kwargs.pop("env", {})}
    return discover_sandboxed(entry, env=env, **kwargs)


def test_a_real_target_is_discovered_identically_sandboxed_and_in_process():
    sandboxed = discover_sandboxed("purpleteam.targets.ledgerpilot:discover_profile", timeout=60)
    in_process = ledgerpilot_discover_profile()
    assert sandboxed.agents == in_process.agents
    assert {t.name for t in sandboxed.tools} == {t.name for t in in_process.tools}
    assert sandboxed.dangerous_tools == in_process.dangerous_tools


def test_a_successful_target_returns_a_real_target_profile():
    profile = _discover(f"{RUNTIME}:ok")
    assert profile.name == "sandboxed" and [t.name for t in profile.tools] == ["do_thing"]
    assert profile.tools[0].tool is None  # the live object never crosses the process boundary


def test_a_target_that_fails_to_construct_raises_discoveryerror_naming_the_cause():
    with pytest.raises(DiscoveryError, match="RuntimeError"):
        _discover(f"{RUNTIME}:broken")


def test_a_target_whose_entry_point_returns_the_wrong_type_is_rejected():
    with pytest.raises(DiscoveryError, match="TargetProfile"):
        _discover(f"{RUNTIME}:not_a_profile")


def test_a_hanging_target_is_killed_and_reported_as_a_timeout():
    with pytest.raises(DiscoveryError, match="did not finish"):
        _discover(f"{RUNTIME}:hangs", timeout=1)


def test_noisy_stdout_from_the_target_does_not_corrupt_the_result():
    profile = _discover(f"{RUNTIME}:noisy")
    assert profile.name == "sandboxed"


def test_this_processs_environment_is_not_visible_to_the_sandboxed_target():
    os.environ["SANDBOX_TEST_SECRET"] = "do-not-leak-me"
    try:
        profile = _discover(f"{RUNTIME}:reads_env")
    finally:
        del os.environ["SANDBOX_TEST_SECRET"]
    assert profile.name == "<not set>"


def test_an_explicitly_opted_in_env_var_does_reach_the_target():
    profile = _discover(f"{RUNTIME}:reads_env", env={"SANDBOX_TEST_SECRET": "opted-in"})
    assert profile.name == "opted-in"


def test_a_flooding_target_is_cut_off_and_reported_as_too_much_output():
    """``floods`` writes directly to fd 1, bypassing the worker's ``redirect_stdout`` — the one
    way a target can still reach the parent's real pipe."""
    with pytest.raises(DiscoveryError, match="more output than this will trust"):
        _discover(f"{RUNTIME}:floods", timeout=30)


def test_the_flood_is_cut_off_live_not_buffered_until_the_timeout():
    """The cap must be enforced as bytes arrive, not checked only after the subprocess exits —
    an unbounded flood never naturally exits, so a post-hoc check would never even run."""
    start = time.monotonic()
    with pytest.raises(DiscoveryError, match="more output than this will trust"):
        _discover(f"{RUNTIME}:floods", timeout=30)
    assert time.monotonic() - start < 15  # cut off well inside the 30s timeout


def test_an_unknown_mode_is_rejected_before_spawning_anything():
    with pytest.raises(ValueError, match="mode"):
        discover_sandboxed(f"{RUNTIME}:ok", mode="bogus")


def test_static_mode_discovers_tools_by_scanning_the_target_module():
    profile = _discover("fixtures.supportbot:ask", mode="static")
    assert {t.name for t in profile.tools} == {"get_balance", "transfer"}
