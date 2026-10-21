"""A tiny target purpose-built to exercise purpleteam.sandbox's child-process boundary: success,
failure, a wrong return type, a hang, noisy stdout, and env-var visibility — each its own entry point."""

import os
import time

from purpleteam.discovery import DiscoveredTool, TargetProfile


def ok() -> TargetProfile:
    return TargetProfile("sandboxed", [DiscoveredTool("do_thing", "", {}, "fixture", "write", "")])


def not_a_profile():
    return "not a TargetProfile"


def broken():
    raise RuntimeError("the target's own construction code failed")


def hangs() -> TargetProfile:
    time.sleep(30)
    return ok()


def noisy() -> TargetProfile:
    print("a banner the target prints while it is being imported or built, not our JSON protocol")
    print({"this": "looks like it could be JSON but it is not"})
    return ok()


def reads_env() -> TargetProfile:
    return TargetProfile(os.environ.get("SANDBOX_TEST_SECRET", "<not set>"), [])


def floods() -> TargetProfile:
    """Writes directly to the OS file descriptor, bypassing ``sys.stdout`` (and so the worker's
    own ``redirect_stdout``) entirely — the one way a target can still reach the parent's real
    pipe, which is exactly what the output cap in ``purpleteam.sandbox`` must catch."""
    chunk = b"x" * 65_536
    while True:
        os.write(1, chunk)
