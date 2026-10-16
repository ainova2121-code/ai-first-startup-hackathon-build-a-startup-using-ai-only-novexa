"""Run a target's discovery in an isolated child process instead of this one.

``capture.profile_runtime`` and ``discovery.discover_tools`` both import and execute a target's own
code to see what it is built from — the one place this platform runs code it does not control. This
module runs that step in a short-lived subprocess instead (``sandbox_worker``): a target that
crashes, hangs, or does something hostile at import time cannot touch this process's memory,
environment or secrets, and a timeout bounds how long it is allowed to run. The child communicates
back only plain JSON — a profile's data, never a live object.

This is not full production sandboxing: no container, no seccomp, no filesystem or network
restriction. That needs an OS-level enforcement layer this platform does not control (see
``capture.py`` and ``targets/generic.py``). It closes the sharpest edge — arbitrary code executing
in the platform's own process — with what plain process isolation gives on any OS; a target that is
actively adversarial (not merely untrusted) still needs that heavier, deployment-specific layer.

Use this for a target you have not vetted; ``capture.profile_runtime``/``discovery.discover_tools``
directly (in-process, faster, no subprocess overhead) remain the right choice for one you already
trust, such as this platform's own demo target.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from purpleteam.capture import DiscoveryError
from purpleteam.discovery import AgentInfo, DiscoveredTool, TargetProfile

DEFAULT_TIMEOUT = 60.0
MAX_OUTPUT = 10_000_000  # a malicious target's unbounded stdout must not be parsed or held onto whole
# The platform's own secrets (API keys, signing material) live in this process's environment; the
# child gets only what a Python interpreter needs to start, plus whatever the caller opts in via env=.
_SAFE_ENV_KEYS = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP", "PYTHONPATH", "VIRTUAL_ENV")


def _child_env(extra: dict[str, str] | None) -> dict[str, str]:
    base = {k: v for k, v in os.environ.items() if k in _SAFE_ENV_KEYS}
    return {**base, **(extra or {})}


def discover_sandboxed(target_ref: str, *, mode: str = "runtime", timeout: float = DEFAULT_TIMEOUT,
                       env: dict[str, str] | None = None) -> TargetProfile:
    """``target_ref``: with ``mode="runtime"`` (default), a zero-arg ``"module:function"`` that returns a
    ``TargetProfile`` (the ``capture.profile_runtime`` convention, e.g. ``"purpleteam.targets.ledgerpilot:
    discover_profile"``); with ``mode="static"``, a module/package entry point to scan for tools, as
    ``discovery.discover_tools`` takes it. ``env`` opts in variables the target genuinely needs (its own
    model key, say) — never this process's own. Raises ``DiscoveryError`` on failure, a hang, or output
    too large to trust, the same way an in-process discovery failure does."""
    if mode not in ("runtime", "static"):
        raise ValueError("mode must be 'runtime' or 'static'")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "purpleteam.sandbox_worker", mode, target_ref],
            capture_output=True, timeout=timeout, env=_child_env(env), text=True)
    except subprocess.TimeoutExpired as error:
        raise DiscoveryError(f"discovery of {target_ref!r} did not finish within {timeout:.0f}s "
                             "(sandboxed)") from error
    if len(result.stdout) > MAX_OUTPUT:
        raise DiscoveryError(f"discovery of {target_ref!r} produced more output than this will trust "
                             "(sandboxed)")
    try:
        data = json.loads(result.stdout) if result.stdout.strip() else None
    except ValueError:
        data = None
    if not isinstance(data, dict) or ("profile" not in data and "error" not in data):
        detail = (result.stderr or "no readable output from the sandboxed process")[:2000]
        raise DiscoveryError(f"discovery of {target_ref!r} failed in the sandbox: {detail}")
    if "error" in data:
        raise DiscoveryError(f"discovery of {target_ref!r} failed: {data['error']}")
    return _profile_from_dict(data["profile"])


def _profile_from_dict(data: dict) -> TargetProfile:
    tools = [DiscoveredTool(**{**t, "tool": None}) for t in data["tools"]]
    agents = [AgentInfo(**{**a, "tool_names": tuple(a["tool_names"])}) for a in data["agent_info"]]
    return TargetProfile(data["name"], tools, agents)
