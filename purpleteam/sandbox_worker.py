"""Entry point for the discovery sandbox's child process (see ``purpleteam.sandbox``).

Never imported — run only via ``python -m purpleteam.sandbox_worker <runtime|static> <target-ref>``.
Everything that crosses back to the parent goes through one line of JSON on stdout; the target's
own output (banners, warnings, anything it prints while being imported or built) is captured and
discarded, so it can never corrupt that one line.
"""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from dataclasses import asdict

from purpleteam.discovery import TargetProfile, discover_tools, load_callable


def _tool_dict(tool) -> dict:
    data = asdict(tool)
    data.pop("tool", None)  # the live tool object: never serializable, never needed by the parent
    return data


def _profile_dict(profile: TargetProfile) -> dict:
    return {"name": profile.name, "tools": [_tool_dict(t) for t in profile.tools],
           "agent_info": [asdict(a) for a in profile.agent_info]}


def _discover(mode: str, target_ref: str) -> dict:
    with redirect_stdout(io.StringIO()):  # the target's own prints must never land on our stdout
        if mode == "runtime":
            profile = load_callable(target_ref)()
            if not isinstance(profile, TargetProfile):
                raise TypeError(f"{target_ref} did not return a TargetProfile")
        else:
            profile = TargetProfile(target_ref.split(":")[0].split(".")[0], discover_tools(target_ref))
    return _profile_dict(profile)


def _main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in ("runtime", "static"):
        print(json.dumps({"error": "usage: python -m purpleteam.sandbox_worker <runtime|static> <target-ref>"}))
        raise SystemExit(2)
    try:
        print(json.dumps({"profile": _discover(sys.argv[1], sys.argv[2])}))
    except Exception as error:
        print(json.dumps({"error": f"{type(error).__name__}: {error}"}))
        raise SystemExit(1)


if __name__ == "__main__":
    _main()
