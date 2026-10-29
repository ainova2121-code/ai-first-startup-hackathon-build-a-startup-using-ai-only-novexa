"""Clone a third-party multi-agent project and get it runnable, with no manual setup choices.

    uv run python scripts/clone_target.py <git-clone-url> [dir]

See ``purpleteam.targets.workspace`` for what is detected and installed. To also attack, patch and verify
it in one go, use ``uv run python -m purpleteam.assess <git-clone-url-or-path>`` instead.
"""

from __future__ import annotations

import sys
from pathlib import Path

from purpleteam.targets.workspace import clone, setup_env


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(f"Usage: uv run python {sys.argv[0]} <git-clone-url> [dir]")
    url = sys.argv[1]
    dest = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git"))
    clone(url, dest)
    setup_env(dest)
    print(f"\nReady: {dest.resolve()}")
    print("Next: uv run python -m purpleteam.assess " + str(dest.resolve()))


if __name__ == "__main__":
    main()
