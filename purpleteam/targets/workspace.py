"""Get a third-party project runnable with no manual setup choices: clone it (or reuse a local copy)
and set up its own environment the way the project itself asks.

An existing ``.venv`` is reused as is; ``pyproject.toml`` is installed with ``uv sync`` (falling back
to ``python -m venv`` + ``pip install -e .`` if ``uv`` is not on PATH); ``requirements.txt`` is
installed into a fresh ``.venv`` with pip. Neither file present leaves the clone as is -- nothing is
invented to install. The project's own code is never edited here: only a ``.venv`` is created inside it.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path


_SHORT_ROOT = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "pt-envs"
_LONG_PATH = 60  # characters; a deep project plus a package's own nested files then passes Windows' 260 limit


def _run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    print(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True, **({"env": env} if env else {}))


def env_dir(repo: Path) -> Path:
    """Where the project's environment lives: its own ``.venv``, unless that does not exist yet and the project
    sits so deep that a package inside it would pass Windows' 260-character path limit (a compiled module then
    fails to load with "the filename is too long"). Then it goes in a short folder of its own instead."""
    venv = repo / ".venv"
    if venv.exists() or sys.platform != "win32" or len(str(repo.resolve())) <= _LONG_PATH:
        return venv
    digest = hashlib.sha256(str(repo.resolve()).encode("utf-8")).hexdigest()[:8]
    return _SHORT_ROOT / f"{repo.name[:24]}-{digest}"


def clone(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"'{dest}' already exists -- reusing it, not re-cloning.")
        return
    try:
        _run(["git", "clone", url, str(dest)], cwd=dest.parent)
    except subprocess.CalledProcessError:
        if sys.platform != "win32" or not dest.exists():
            raise
        # Git's default checkout on Windows refuses a path over MAX_PATH (260 chars) -- common in
        # repos with deeply nested example folders, unrelated to anything this module controls.
        # The clone itself (the object database) still succeeded; only the working-tree checkout
        # failed, so re-running the checkout with long paths enabled finishes the same clone.
        print("Checkout hit Windows' MAX_PATH limit on a deeply nested file -- retrying with "
              "core.longpaths enabled for this clone.")
        _run(["git", "-c", "core.longpaths=true", "checkout", "HEAD", "--", "."], cwd=dest)


def setup_env(repo: Path) -> None:
    venv = env_dir(repo)
    if venv.exists():
        print(f"Found an existing environment at {venv} -- reusing it.")
        return
    pyproject, requirements = repo / "pyproject.toml", repo / "requirements.txt"
    if pyproject.exists():
        if shutil.which("uv"):
            print("pyproject.toml found -- installing with `uv sync`.")
            env = None
            if venv != repo / ".venv":  # uv's own way to put a project's environment elsewhere
                env = {k: v for k, v in os.environ.items() if k != "VIRTUAL_ENV"} | {"UV_PROJECT_ENVIRONMENT": str(venv)}
            _run(["uv", "sync"], cwd=repo, env=env)
        else:
            print("pyproject.toml found but `uv` is not on PATH -- falling back to "
                  "`python -m venv` + `pip install -e .`.")
            _run([sys.executable, "-m", "venv", str(venv)], cwd=repo)
            _run([str(_venv_bin(venv, "pip")), "install", "-e", "."], cwd=repo)
    elif requirements.exists():
        print("requirements.txt found -- creating .venv and installing with pip.")
        _run([sys.executable, "-m", "venv", str(venv)], cwd=repo)
        _run([str(_venv_bin(venv, "pip")), "install", "-r", "requirements.txt"], cwd=repo)
    else:
        print("No pyproject.toml or requirements.txt found -- nothing to install automatically. "
              "Check the project's own README for its setup steps.")


def python_for(repo: Path) -> Path:
    """The project's own interpreter: its environment's if there is one, else this one (a project with no
    environment of its own runs on whatever is installed here)."""
    candidate = _venv_bin(env_dir(repo), "python")
    return candidate if candidate.exists() else Path(sys.executable)


def prepare(source: str, workdir: Path) -> Path:
    """A local project path as is, or a git URL cloned under ``workdir``; then its environment set up."""
    local = Path(source)
    if local.is_dir():
        repo = local.resolve()
    else:
        workdir.mkdir(parents=True, exist_ok=True)
        repo = workdir / source.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        clone(source, repo)
    setup_env(repo)
    return repo


def _venv_bin(venv: Path, name: str) -> Path:
    return venv / ("Scripts" if sys.platform == "win32" else "bin") / (f"{name}.exe" if sys.platform == "win32" else name)
