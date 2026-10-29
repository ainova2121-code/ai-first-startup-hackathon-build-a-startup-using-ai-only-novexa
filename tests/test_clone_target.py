"""Workspace setup: clone a third-party repo and set it up automatically -- no network, no real
git or pip calls (every subprocess is faked), so this proves the decision logic only: what gets
run, in what order, and that an existing clone or venv is never clobbered."""

import sys
from pathlib import Path

import pytest

from purpleteam.targets import workspace


@pytest.fixture
def module(monkeypatch):
    mod = workspace
    calls = []

    def fake_run(cmd, cwd, check, env=None):
        calls.append((cmd, str(cwd)))
        mod._env = env
        if cmd[:2] == ["git", "clone"]:
            Path(cwd, cmd[-1]).mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod, "_LONG_PATH", 10_000)  # pytest's own temp folders are deep; tested on its own below
    mod._calls = calls  # stashed on the module so tests can read it back
    return mod


def test_an_existing_clone_is_reused_not_recloned(module, tmp_path):
    dest = tmp_path / "already-here"
    dest.mkdir()
    module.clone("https://example.com/x.git", dest)
    assert module._calls == []  # git clone never ran


def test_a_fresh_url_is_cloned(module, tmp_path):
    dest = tmp_path / "fresh"
    module.clone("https://example.com/x.git", dest)
    assert module._calls == [(["git", "clone", "https://example.com/x.git", str(dest)], str(tmp_path))]


def test_an_existing_venv_is_reused_and_nothing_else_runs(module, tmp_path, capsys):
    repo = tmp_path / "repo"
    (repo / ".venv").mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\nname='x'\n")
    module.setup_env(repo)
    assert module._calls == []
    assert "reusing it" in capsys.readouterr().out


def test_pyproject_with_uv_on_path_runs_uv_sync(module, tmp_path, monkeypatch):
    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/uv" if name == "uv" else None)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname='x'\n")
    module.setup_env(repo)
    assert module._calls == [(["uv", "sync"], str(repo))]


def test_pyproject_without_uv_falls_back_to_venv_and_pip_install_e(module, tmp_path, monkeypatch):
    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname='x'\n")
    module.setup_env(repo)
    cmds = [c for c, _ in module._calls]
    assert cmds[0] == [sys.executable, "-m", "venv", str(repo / ".venv")]
    assert cmds[1][1:] == ["install", "-e", "."]


def test_requirements_txt_creates_a_venv_and_pip_installs_it(module, tmp_path, monkeypatch):
    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/uv")  # irrelevant without pyproject.toml
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests\n")
    module.setup_env(repo)
    cmds = [c for c, _ in module._calls]
    assert cmds[0] == [sys.executable, "-m", "venv", str(repo / ".venv")]
    assert cmds[1][1:] == ["install", "-r", "requirements.txt"]


def test_neither_file_present_installs_nothing(module, tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    module.setup_env(repo)
    assert module._calls == []
    assert "nothing to install automatically" in capsys.readouterr().out


def test_windows_long_path_checkout_failure_is_retried_with_longpaths(module, tmp_path, monkeypatch):
    monkeypatch.setattr(module.sys, "platform", "win32")
    dest = tmp_path / "repo"

    def flaky_run(cmd, cwd, check):
        module._calls.append((cmd, str(cwd)))
        if cmd[:2] == ["git", "clone"]:
            dest.mkdir(parents=True, exist_ok=True)  # the object database still landed
            raise module.subprocess.CalledProcessError(128, cmd)

    monkeypatch.setattr(module.subprocess, "run", flaky_run)
    module.clone("https://example.com/x.git", dest)
    assert module._calls[-1][0] == ["git", "-c", "core.longpaths=true", "checkout", "HEAD", "--", "."]


def test_a_non_windows_clone_failure_is_not_swallowed(module, tmp_path, monkeypatch):
    monkeypatch.setattr(module.sys, "platform", "linux")

    def broken_run(cmd, cwd, check):
        raise module.subprocess.CalledProcessError(128, cmd)

    monkeypatch.setattr(module.subprocess, "run", broken_run)
    with pytest.raises(module.subprocess.CalledProcessError):
        module.clone("https://example.com/x.git", tmp_path / "repo")


def test_a_deep_project_on_windows_gets_its_environment_in_a_short_folder(module, tmp_path, monkeypatch):
    """Found on a real project: a deep .venv put a compiled module past Windows' 260-character limit."""
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(module, "_LONG_PATH", 5)
    monkeypatch.setattr(module, "_SHORT_ROOT", tmp_path / "envs")
    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/uv")
    repo = tmp_path / "deep" / "repo"
    repo.mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\nname='x'\n")
    module.setup_env(repo)

    short = module.env_dir(repo)
    assert short.parent == tmp_path / "envs" and short.name.startswith("repo-")
    assert module._env["UV_PROJECT_ENVIRONMENT"] == str(short) and "VIRTUAL_ENV" not in module._env
    assert module.env_dir(repo) == short  # the same folder every time, so it is reused
