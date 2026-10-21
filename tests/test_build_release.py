"""The release build pipeline: stage, compile, strip source, archive and sign — with translate/
build injected so this is tested without Cython or a C toolchain, and the orchestration logic
(what gets stripped, what fails loud, what never ships partially) is what's actually proven here."""

import importlib.util
import json
import tarfile
from pathlib import Path

import pytest

from purpleteam.audit.keys import AgentKeyring
from purpleteam.provenance import verify_release

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_release.py"


def _load():
    spec = importlib.util.spec_from_file_location("build_release", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CORE = ["purpleteam/a.py", "purpleteam/sub/b.py"]


def _src(tmp_path: Path) -> Path:
    src = tmp_path / "purpleteam"
    (src / "sub").mkdir(parents=True)
    (src / "a.py").write_text("A = 1\n", encoding="utf-8")
    (src / "sub" / "b.py").write_text("B = 2\n", encoding="utf-8")
    (src / "integration.py").write_text("INTEGRATION = 3\n", encoding="utf-8")  # never compiled
    return src


def _fake_translate(root: Path) -> list[str]:
    return []


def _fake_build_ok(root: Path) -> None:
    for module in CORE:
        (root / module).with_suffix(".so").write_bytes(b"FAKE-COMPILED-EXTENSION")


def _fake_build_leaves_one_uncompiled(root: Path) -> None:
    (root / CORE[0]).with_suffix(".so").write_bytes(b"FAKE-COMPILED-EXTENSION")
    # CORE[1] never gets a compiled extension


def _fake_build_real_platform_tag(root: Path) -> None:
    """What a real Cython/setuptools build actually names its output — never a bare ``module.so``,
    always with the interpreter's platform/ABI tag. The bug this guards against: a detection check
    that only ever matched the bare form a hand-written fake wrote, never real build output."""
    for module in CORE:
        source = root / module
        source.with_name(f"{source.stem}.cpython-312-x86_64-linux-gnu.so").write_bytes(b"FAKE-COMPILED-EXTENSION")


def test_stage_strips_only_the_core_modules_and_keeps_the_rest(tmp_path):
    br = _load()
    src = _src(tmp_path)
    dest = tmp_path / "dest"

    package = br.stage(src, dest, translate=_fake_translate, build=_fake_build_ok, core_modules=CORE)

    assert not (package / "a.py").exists() and (package / "a.so").exists()
    assert not (package / "sub" / "b.py").exists() and (package / "sub" / "b.so").exists()
    assert (package / "integration.py").exists()  # never a core module, never touched


def test_stage_recognizes_a_real_platform_tagged_extension_not_only_a_bare_so(tmp_path):
    br = _load()
    src = _src(tmp_path)
    dest = tmp_path / "dest"

    package = br.stage(src, dest, translate=_fake_translate, build=_fake_build_real_platform_tag, core_modules=CORE)

    assert not (package / "a.py").exists()
    assert (package / "a.cpython-312-x86_64-linux-gnu.so").exists()
    assert not (package / "sub" / "b.py").exists()
    assert (package / "sub" / "b.cpython-312-x86_64-linux-gnu.so").exists()


def test_stage_fails_loud_when_a_core_module_was_not_compiled(tmp_path):
    br = _load()
    src = _src(tmp_path)
    dest = tmp_path / "dest"

    with pytest.raises(br.ReleaseBuildFailed, match="sub/b.py"):
        br.stage(src, dest, translate=_fake_translate, build=_fake_build_leaves_one_uncompiled, core_modules=CORE)


def test_stage_fails_loud_when_translation_itself_fails(tmp_path):
    br = _load()
    src = _src(tmp_path)
    dest = tmp_path / "dest"

    def failing_translate(root: Path) -> list[str]:
        return ["purpleteam/a.py: syntax error"]

    with pytest.raises(br.ReleaseBuildFailed, match="translation failed"):
        br.stage(src, dest, translate=failing_translate, build=_fake_build_ok, core_modules=CORE)


def test_make_archive_is_deterministic_across_two_builds(tmp_path):
    br = _load()
    src = _src(tmp_path)
    staged = tmp_path / "staged" / "purpleteam"
    import shutil
    shutil.copytree(src, staged)

    first = br.make_archive(staged, tmp_path / "first.tar.gz")
    second = br.make_archive(staged, tmp_path / "second.tar.gz")

    assert first.read_bytes() == second.read_bytes()


def test_build_release_produces_a_signed_statement_that_verifies(tmp_path):
    br = _load()
    src = _src(tmp_path)
    out_dir = tmp_path / "dist"
    keyring = AgentKeyring()

    statement = br.build_release(src, out_dir, "1.2.3", "a" * 40, keyring,
                                 translate=_fake_translate, build=_fake_build_ok, core_modules=CORE)

    archive_path = out_dir / "purpleteam-1.2.3.tar.gz"
    assert archive_path.exists()
    result = verify_release(statement, keyring.public_keys(), artifact_path=archive_path)
    assert result.ok and result.version == "1.2.3" and result.revision == "a" * 40

    saved = json.loads((out_dir / "purpleteam-1.2.3.tar.gz.release.json").read_text(encoding="utf-8"))
    assert saved["statement"] == statement
    assert not (out_dir / "_staging").exists()  # staging is cleaned up, never shipped


def test_build_release_archive_holds_only_compiled_and_plain_source_no_c_files(tmp_path):
    br = _load()
    src = _src(tmp_path)
    out_dir = tmp_path / "dist"
    keyring = AgentKeyring()

    br.build_release(src, out_dir, "1.0.0", "b" * 40, keyring,
                     translate=_fake_translate, build=_fake_build_ok, core_modules=CORE)

    with tarfile.open(out_dir / "purpleteam-1.0.0.tar.gz") as tar:
        names = set(tar.getnames())
    assert names == {"purpleteam/a.so", "purpleteam/sub/b.so", "purpleteam/integration.py"}


def test_build_release_leaves_nothing_in_out_dir_when_the_build_fails(tmp_path):
    br = _load()
    src = _src(tmp_path)
    out_dir = tmp_path / "dist"
    keyring = AgentKeyring()

    with pytest.raises(br.ReleaseBuildFailed):
        br.build_release(src, out_dir, "1.0.0", "c" * 40, keyring,
                         translate=_fake_translate, build=_fake_build_leaves_one_uncompiled, core_modules=CORE)

    assert list(out_dir.iterdir()) == []  # no half-finished archive, no leftover staging dir


def test_build_release_leaves_no_unsigned_archive_when_signing_itself_fails(tmp_path):
    """The real bug this fixes: compiling and archiving can succeed and signing can still fail
    (a bad revision string, a broken keyring) — the archive must not survive that as if it were
    a completed, signed release."""
    br = _load()
    src = _src(tmp_path)
    out_dir = tmp_path / "dist"
    keyring = AgentKeyring()

    with pytest.raises(ValueError):  # provenance.sign_release rejects a revision with a space
        br.build_release(src, out_dir, "1.0.0", "not a valid revision", keyring,
                         translate=_fake_translate, build=_fake_build_ok, core_modules=CORE)

    assert list(out_dir.iterdir()) == []  # the archive that was successfully built is not left behind


def test_main_stage_flag_calls_stage_with_the_given_paths(tmp_path, monkeypatch):
    """What the gateway Dockerfile actually invokes: --stage <src> <dest>, no signing involved."""
    br = _load()
    calls = []
    monkeypatch.setattr(br, "stage", lambda src, dest: calls.append((src, dest)))
    monkeypatch.setattr(br.sys, "argv", ["build_release.py", "--stage", "purpleteam", "/compiled"])

    br._main()

    assert calls == [(Path("purpleteam"), Path("/compiled"))]


def test_main_stage_flag_needs_exactly_two_paths(monkeypatch):
    br = _load()
    monkeypatch.setattr(br.sys, "argv", ["build_release.py", "--stage", "only-one-arg"])
    with pytest.raises(SystemExit):
        br._main()


def test_a_tampered_archive_fails_verification(tmp_path):
    br = _load()
    src = _src(tmp_path)
    out_dir = tmp_path / "dist"
    keyring = AgentKeyring()

    statement = br.build_release(src, out_dir, "1.0.0", "d" * 40, keyring,
                                 translate=_fake_translate, build=_fake_build_ok, core_modules=CORE)
    archive_path = out_dir / "purpleteam-1.0.0.tar.gz"
    archive_path.write_bytes(archive_path.read_bytes() + b"tampered")

    result = verify_release(statement, keyring.public_keys(), artifact_path=archive_path)
    assert result.ok is False
