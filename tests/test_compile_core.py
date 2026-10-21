"""compile_core.translate(root=...) reads from, and writes into, the given root rather than
always this repo's own tree — what a release build needs to compile a staged copy instead."""

import importlib.util
import shutil
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "compile_core.py"


def _load():
    spec = importlib.util.spec_from_file_location("compile_core", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stage(compile_core, dest: Path) -> None:
    shutil.copytree(compile_core.ROOT / "purpleteam", dest / "purpleteam")


def test_translate_reads_from_the_given_root_not_the_real_repo(tmp_path):
    compile_core = _load()
    staged = tmp_path / "staged"
    _stage(compile_core, staged)

    failed = compile_core.translate(root=staged)

    assert failed == []
    for module in compile_core.CORE_MODULES:
        assert (staged / module).with_suffix(".c").exists()
        assert not (compile_core.ROOT / module).with_suffix(".c").exists()  # the real repo untouched


def test_translate_reports_a_module_that_does_not_parse(tmp_path):
    compile_core = _load()
    staged = tmp_path / "staged"
    _stage(compile_core, staged)
    broken = staged / compile_core.CORE_MODULES[0]
    broken.write_text("def broken(:\n", encoding="utf-8")

    failed = compile_core.translate(root=staged)

    assert len(failed) == 1 and compile_core.CORE_MODULES[0] in failed[0]


def test_translate_with_no_root_argument_defaults_to_this_repo():
    compile_core = _load()
    failed = compile_core.translate()  # no root=: must fall back to compile_core.ROOT
    assert failed == []
    for module in compile_core.CORE_MODULES:
        generated = (compile_core.ROOT / module).with_suffix(".c")
        assert generated.exists()
        generated.unlink()  # clean up: this ran against the real repo on purpose
