"""Build a signed, source-minimized release artifact: the crown-jewel modules (see
``compile_core.py``) compiled to native extensions with their ``.py`` source removed, everything
else shipped as plain source, archived and signed with the vendor's keyring.

This raises the cost of casual copying; it does not make the logic secret. Compiled bytecode on a
machine the recipient fully controls is not a secret, only slower to read — see
``purpleteam/audit/hardware_signer.py``'s module docstring for the same caveat about hardware
signing, and ``purpleteam/provenance.py``'s, for the same one about signing in general.
"""

from __future__ import annotations

import gzip
import json
import shutil
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compile_core  # noqa: E402 — the sibling script; scripts/ is not a package

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from purpleteam.audit.keys import AgentKeyring  # noqa: E402
from purpleteam.provenance import digest_file, sign_release  # noqa: E402

_COMPILED_SUFFIXES = (".so", ".pyd")


class ReleaseBuildFailed(Exception):
    """A core module did not actually produce a compiled extension, or signing could not proceed.
    Never shipped as a partial or best-effort release — fixed and rebuilt from scratch instead."""


def _compiled_extension(source: Path) -> Path | None:
    """The compiled extension for ``source`` (``module.py``), bare (``module.so``) or carrying the
    platform/ABI tag a real Cython/setuptools build actually names it with (``module.cpython-312-
    x86_64-linux-gnu.so``, ``module.cp312-win_amd64.pyd``) — a bare-suffix check alone never matches
    real build output, only a hand-written test fake."""
    for suffix in _COMPILED_SUFFIXES:
        bare = source.with_suffix(suffix)
        if bare.exists():
            return bare
        tagged = sorted(source.parent.glob(f"{source.stem}.*{suffix}"))
        if tagged:
            return tagged[0]
    return None


def _strip_compiled_sources(root: Path, core_modules: list[str]) -> None:
    """Delete each core module's ``.py`` only once its compiled extension is confirmed present —
    a module that silently produced nothing must keep its source, not lose it and ship nothing."""
    for module in core_modules:
        source = root / module
        if _compiled_extension(source) is None:
            raise ReleaseBuildFailed(f"{module} did not produce a compiled extension (.so/.pyd); "
                                     "refusing to ship a release with this module's source instead")
        source.unlink()
        source.with_suffix(".c").unlink(missing_ok=True)


def stage(src: Path, dest: Path, *, translate=compile_core.translate, build=compile_core.build,
         core_modules: list[str] = compile_core.CORE_MODULES) -> Path:
    """Copy ``src`` (a ``purpleteam`` package directory) into ``dest``, compile its core modules in
    place, and strip their ``.py`` source. ``translate``/``build`` are injected so this is testable
    without Cython or a C toolchain. Returns the staged package directory."""
    package = dest / "purpleteam"
    shutil.copytree(src, package)
    failed = translate(root=dest)
    if failed:
        raise ReleaseBuildFailed("translation failed for: " + "; ".join(failed))
    build(root=dest)
    _strip_compiled_sources(dest, core_modules)  # core_modules are "purpleteam/...", relative to dest
    return package


def make_archive(staged: Path, dest: Path) -> Path:
    """A deterministic ``tar.gz`` of the staged package (sorted entries, zeroed timestamps and
    ownership) — the same input always produces the same bytes, so the digest that gets signed is
    independently reproducible by anyone who builds the same source the same way. The gzip wrapper
    is opened directly with ``mtime=0`` and an empty embedded filename: ``tarfile.open(...,
    "w:gz")`` does not forward ``mtime`` on every Python version, and gzip otherwise embeds
    ``dest``'s own basename in its header — either one alone would make two builds of the exact
    same source produce different bytes, purely from being written to different destination
    paths, which would make the signed digest nothing anyone else could reproduce and check."""
    with open(dest, "wb") as raw, \
         gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz, \
         tarfile.open(fileobj=gz, mode="w") as tar:
        for path in sorted(staged.rglob("*")):
            if not path.is_file():
                continue
            info = tar.gettarinfo(str(path), arcname=str(path.relative_to(staged.parent)))
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
            with path.open("rb") as handle:
                tar.addfile(info, handle)
    return dest


def build_release(src: Path, out_dir: Path, version: str, revision: str, keyring: AgentKeyring, *,
                  translate=compile_core.translate, build=compile_core.build,
                  core_modules: list[str] = compile_core.CORE_MODULES) -> dict:
    """Stage, compile, strip, archive and sign — the whole pipeline, transactionally: writes the
    archive and its signed statement under ``out_dir`` only once every step, signing included,
    has succeeded. If anything fails — compiling, archiving, or signing itself — nothing is left
    under ``out_dir`` that could be mistaken for a completed release; a half-built, unsigned
    archive is exactly what a failed build must never leave behind."""
    out_dir.mkdir(parents=True, exist_ok=True)
    staging = out_dir / "_staging"
    if staging.exists():
        shutil.rmtree(staging)
    artifact_name = f"purpleteam-{version}.tar.gz"
    archive_path = out_dir / artifact_name
    sidecar_path = out_dir / f"{artifact_name}.release.json"
    try:
        package = stage(src, staging, translate=translate, build=build, core_modules=core_modules)
        make_archive(package, archive_path)
        statement = sign_release(keyring, artifact_name, version, revision, digest_file(archive_path))
        sidecar_path.write_text(
            json.dumps({"statement": statement, "public_keys": keyring.public_keys()["vendor"]}, indent=2),
            encoding="utf-8")
    except Exception:
        archive_path.unlink(missing_ok=True)
        sidecar_path.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return statement


def _main() -> None:
    """``uv run python scripts/build_release.py <version> <revision> [out_dir]`` for a full signed
    release, or ``... --stage <src> <dest>`` to only compile and strip source into ``dest`` (no
    archive, no signing) — what the gateway Dockerfile uses to ship compiled modules. Signs with a
    persisted vendor keyring: set ``RELEASE_KEYRING_DIR`` and ``RELEASE_KEYRING_PASSPHRASE`` (or
    ``RELEASE_KEYRING_PASSPHRASE_FILE``) — never an ephemeral one for a real release."""
    import os

    if sys.argv[1:2] == ["--stage"]:
        if len(sys.argv) != 4:
            print("usage: python scripts/build_release.py --stage <src> <dest>")
            raise SystemExit(2)
        stage(Path(sys.argv[2]), Path(sys.argv[3]))
        return
    if len(sys.argv) not in (3, 4):
        print("usage: python scripts/build_release.py <version> <revision> [out_dir]")
        raise SystemExit(2)
    version, revision = sys.argv[1], sys.argv[2]
    out_dir = Path(sys.argv[3]) if len(sys.argv) == 4 else Path("dist")
    directory = os.environ.get("RELEASE_KEYRING_DIR")
    if not directory:
        raise ReleaseBuildFailed("RELEASE_KEYRING_DIR is not set — refusing to sign a release with "
                                 "an ephemeral, in-memory key")
    passphrase_file = os.environ.get("RELEASE_KEYRING_PASSPHRASE_FILE")
    passphrase = (Path(passphrase_file).read_bytes().strip() if passphrase_file
                 else os.environ.get("RELEASE_KEYRING_PASSPHRASE", "").encode("utf-8"))
    if not passphrase:
        raise ReleaseBuildFailed("set RELEASE_KEYRING_PASSPHRASE_FILE or RELEASE_KEYRING_PASSPHRASE")
    keyring = AgentKeyring(directory, passphrase)
    src = Path(__file__).resolve().parents[1] / "purpleteam"
    statement = build_release(src, out_dir, version, revision, keyring)
    print(json.dumps(statement, indent=2))


if __name__ == "__main__":
    _main()
