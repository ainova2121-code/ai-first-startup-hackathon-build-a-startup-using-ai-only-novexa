"""Compile the platform's crown-jewel modules to native extensions with Cython, so a BYOC
distribution ships compiled binaries for this logic rather than readable ``.py`` source.

Pure-Python mode: these are ordinary ``.py`` files, not rewritten ``.pyx`` — Cython compiles
them as-is. Nothing here changes behaviour; it only changes what a customer's filesystem holds.

Two steps, run separately because only the second needs a C toolchain:
  1. ``--translate`` (always available): Cython's front end turns each module into a ``.c`` file
     and fails loudly on anything it cannot translate. No compiler needed, so this runs anywhere,
     including this repo's own CI, as a fast correctness check on every change to a core module.
  2. ``--build`` (needs a C compiler: MSVC on Windows, gcc/clang on Linux/macOS): actually compiles
     the ``.c`` files into ``.pyd``/``.so`` extensions importable in place of the ``.py`` source.

A real release then ships the compiled extensions and drops the ``.py`` files for these modules
from the distributed artifact (see ``purpleteam/provenance.py`` for signing what does ship).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The modules that carry real proprietary logic (detection, scoring, patch selection, the signed
# audit trail). Integration surfaces a customer extends per target (discovery, adapters, target
# connectors, the LLM gateway) are deliberately left out: those must stay plain, readable Python.
CORE_MODULES = [
    "purpleteam/oracle.py",
    "purpleteam/defender/selector.py",
    "purpleteam/patches/catalog.py",
    "purpleteam/patches/rules.py",
    "purpleteam/attack/outcome.py",
    "purpleteam/attack/corpus.py",
    "purpleteam/attack/engine.py",
    "purpleteam/audit/hashing.py",
    "purpleteam/audit/keys.py",
    "purpleteam/audit/verify.py",
    "purpleteam/audit/ledger.py",
    "purpleteam/audit/compliance.py",
    "purpleteam/audit/report.py",
    "purpleteam/audit/trend.py",
    "purpleteam/licensing.py",
    "purpleteam/provenance.py",
]


def translate() -> list[str]:
    """Cython's front end only; returns the modules that failed to translate (empty = all clean)."""
    from Cython.Build import cythonize

    sources = [str(ROOT / module) for module in CORE_MODULES]
    failed = []
    for module, source in zip(CORE_MODULES, sources):
        try:
            cythonize([source], compiler_directives={"language_level": "3"}, quiet=True)
        except Exception as error:
            failed.append(f"{module}: {error}")
    return failed


def build() -> None:
    """Compile the translated ``.c`` files into importable extensions. Needs a C toolchain."""
    from Cython.Build import cythonize
    from setuptools import Extension
    from setuptools.dist import Distribution

    extensions = [Extension(module.removesuffix(".py").replace("/", "."), [str(ROOT / module)])
                 for module in CORE_MODULES]
    dist = Distribution({"ext_modules": cythonize(extensions, compiler_directives={"language_level": "3"})})
    dist.script_args = ["build_ext", "--inplace"]
    dist.parse_command_line()
    dist.run_commands()


def _main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "--translate"
    if mode == "--translate":
        failed = translate()
        if failed:
            print(f"{len(CORE_MODULES) - len(failed)}/{len(CORE_MODULES)} modules translated cleanly; failed:")
            for line in failed:
                print(f"  {line}")
            raise SystemExit(1)
        print(f"all {len(CORE_MODULES)} core modules translate cleanly (no C compiler needed for this check)")
    elif mode == "--build":
        build()
    else:
        print("usage: python scripts/compile_core.py [--translate|--build]")
        raise SystemExit(2)


if __name__ == "__main__":
    _main()
