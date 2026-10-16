"""Is there a hardware root of trust on this machine, and what kind? Works on Windows, Linux and macOS.

The question is not only "is there a TPM", because not every platform has one. Windows and most Linux
machines carry a TPM; macOS never does (Apple's equivalent is the Secure Enclave, in every Apple-silicon Mac
and in Intel Macs with a T2 chip). So ``detect`` names what it found: ``tpm2``, ``tpm1.2``, ``tpm`` (present,
version unknown), ``secure_enclave`` or ``none``. ``present`` is three-valued: ``None`` means "could not be
determined here" (an unsupported platform, a command that failed), which is never reported as absent.

Detection is read-only and asks for no privilege: sysfs and device nodes on Linux, the Windows TPM Base
Services API (the same one every Windows program uses), and two fixed system commands on macOS (absolute
paths, no shell, short timeout, output size cap). ``reachable`` says whether this process can use it with what
is built today: a Linux TPM needs read/write on its resource-manager node (usually the ``tss`` group), a
Windows TPM is reached through TBS, and a Secure Enclave is detected but not yet usable from here.

A virtual TPM (Azure trusted launch, Google Shielded VM, AWS NitroTPM, Hyper-V) looks like a hardware one
from inside the machine; this check cannot tell them apart, and says so. WSL2 does not expose the host TPM.
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

TPM2, TPM12, TPM, SECURE_ENCLAVE, NONE = "tpm2", "tpm1.2", "tpm", "secure_enclave", "none"
_TBS_E_TPM_NOT_FOUND = 0x8028400F
_MAX_OUTPUT, _MAX_SYSFS = 200_000, 64


@dataclass(frozen=True)
class RootOfTrust:
    kind: str
    present: bool | None  # None: could not be determined on this platform, never read as "absent"
    reachable: bool       # this process can use it with what is built today
    via: str              # how it was found
    system: str           # the operating system it was asked on
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"kind": self.kind, "present": self.present, "reachable": self.reachable, "via": self.via,
                "system": self.system, "notes": list(self.notes)}


def _run(args: list[str]) -> str | None:
    """A fixed command's output, or None if it failed. Never a shell; the executable is an absolute path."""
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=15, check=False, shell=False)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return done.stdout[:_MAX_OUTPUT] if done.returncode == 0 else None


def _tbs() -> tuple[int, int] | int:
    """(TPM version, interface type) from the Windows TPM Base Services, or the TBS error code. Raises OSError off Windows."""
    class DeviceInfo(ctypes.Structure):
        _fields_ = [("structVersion", ctypes.c_uint32), ("tpmVersion", ctypes.c_uint32),
                    ("tpmInterfaceType", ctypes.c_uint32), ("tpmImpRevision", ctypes.c_uint32)]

    info = DeviceInfo(structVersion=1)
    code = ctypes.WinDLL("tbs").Tbsi_GetDeviceInfo(ctypes.sizeof(info), ctypes.byref(info)) & 0xFFFFFFFF
    return (info.tpmVersion, info.tpmInterfaceType) if code == 0 else code


@dataclass
class Probes:
    """Everything detection touches, so each platform can be tested on any machine."""

    root: Path = Path("/")
    run: Callable[[list[str]], str | None] = _run
    tbs: Callable[[], tuple[int, int] | int] = _tbs
    access: Callable[[Path], bool] = lambda path: os.access(path, os.R_OK | os.W_OK)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="ascii", errors="replace")[:_MAX_SYSFS].strip()
    except OSError:
        return None


def _linux(probes: Probes, system: str) -> RootOfTrust:
    sysfs = probes.root / "sys/class/tpm"
    try:
        devices = sorted(d for d in sysfs.iterdir() if d.name.startswith("tpm") and d.name[3:].isdigit())
    except OSError:
        devices = []
    wsl = "microsoft" in (_read(probes.root / "proc/version") or "").lower()
    if not devices:
        note = ("WSL2 does not expose the host's TPM",) if wsl else ("no TPM device in /sys/class/tpm",)
        return RootOfTrust(NONE, False, False, "sysfs", system, note)
    device = devices[0]
    major = _read(device / "tpm_version_major")
    kind = {"2": TPM2, "1": TPM12}.get(major or "", TPM)
    node = probes.root / "dev" / ("tpmrm" + device.name[3:] if kind == TPM2 else device.name)
    reachable = node.exists() and probes.access(node)
    notes = [f"{node.name} is not readable and writable by this user (the 'tss' group usually is)"] if not reachable else []
    if kind == TPM:
        notes.append("the kernel did not report the TPM version")
    return RootOfTrust(kind, True, reachable, "sysfs", system, (*notes, "a virtual TPM looks the same from inside"))


def _windows(probes: Probes, system: str) -> RootOfTrust:
    try:
        found = probes.tbs()
    except (OSError, AttributeError):
        return RootOfTrust(NONE, None, False, "tbs", system, ("the TPM Base Services library could not be loaded",))
    if isinstance(found, int):
        if found == _TBS_E_TPM_NOT_FOUND:
            return RootOfTrust(NONE, False, False, "tbs", system, ("Windows reports no TPM",))
        return RootOfTrust(NONE, None, False, "tbs", system, (f"TPM Base Services returned error 0x{found:08X}",))
    version, _ = found
    kind = {2: TPM2, 1: TPM12}.get(version, TPM)
    return RootOfTrust(kind, True, True, "tbs", system, ("a virtual TPM looks the same from inside",))


def _mac(probes: Probes, system: str) -> RootOfTrust:
    notes = ("macOS has no TPM; its hardware key store is the Secure Enclave",
             "the Secure Enclave is detected, but no signer for it is built")
    arm = probes.run(["/usr/sbin/sysctl", "-n", "hw.optional.arm64"])
    if arm is not None and arm.strip() == "1":
        return RootOfTrust(SECURE_ENCLAVE, True, False, "sysctl", system, notes)
    bridge = probes.run(["/usr/sbin/system_profiler", "SPiBridgeDataType"])
    if bridge is None:
        return RootOfTrust(NONE, None, False, "system_profiler", system, ("the hardware could not be queried",))
    if "T2" in bridge:
        return RootOfTrust(SECURE_ENCLAVE, True, False, "system_profiler", system, notes)
    return RootOfTrust(NONE, False, False, "system_profiler", system,
                       ("macOS has no TPM; this Intel Mac has no T2 chip, so no Secure Enclave either",))


def _other(probes: Probes, system: str) -> RootOfTrust:
    if (probes.root / "dev/tpm0").exists():  # the BSDs and others that expose a TPM as a device node
        return RootOfTrust(TPM, True, probes.access(probes.root / "dev/tpm0"), "dev", system,
                           ("the TPM version could not be read on this platform",))
    return RootOfTrust(NONE, None, False, "none", system, (f"no TPM check is built for {system or 'this platform'}",))


def detect(probes: Probes | None = None, system: str | None = None) -> RootOfTrust:
    """What hardware root of trust this machine has. Never raises: a failed probe is ``present=None``."""
    system = system if system is not None else platform.system()
    probes = probes or Probes()
    handlers = {"Linux": _linux, "Windows": _windows, "Darwin": _mac}
    try:
        return handlers.get(system, _other)(probes, system)
    except Exception as error:  # a probe misbehaving must not take the caller down, nor be mistaken for "absent"
        return RootOfTrust(NONE, None, False, "error", system, (f"the check failed ({type(error).__name__})",))


if __name__ == "__main__":
    import json

    print(json.dumps(detect().to_dict(), indent=2))
