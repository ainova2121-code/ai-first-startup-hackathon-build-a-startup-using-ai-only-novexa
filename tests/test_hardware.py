"""Hardware root-of-trust detection: each platform is simulated, so every OS is tested on any machine."""

import platform

import pytest

from purpleteam.audit.hardware import NONE, SECURE_ENCLAVE, TPM, TPM2, TPM12, Probes, detect


def _linux_tree(tmp_path, *, version="2", node="tpmrm0", wsl=False):
    sysfs = tmp_path / "sys/class/tpm/tpm0"
    sysfs.mkdir(parents=True)
    if version is not None:
        (sysfs / "tpm_version_major").write_text(version + "\n")
    (tmp_path / "dev").mkdir()
    if node:
        (tmp_path / "dev" / node).write_text("")
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/version").write_text("Linux version 5.15 microsoft-standard-WSL2" if wsl else "Linux version 6.1")
    return Probes(root=tmp_path, access=lambda path: True)


def test_a_linux_tpm2_is_found_and_reachable_through_its_resource_manager(tmp_path):
    found = detect(_linux_tree(tmp_path), "Linux")
    assert (found.kind, found.present, found.reachable, found.via) == (TPM2, True, True, "sysfs")


def test_a_linux_tpm12_uses_the_plain_device_node(tmp_path):
    found = detect(_linux_tree(tmp_path, version="1", node="tpm0"), "Linux")
    assert (found.kind, found.present, found.reachable) == (TPM12, True, True)


def test_a_linux_tpm_the_user_cannot_open_is_present_but_not_reachable(tmp_path):
    probes = _linux_tree(tmp_path)
    probes.access = lambda path: False
    found = detect(probes, "Linux")
    assert (found.present, found.reachable) == (True, False) and "tss" in " ".join(found.notes)


def test_a_linux_tpm_with_no_device_node_is_not_reachable(tmp_path):
    assert not detect(_linux_tree(tmp_path, node=None), "Linux").reachable


def test_an_unreported_or_garbage_version_is_never_guessed(tmp_path):
    for version in (None, "9", "two", "\x00\xff", "2" * 5000):
        found = detect(_linux_tree(tmp_path / str(hash(str(version))), version=version), "Linux")
        assert found.present is True and found.kind in (TPM, TPM2), version
    assert detect(_linux_tree(tmp_path / "none", version=None), "Linux").kind == TPM


def test_linux_without_a_tpm_says_so_and_wsl_explains_why(tmp_path):
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/version").write_text("Linux version 6.1")
    bare = detect(Probes(root=tmp_path), "Linux")
    assert (bare.kind, bare.present) == (NONE, False)
    (tmp_path / "proc/version").write_text("Linux version 5.15 microsoft-standard-WSL2")
    assert "WSL2" in " ".join(detect(Probes(root=tmp_path), "Linux").notes)


def test_windows_reports_the_tpm_version_from_tbs():
    for version, kind in ((2, TPM2), (1, TPM12), (7, TPM)):
        found = detect(Probes(tbs=lambda v=version: (v, 6)), "Windows")
        assert (found.kind, found.present, found.reachable, found.via) == (kind, True, True, "tbs")


def test_windows_distinguishes_no_tpm_from_not_knowing():
    none = detect(Probes(tbs=lambda: 0x8028400F), "Windows")
    assert (none.kind, none.present) == (NONE, False)
    unknown = detect(Probes(tbs=lambda: 0x80284001), "Windows")
    assert (unknown.kind, unknown.present) == (NONE, None) and "0x80284001" in unknown.notes[0]

    def missing():
        raise OSError("tbs.dll not found")

    assert detect(Probes(tbs=missing), "Windows").present is None


def test_apple_silicon_has_a_secure_enclave_and_never_a_tpm():
    found = detect(Probes(run=lambda args: "1\n" if "hw.optional.arm64" in args else None), "Darwin")
    assert (found.kind, found.present, found.reachable) == (SECURE_ENCLAVE, True, False)
    assert "no TPM" in found.notes[0] and "no signer" in found.notes[1]


def test_an_intel_mac_has_one_only_with_a_t2_chip():
    def run(args):
        if "hw.optional.arm64" in args:
            return "0\n"
        return "Apple T2 Security Chip\n  Model Name: Apple T2" if "SPiBridgeDataType" in args else None

    assert detect(Probes(run=run), "Darwin").kind == SECURE_ENCLAVE
    bare = detect(Probes(run=lambda args: "0\n" if "hw.optional.arm64" in args else "No information found\n"), "Darwin")
    assert (bare.kind, bare.present) == (NONE, False) and "no T2" in bare.notes[0]


def test_a_mac_whose_hardware_cannot_be_queried_is_unknown_not_absent():
    found = detect(Probes(run=lambda args: None), "Darwin")
    assert (found.kind, found.present) == (NONE, None)


def test_other_platforms_are_reported_honestly(tmp_path):
    found = detect(Probes(root=tmp_path), "FreeBSD")
    assert (found.present, found.reachable) == (None, False) and "FreeBSD" in found.notes[0]
    (tmp_path / "dev").mkdir()
    (tmp_path / "dev/tpm0").write_text("")
    bsd = detect(Probes(root=tmp_path, access=lambda p: True), "FreeBSD")
    assert (bsd.kind, bsd.present, bsd.reachable) == (TPM, True, True)


def test_detection_never_raises_and_a_failure_is_not_read_as_absent():
    def boom(*args):
        raise RuntimeError("probe exploded")

    for system in ("Linux", "Windows", "Darwin", "Plan9"):
        found = detect(Probes(root=None, run=boom, tbs=boom, access=boom), system)
        assert found.present is None or found.present is False
    assert detect(Probes(tbs=boom), "Windows").present is None


def test_the_real_host_can_always_be_asked():
    found = detect()
    assert found.system == platform.system() and found.kind in (TPM2, TPM12, TPM, SECURE_ENCLAVE, NONE)
    assert found.present in (True, False, None) and set(found.to_dict()) == {
        "kind", "present", "reachable", "via", "system", "notes"}


@pytest.mark.parametrize("hostile", ["x" * 300_000, "\x00" * 10, "1\n" * 100_000], ids=["huge", "nulls", "many-lines"])
def test_hostile_command_output_is_handled(hostile):
    assert detect(Probes(run=lambda args: hostile), "Darwin").kind in (SECURE_ENCLAVE, NONE)
