"""The Windows TPM signer: input is validated before any ctypes call, and a crypto library that
cannot even load is reported as unavailable (soft, under "preferred") rather than crashing startup."""

import sys

import pytest

from purpleteam.audit.hardware_signer import SignerUnavailable

needs_windows = pytest.mark.skipif(sys.platform != "win32", reason="ncrypt.dll only exists on Windows")


def test_a_bad_key_name_is_refused_before_touching_any_dll():
    from purpleteam.audit.tpm_windows import WindowsTpmSigner

    with pytest.raises(ValueError, match="1-64 letters"):
        WindowsTpmSigner("not a valid name!")


@needs_windows
def test_ncrypt_failing_to_load_is_reported_as_unavailable(monkeypatch):
    import ctypes

    from purpleteam.audit.tpm_windows import _library

    def refuses(name):
        raise OSError("the specified module could not be found")

    monkeypatch.setattr(ctypes, "WinDLL", refuses)
    with pytest.raises(SignerUnavailable, match="ncrypt.dll"):
        _library()
