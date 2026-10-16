"""Evasions found in review: blank-looking padding letters, a decoy that consumes the first
characters of a real key, and JSON escapes that a serialised tool result adds."""

import base64
import json

import pytest

from fixtures.fake_secrets import FORMATS, RANDOM_LOOKING
from purpleteam.secrets import SecretFinder

DECOY = "HTK-7F3A-LEAKCANARY"
FINDER = SecretFinder(known=[DECOY])


@pytest.mark.parametrize("filler", [chr(0x3164), chr(0x115F), chr(0x1160), chr(0xFFA0), chr(0x200B), chr(0x301)],
                         ids=["hangul-filler", "choseong-filler", "jungseong-filler", "halfwidth-filler",
                              "zero-width-space", "combining-acute"])
def test_blank_looking_letters_do_not_hide_a_known_secret(filler):
    text = f"HTK-7F3A-LEAK{filler}CANARY"
    assert FINDER.contains(text)
    assert FINDER.redact(text) == "[redacted]"


def test_a_decoy_that_overlaps_the_start_of_a_real_key_does_not_hide_it():
    real = FORMATS["aws_access_key"]
    assert SecretFinder().redact("ASIA" + "X" * 15 + real) == "[redacted]"  # the decoy ends on the real key's "A"


def test_a_decoy_skipped_for_lacking_a_digit_does_not_hide_a_spaced_key():
    text = "ASIA" + "X" * 15 + "A AKIA IOSFODNN7EXAMPLE"
    assert "IOSFODNN7EXAMPLE" not in SecretFinder().redact(text)


def test_a_low_entropy_assignment_does_not_hide_a_real_one_after_it():
    text = "token=" + "a" * 480 + f"api_key={RANDOM_LOOKING}"
    assert any(m.kind == "high_entropy_secret" for m in SecretFinder().find(text))
    assert RANDOM_LOOKING not in SecretFinder().redact(text)


def test_control_characters_and_astral_letters_survive_json_serialisation():
    for control in (chr(8), chr(12)):  # backspace and form feed serialise as \b and \f
        assert FINDER.contains(json.dumps({"result": f"HTK-7F3A-{control}LEAKCANARY"}))
    bold = "".join(chr(0x1D400 + ord(c) - 65) if c.isupper() else c for c in DECOY)  # mathematical bold capitals
    serialised = json.dumps({"result": bold})
    assert "\\ud835" in serialised  # written as surrogate pairs
    assert FINDER.contains(serialised)


def test_a_wrapped_encoding_serialised_in_a_tool_result_is_still_decoded():
    encoded = base64.b64encode((DECOY * 3).encode()).decode()
    wrapped = "\n".join(encoded[i:i + 16] for i in range(0, len(encoded), 16))
    assert FINDER.contains(wrapped)
    assert FINDER.contains(json.dumps({"result": wrapped}))  # the line breaks became backslash-n
