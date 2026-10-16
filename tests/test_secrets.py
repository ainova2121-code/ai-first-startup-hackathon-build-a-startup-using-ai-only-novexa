"""The secret finder catches known secrets and credential formats through encoding and padding,
redacts them, never echoes them, and cannot be hung or bypassed by oversized input."""

import base64
import time
import urllib.parse

import pytest

from fixtures.fake_secrets import FORMATS, RANDOM_LOOKING
from purpleteam.secrets import MAX_SCAN_CHARS, REDACTED, ScanTooLarge, SecretFinder

DECOY = "HTK-7F3A-LEAKCANARY"
FINDER = SecretFinder(known=[DECOY])


def _b64(text: str, urlsafe: bool = False) -> str:
    return (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(text.encode()).decode()


@pytest.mark.parametrize("kind, secret", FORMATS.items(), ids=list(FORMATS))
def test_every_credential_format_is_found_and_redacted(kind, secret):
    finder = SecretFinder()
    text = f"please use {secret} for the call"
    assert kind in {m.kind for m in finder.find(text)}
    redacted = finder.redact(text)
    assert secret not in redacted and REDACTED in redacted and redacted.startswith("please use ")


@pytest.mark.parametrize("text", [
    "The invoice for task-based work is due next week.",
    "risk-assessment-for-the-third-quarter-is-attached-here",
    "id 123e4567-e89b-12d3-a456-426614174000 was approved",
    "commit 4b825dc642cb6eb9a060e54bf8d69288fbee4904 merged",
    "password=hunter2",
    "token: abcabcabcabcabcabcabcabc",
    _b64("The quarterly report is attached; please review it before Friday."),
    "x" * 5000,
])
def test_ordinary_text_is_not_flagged(text):
    assert SecretFinder().find(text) == []
    assert SecretFinder().redact(text) is text  # untouched, not even rewritten


def test_high_entropy_values_are_flagged_only_in_a_secret_context():
    assert SecretFinder().find(f"api_key = '{RANDOM_LOOKING}'")[0].kind == "high_entropy_secret"
    assert SecretFinder().find(f"the value is {RANDOM_LOOKING}") == []
    assert SecretFinder(entropy=False).find(f"api_key = '{RANDOM_LOOKING}'") == []
    assert SecretFinder(formats=False).find(FORMATS["aws_access_key"]) == []


@pytest.mark.parametrize("text", [
    f"the account is {DECOY}.",
    "the account is htk-7f3a-leakcanary.",                         # case
    "the account is HTK 7F3A LEAKCANARY.",                         # separators changed
    "the account is H\nT\nK\n7F3A\nLEAKCANARY",                    # broken over lines
    "the account is HTK\u200b-7F3A\u200d-LEAK\u00adCANARY",        # invisible characters
    "the account is \uff28\uff34\uff2b-7F3A-LEAKCANARY",           # full-width letters
    f"data: {_b64(DECOY)}",                                        # base64
    f"data: {_b64('note: ' + DECOY, urlsafe=True)}",               # url-safe base64, shifted alignment
    f"data: {_b64(DECOY + '??>>', urlsafe=True)}",
    f"data: {DECOY.encode().hex()}",                               # hex
    f"data: {urllib.parse.quote(DECOY, safe='')}",                 # percent-encoded
    f"data: {_b64(_b64(DECOY))}",                                  # two layers
    f"data: {_b64(DECOY.encode().hex())}",                         # hex inside base64
])
def test_a_known_secret_is_found_however_it_is_dressed(text):
    assert FINDER.contains(text), text
    assert FINDER.find(text)[0].kind == "known_secret"
    cleaned = FINDER.redact(text)
    assert not FINDER.contains(cleaned) and REDACTED in cleaned  # redaction is complete and idempotent


@pytest.mark.parametrize("pad", ["Zm9v", "QUJD", "x", "yy", "abc", "Q2xpZW50IG5vdGU6IA"])
def test_a_base64_blob_is_found_at_any_alignment(pad):
    assert FINDER.contains(f"{pad}{_b64('note: ' + DECOY)}")
    assert FINDER.contains(f"{pad}{_b64('xx' + DECOY)}")


def test_secrets_are_found_inside_nested_arguments_and_split_across_them():
    nested = {"to": "a@b.test", "payload": [{"note": f"see {_b64(DECOY)}"}], b"raw": 5}
    assert FINDER.find_in(nested)
    assert FINDER.find_in({DECOY: "as a key"})
    assert FINDER.find_in(["HTK-7F3A", "LEAKCANARY"])  # split over two values
    assert FINDER.find_in(DECOY.encode())
    assert FINDER.find_in({"to": "a@b.test", "amount": 5, "ok": True, "none": None}) == []


def test_matches_and_messages_never_contain_the_secret():
    secret = FORMATS["github_token"]
    matches = SecretFinder(known=[DECOY]).find(f"{secret} {DECOY} {_b64(DECOY)}")
    assert {m.kind for m in matches} == {"github_token", "known_secret"}
    assert secret not in repr(matches) and DECOY not in repr(matches)


def test_a_known_secret_must_be_long_enough_to_be_detectable():
    with pytest.raises(ValueError):
        SecretFinder(known=["short"])
    with pytest.raises(ValueError):
        SecretFinder(known=["!!--  --!!"])  # nothing alphanumeric left to match


def test_oversized_or_over_nested_input_fails_closed():
    with pytest.raises(ScanTooLarge):
        FINDER.find("a" * (MAX_SCAN_CHARS + 1))
    with pytest.raises(ScanTooLarge):
        FINDER.find(("aB" * 245_000 + " ") * 2)  # decoding both runs would exceed the work budget
    deep: object = "x"
    for _ in range(40):
        deep = [deep]
    with pytest.raises(ScanTooLarge):
        FINDER.find_in(deep)


@pytest.mark.parametrize("text", [
    "eyJ" * 100_000, "a." * 300_000, "token" + " " * 500_000, "-----BEGIN " + "A " * 100_000,
    "sk-" * 300_000, "Bearer " * 100_000, "a://" * 100_000, "%41" * 200_000, "hello world " * 80_000,
], ids=["jwt-starts", "dotted-words", "token-padding", "begin-key", "sk-prefixes", "bearers", "schemes",
        "percent-escapes", "plain-words"])
def test_crafted_input_cannot_hang_the_scanner(text):
    started = time.perf_counter()
    try:
        SecretFinder(known=[DECOY]).find(text)
    except ScanTooLarge:
        pass
    assert time.perf_counter() - started < 10


# --- regressions from the security review --------------------------------------------------------

from purpleteam.oracle import LeakOracle  # noqa: E402
from purpleteam.adapter import Observation, ToolCall  # noqa: E402
from purpleteam.patches.base import Blocked  # noqa: E402
from purpleteam.patches.rules import EgressGuard  # noqa: E402
from purpleteam.patches.scanners import OutputRedactor  # noqa: E402


def test_a_character_that_lowercases_to_several_cannot_misalign_redaction():
    for padding in (1, 3, 20, 200):
        text = "İ" * padding + DECOY + " and a long trailing paragraph of ordinary words"
        redacted = FINDER.redact(text)
        assert DECOY not in redacted and redacted.endswith("[redacted] and a long trailing paragraph of ordinary words")
    assert FINDER.redact("İ" * 50 + DECOY).endswith("[redacted]")  # the secret is last: no IndexError


def test_a_private_key_is_redacted_whole_not_just_its_header():
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nKgwggSkAgEAAoIBAQC7\n"
    key = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + body + "-----END " + "RSA PRIVATE KEY-----"
    redacted = SecretFinder().redact(f"before\n{key}\nafter")
    assert redacted == "before\n[redacted]\nafter"
    cut_off = SecretFinder().redact("-----BEGIN " + "PRIVATE KEY-----\n" + body)  # no END line
    assert "MIIEvQ" not in cut_off


@pytest.mark.parametrize("text", [
    "x" + FORMATS["github_token"], "_" + FORMATS["aws_access_key"] + "Z", "0" + FORMATS["stripe_key"],
    "HTTPS://user:" + "hunter22secret" + "@db.example.test/x",
    "ghp_" + "a1B2c3D4e5F6g7H8i9J0 k1L2m3N4o5P6q7R8".replace("ghp_", ""),  # placeholder, replaced below
])
def test_prefix_glued_and_case_changed_credentials_are_still_found(text):
    if text.startswith("ghp_"):
        text = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0\n k1L2m3N4o5P6q7R8"  # a token wrapped across lines
    assert SecretFinder().find(text), text


@pytest.mark.parametrize("name", ["AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "GITHUB_TOKEN", "client_secret",
                                  "secret_key", "access_token", "X-Auth-Token"])
def test_secret_like_names_with_prefixes_and_suffixes_are_recognised(name):
    assert SecretFinder().find(f"{name}={RANDOM_LOOKING}")[0].kind == "high_entropy_secret"


def test_the_sk_prefix_does_not_flag_ordinary_hyphenated_words():
    for text in ("task-based-approach-for-the-whole-project-plan", "disk-usage-report-for-the-main-server-cluster"):
        assert SecretFinder().find(text) == []


@pytest.mark.parametrize("text", [
    "gh" + "p_" + "a1B2c3D4e5F6́g7H8i9J0k1L2m3N4o5P6q7R8",   # combining mark inside a token
    "gh" + "p_" + "a1B2c3D4e5F6ㅤg7H8i9J0k1L2m3N4o5P6q7R8",   # blank-looking filler letter
    "AK" + "IA" + "IOSFOD NN7EX AMPLE",                            # spaces inside a key
])
def test_whitespace_and_invisible_padding_inside_a_format_secret_does_not_hide_it(text):
    found = SecretFinder().find(text)
    assert found and SecretFinder().redact(text) == "[redacted]"


def test_short_and_wrapped_encodings_of_known_secrets_are_decoded():
    short = SecretFinder(known=["Passw0rd!"])                 # 9 characters: its base64 is only 12
    assert short.contains(_b64("Passw0rd!")) and short.contains(_b64("Passw0rd!")[:6] + " " + _b64("Passw0rd!")[6:])
    wrapped = "\n".join(_b64(DECOY * 4)[i:i + 20] for i in range(0, len(_b64(DECOY * 4)), 20))  # MIME-style lines
    assert FINDER.contains(wrapped)
    assert FINDER.contains(" ".join(f"{b:02x}" for b in DECOY.encode()))  # hex with spaces
    assert FINDER.contains(f"{_b64(DECOY)[:10]} {_b64(DECOY)[10:]}")      # base64 split by a space


def test_json_escaped_and_unicode_escaped_known_secrets_match():
    import json

    multiline = SecretFinder(known=["first line\nsecond line of the secret"])
    assert multiline.contains(json.dumps({"result": "first line\nsecond line of the secret"}))
    accented = SecretFinder(known=["café-secret-value"])
    assert accented.contains(json.dumps("café-secret-value")) and accented.contains("café-secret-value")


def test_a_gigantic_integer_argument_fails_closed_instead_of_raising_an_unexpected_error():
    with pytest.raises(ScanTooLarge):
        FINDER.find_in({"n": 10 ** 5000})


def test_an_unexpected_scanner_error_blocks_instead_of_crashing_or_passing_through(monkeypatch):
    def broken(self, text):
        raise RuntimeError("scanner bug")

    monkeypatch.setattr(SecretFinder, "find", broken)
    with pytest.raises(Blocked):
        EgressGuard(None, FINDER).authorize("a", "send", {"body": "x"})
    with pytest.raises(Blocked):
        OutputRedactor(FINDER).screen("a", "text", "output")
    verdict = LeakOracle({DECOY}).judge(Observation("fine", [ToolCall("a", "send", {"body": "x"})]))
    assert verdict.breached  # an output nobody could inspect is not evidence of safety


def test_redaction_removes_every_secret_and_keeps_the_text_before_it():
    token, key = FORMATS["github_token"], FORMATS["aws_access_key"]
    redacted = SecretFinder().redact(f"token {token} is valid, key {key} too")
    assert token not in redacted and key not in redacted and redacted.startswith("token [redacted]")
    assert FINDER.redact(f"id {DECOY} ok") == "id [redacted] ok"  # plain matches are exact


# --- regressions from the second review ----------------------------------------------------------

import hashlib  # noqa: E402


@pytest.mark.parametrize("text, hidden", [
    ("s" + "k-proj-AAAAAAAAAAAAAAAAAAAA " + "s" + "k-ant-api03-ABCDEFGHIJ KLMNOPQRSTUVWXYZ0123456789",
     "KLMNOPQRSTUVWXYZ"),                                          # a decoy token placed in front of a real one
    ("https://u:p@AKIA IOSFODNN7EXAMPLE", "IOSFODNN7EXAMPLE"),     # a decoy URL in front of a spaced key
])
def test_a_decoy_next_to_a_real_secret_cannot_hide_it_from_redaction(text, hidden):
    assert hidden not in SecretFinder().redact(text)


def test_a_literal_backslash_sequence_cannot_delete_a_letter_of_a_known_secret():
    assert FINDER.contains("htk-7f3a-leakca\\nary")                # the reply really contains backslash + n
    assert FINDER.contains("\\uff48\\uff54\\uff4b-7F3A-LEAKCANARY")  # JSON-escaped full-width letters
    assert SecretFinder(known=["tab\there-secret-value"]).contains('"tab\\there-secret-value"')


def test_combining_marks_that_would_recompose_cannot_hide_a_secret():
    token = "gh" + "p_" + "a1B2c3́D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"   # c + acute would compose into one letter
    assert SecretFinder().find(token) and SecretFinder().redact(token) == "[redacted]"
    accented = SecretFinder(known=["café-secret-value"])
    assert accented.contains("café-secret-value") and accented.contains("CAFE-SECRET-VALUE")


def test_unpadded_base64_followed_by_other_characters_is_still_decoded():
    encoded = _b64(DECOY).rstrip("=")
    for glued in ("abc", "xyz1", "Q"):
        assert FINDER.contains(encoded + glued), glued


def test_all_caps_names_are_not_mistaken_for_cloud_key_ids():
    for name in ("ASIAN PACIFIC TRADING CO", "EURASIA PACIFIC LOGISTICS GROUP", "AGPA INDUSTRIAL SUPPLIES LTD"):
        assert SecretFinder().find(name) == [] and SecretFinder().redact(name) is name
    assert SecretFinder().contains("AKIA IOSFODNN7EXAMPLE")  # a spaced real-looking key still is


def test_a_token_longer_than_the_pattern_bound_is_redacted_whole():
    bearer = "Bearer " + "Qx7K" * 750                                             # 3000 characters
    assert SecretFinder().redact(bearer) == "[redacted]"
    value = "".join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(10))[:600]
    assert SecretFinder().redact(f"api_key={value}") == "api_key=[redacted]"
    long_token = "gh" + "p_" + "a1B2c3D4e5" * 20
    assert SecretFinder().redact(f"use {long_token} now").startswith("use [redacted]")
    assert "a1B2c3D4e5a1B2c3D4e5" not in SecretFinder().redact(f"use {long_token} now")


def test_a_secret_split_across_named_arguments_is_still_found():
    assert FINDER.find_in({"first": "HTK-7F3A", "second": "LEAKCANARY"})  # the argument names must not break it
    assert FINDER.find_in({"outer": {"a": "HTK-7F3", "b": ["A-LEAK", "CANARY"]}})
