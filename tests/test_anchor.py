"""Timestamp anchoring: a genuine FreeTSA token verifies, every kind of damage is rejected, and
the multi-authority policy behaves. The live round trip is opt-in (PURPLETEAM_LIVE_TSA=1)."""

import base64
import hashlib
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from fixtures.ledger import make_ledger
from purpleteam.audit import anchor
from purpleteam.audit.anchor import (
    FREETSA_DIR, MAX_RESPONSE_BYTES, AnchorError, Authority, anchor_trust, freetsa, https_post,
    load_authority, request_anchor, verify_anchored_log, verify_token,
)

TSA_FIXTURES = Path(__file__).parent / "fixtures" / "tsa"
MESSAGE = (TSA_FIXTURES / "checkpoint.json").read_bytes()
TOKEN = (TSA_FIXTURES / "checkpoint.tsr").read_bytes()
STAMPED = datetime(2026, 10, 9, 16, 30, 4, tzinfo=timezone.utc)  # the time FreeTSA signed into the token


def _foreign_cert() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not freetsa")])
    now = datetime.now(timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))


def test_a_genuine_freetsa_token_verifies_against_the_pinned_certificates():
    assert verify_token(TOKEN, MESSAGE, freetsa()) == STAMPED


@pytest.mark.parametrize("token, message", [
    (TOKEN, MESSAGE + b"x"),                                              # a different message
    (TOKEN[:-5], MESSAGE),                                                # truncated
    (TOKEN[:200] + bytes([TOKEN[200] ^ 1]) + TOKEN[201:], MESSAGE),       # one flipped bit
    (b"", MESSAGE),
    (b"\x30\x03\x02\x01\x00", MESSAGE),                                   # valid DER, not a timestamp
    (TOKEN + b"\x00" * MAX_RESPONSE_BYTES, MESSAGE),                      # oversized
], ids=["other-message", "truncated", "flipped-bit", "empty", "not-a-timestamp", "oversized"])
def test_damaged_or_mismatched_tokens_are_rejected(token, message):
    with pytest.raises(AnchorError):
        verify_token(token, message, freetsa())


def test_a_token_is_rejected_unless_it_chains_to_the_pinned_roots_and_signer():
    real = freetsa()
    with pytest.raises(AnchorError):
        verify_token(TOKEN, MESSAGE, Authority("other", real.url, (_foreign_cert(),)))
    with pytest.raises(AnchorError):
        verify_token(TOKEN, MESSAGE, Authority("other", real.url, real.roots, _foreign_cert()))


def test_certificate_files_must_match_the_manifest(tmp_path):
    shutil.copytree(FREETSA_DIR, tmp_path / "ok")
    load_authority("copy", "https://tsa.test/tsr", tmp_path / "ok")

    shutil.copytree(FREETSA_DIR, tmp_path / "edited")
    (tmp_path / "edited" / "tsa.crt").write_bytes((FREETSA_DIR / "tsa.crt").read_bytes() + b"\n")
    shutil.copytree(FREETSA_DIR, tmp_path / "unlisted")
    (tmp_path / "unlisted" / "SHA256SUMS").write_text("")
    for directory in ("edited", "unlisted"):
        with pytest.raises(AnchorError, match="SHA256SUMS"):
            load_authority("copy", "https://tsa.test/tsr", tmp_path / directory)
    with pytest.raises(AnchorError):
        load_authority("copy", "https://tsa.test/tsr", FREETSA_DIR, roots=("../x.pem",))
    for url in ("http://tsa.test/tsr", "https://user:pw@tsa.test/tsr", "ftp://tsa.test"):
        with pytest.raises(AnchorError):
            load_authority("copy", url, FREETSA_DIR)


def _transport(handler):
    return httpx.MockTransport(handler)


def test_the_http_client_refuses_redirects_errors_oversize_and_plain_http():
    ok = _transport(lambda r: httpx.Response(200, content=b"token"))
    assert https_post("https://tsa.test/tsr", b"q", 5, transport=ok) == b"token"
    for response in (httpx.Response(302, headers={"location": "https://evil.test/"}), httpx.Response(500),
                     httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))):
        with pytest.raises(AnchorError):
            https_post("https://tsa.test/tsr", b"q", 5, transport=_transport(lambda r, resp=response: resp))

    def unreachable(request):
        raise httpx.ConnectError("down")

    with pytest.raises(AnchorError):
        https_post("https://tsa.test/tsr", b"q", 5, transport=_transport(unreachable))
    with pytest.raises(AnchorError):
        https_post("http://tsa.test/tsr", b"q", 5, transport=ok)


def test_malformed_urls_and_client_errors_become_anchor_errors():
    for url in ("https://[::1", "https://", "https:///path", "not a url"):
        with pytest.raises(AnchorError):
            https_post(url, b"q", 5, transport=_transport(lambda r: httpx.Response(200)))
        with pytest.raises(AnchorError):
            load_authority("copy", url, FREETSA_DIR)

    def invalid(request):
        raise httpx.InvalidURL("bad")

    with pytest.raises(AnchorError):
        https_post("https://tsa.test/tsr", b"q", 5, transport=_transport(invalid))


def _directory_with(tmp_path, name, content: bytes) -> Path:
    directory = tmp_path / name
    directory.mkdir()
    (directory / "cacert.pem").write_bytes(content)
    (directory / "SHA256SUMS").write_text(f"{hashlib.sha256(content).hexdigest()}  cacert.pem\n")
    return directory


def test_a_pinned_file_must_hold_exactly_one_certificate(tmp_path):
    pem = (FREETSA_DIR / "cacert.pem").read_bytes()
    load_authority("copy", "https://tsa.test/tsr", _directory_with(tmp_path, "one", pem), signer=None)
    for name, content, expected in (("two", pem + pem, "exactly one"), ("junk", b"not a certificate", "not a PEM"),
                                    ("empty", b"", "not a PEM")):
        with pytest.raises(AnchorError, match=expected):
            load_authority("copy", "https://tsa.test/tsr", _directory_with(tmp_path, name, content), signer=None)


def test_a_replayed_genuine_response_does_not_answer_a_fresh_request():
    with pytest.raises(AnchorError):
        request_anchor({"size": 1}, freetsa(), post=lambda url, body, timeout: TOKEN)


# --- multi-authority policy, with the authority's time under test control ---------------------

T0 = 1_800_000_000.0


@pytest.fixture
def anchored(tmp_path, monkeypatch):
    """A pinned trust bundle with anchors "a" and "b" whose verified times the test controls."""
    ledger = make_ledger(tmp_path / "audit.jsonl")
    trust = ledger.export_trust()
    times = {"a": trust["checkpoint"]["ts"] + 10, "b": trust["checkpoint"]["ts"] + 20}

    def fake_verify(token, message, authority, *, request=None):
        if times.get(authority.name) is None:
            raise AnchorError("rejected")
        return datetime.fromtimestamp(times[authority.name], tz=timezone.utc)

    monkeypatch.setattr(anchor, "verify_token", fake_verify)
    token = base64.b64encode(b"x").decode()
    trust["anchors"] = [{"authority": "a", "response": token}, {"authority": "b", "response": token}]
    authorities = {n: Authority(n, "https://tsa.test/tsr", ()) for n in ("a", "b")}
    return ledger, trust, authorities, times


def test_the_latest_of_the_verified_times_is_the_conservative_bound(anchored):
    ledger, trust, authorities, times = anchored
    result = verify_anchored_log(ledger.events(), trust, authorities, min_anchors=2)
    assert result.ok and result.anchored and result.anchored_at == times["b"]


def test_too_few_distinct_verified_anchors_fails(anchored):
    ledger, trust, authorities, times = anchored
    times["b"] = None
    result = verify_anchored_log(ledger.events(), trust, authorities, min_anchors=2)
    assert not result.ok and "1 of 2" in result.reason
    assert verify_anchored_log(ledger.events(), trust, authorities, min_anchors=1).ok
    trust["anchors"].append(trust["anchors"][0])  # the same authority twice is still one authority
    assert not verify_anchored_log(ledger.events(), trust, authorities, min_anchors=2).ok
    trust["anchors"].append({"authority": "unknown", "response": "AA=="})
    assert "1 of 2" in verify_anchored_log(ledger.events(), trust, authorities, min_anchors=2).reason


def test_anchored_before_requires_every_anchor_to_be_early_enough(anchored):
    ledger, trust, authorities, times = anchored
    assert verify_anchored_log(ledger.events(), trust, authorities, anchored_before=times["b"]).ok
    late = verify_anchored_log(ledger.events(), trust, authorities, anchored_before=times["a"])
    assert not late.ok and "later than required" in late.reason  # one early liar cannot pull the bound earlier


def test_a_checkpoint_cannot_claim_a_time_after_its_own_timestamp(anchored):
    ledger, trust, authorities, times = anchored
    times["a"] = times["b"] = trust["checkpoint"]["ts"] - 3600
    result = verify_anchored_log(ledger.events(), trust, authorities)
    assert not result.ok and "after its own timestamp" in result.reason


def test_anchors_do_not_rescue_a_log_that_fails_verification(anchored, tmp_path):
    ledger, trust, authorities, _ = anchored
    lines = ledger.path.read_text().splitlines()
    ledger.path.write_text("\n".join(lines[:-1]) + "\n")
    result = verify_anchored_log(ledger.events(), trust, authorities)
    assert not result.ok and "truncated" in result.reason


def test_without_a_pinned_checkpoint_there_is_nothing_to_anchor(anchored):
    ledger, trust, authorities, _ = anchored
    result = verify_anchored_log(ledger.events(), {"keys": trust["keys"], "anchors": trust["anchors"]}, authorities)
    assert not result.ok and "no pinned checkpoint" in result.reason


def test_unreachable_authorities_are_reported_not_fatal(anchored, monkeypatch):
    _, trust, authorities, _ = anchored

    def fake_request(checkpoint, authority, **kwargs):
        if authority.name == "b":
            raise AnchorError("down")
        return {"authority": authority.name, "response": "AA=="}

    monkeypatch.setattr(anchor, "request_anchor", fake_request)
    anchored_trust, errors = anchor_trust(trust, list(authorities.values()))
    assert [a["authority"] for a in anchored_trust["anchors"]] == ["a"] and errors == ["b: down"]


@pytest.mark.skipif(os.environ.get("PURPLETEAM_LIVE_TSA") != "1", reason="live network test; set PURPLETEAM_LIVE_TSA=1")
def test_live_round_trip_with_freetsa(tmp_path):
    ledger = make_ledger(tmp_path / "audit.jsonl")
    trust, errors = anchor_trust(ledger.export_trust(), [freetsa()])
    assert errors == []
    result = verify_anchored_log(ledger.events(), trust, {"freetsa": freetsa()}, min_anchors=1)
    assert result.ok and result.anchored and abs(result.anchored_at - datetime.now(timezone.utc).timestamp()) < 300
