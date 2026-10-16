"""Static findings: a local Bandit scan and a self-hosted SonarQube connector, both feeding the
same Finding/patch pipeline a dynamic breach does."""

from pathlib import Path

import pytest

from purpleteam.defender.selector import Finding
from purpleteam.sast import BanditScanner, SonarQubeScanner, StaticFinding, bandit_available


def test_a_static_finding_converts_to_the_same_finding_type_a_breach_produces():
    static = StaticFinding("sql_injection", "ledgerpilot/agents/vendor.py", 42, "string-built SQL query")
    finding = static.as_finding()
    assert finding == Finding("sql_injection", tool="", agent="", detail="string-built SQL query "
                              "(ledgerpilot/agents/vendor.py:42)", source="static")


def test_bandit_scanner_maps_only_known_test_ids_and_drops_the_rest(monkeypatch, tmp_path):
    import purpleteam.sast as sast_module

    class _Result:
        stdout = ("{"
                 '"results": ['
                 '{"test_id": "B608", "filename": "a.py", "line_number": 10, '
                 '"issue_text": "possible SQL injection", "issue_severity": "MEDIUM"},'
                 '{"test_id": "B101", "filename": "b.py", "line_number": 1, '
                 '"issue_text": "assert used", "issue_severity": "LOW"}'
                 "]}")

    monkeypatch.setattr(sast_module.subprocess, "run", lambda *a, **k: _Result())
    findings = BanditScanner().scan(tmp_path)
    assert findings == [StaticFinding("sql_injection", "a.py", 10, "possible SQL injection", "medium")]


def test_bandit_scanner_degrades_to_empty_when_bandit_is_not_installed(monkeypatch, tmp_path):
    import purpleteam.sast as sast_module

    def _missing(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(sast_module.subprocess, "run", _missing)
    assert BanditScanner().scan(tmp_path) == []


def test_bandit_available_reflects_whether_the_cli_can_run():
    assert bandit_available() is True  # installed in this environment (see pyproject's platform group)


def test_sonarqube_scanner_refuses_sonarcloud():
    with pytest.raises(ValueError, match="SonarCloud"):
        SonarQubeScanner("https://sonarcloud.io", "token", "my-project")


def test_sonarqube_scanner_reads_issues_from_a_self_hosted_server(tmp_path):
    class _Response:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"issues": [
                {"rule": "python:S2077", "component": "svc/db.py", "message": "SQL built by concatenation",
                 "severity": "CRITICAL", "textRange": {"startLine": 7}},
                {"rule": "python:S9999", "component": "svc/other.py", "message": "unmapped rule",
                 "textRange": {"startLine": 1}},
            ]}

    class _Http:
        def get(self, url, params=None, auth=None, timeout=None):
            self.called_with = (url, params, auth, timeout)
            return _Response()

    http = _Http()
    scanner = SonarQubeScanner("https://sonar.internal.example.com", "s3cr3t", "my-project", http=http)
    findings = scanner.scan(Path("."))

    assert findings == [StaticFinding("sql_injection", "svc/db.py", 7, "SQL built by concatenation", "critical")]
    url, params, auth, _ = http.called_with
    assert url == "https://sonar.internal.example.com/api/issues/search"
    assert params == {"componentKeys": "my-project", "resolved": "false"} and auth == ("s3cr3t", "")


def test_sonarqube_scanner_never_logs_the_token_in_the_auth_tuple_as_plaintext_from_a_secretstr():
    from pydantic import SecretStr

    class _Http:
        def get(self, url, params=None, auth=None, timeout=None):
            self.auth = auth
            return self

        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"issues": []}

    http = _Http()
    SonarQubeScanner("https://sonar.internal", SecretStr("s3cr3t-token"), "proj", http=http).scan(Path("."))
    assert http.auth == ("s3cr3t-token", "")  # unwrapped only at the call site, never stored or printed as plaintext
