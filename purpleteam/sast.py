"""Read-only static analysis of a target's own source — domain-agnostic.

A dynamic breach proves a hole by walking through it; this finds the same class of hole by
reading the code, for the cases a black-box attack might miss or a customer wants evidence
pointing at an exact line. Findings here feed the same Finding/patch-catalog pipeline a dynamic
breach does (``StaticFinding.as_finding``), so the defender and the compliance report treat both
as one evidence set — just tagged with how each was found (``Finding.source``).

Nothing here is uploaded anywhere by default: ``BanditScanner`` runs fully offline, no account or
network needed. ``SonarQubeScanner`` only talks to a self-hosted SonarQube instance the customer
runs and points us at (their own base URL and token) — never SonarCloud or any other host we
don't control. Sending a customer's source to a cloud we operate would break BYOC the same way
routing their traffic through our own LLM gateway would; this module refuses that host outright.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from purpleteam.defender.selector import Finding

_SCAN_TIMEOUT = 600

# Third-party and generated code a project ships with but does not own: scanning a cloned target's
# own .venv would bury its real findings under thousands from its dependencies (and time out).
EXCLUDED_DIRS = (".venv", "venv", "env", ".env", "node_modules", "site-packages", ".git", "__pycache__",
                 ".tox", ".nox", ".mypy_cache", ".pytest_cache", "build", "dist", ".eggs")

# Bandit test ID -> the Finding kind this platform knows what to do with. sql_injection has a runtime
# patch (purpleteam.patches.catalog); the rest have none -- no guard can "un-hardcode" a secret or make
# an already-built shell command safe -- so only a verified source edit resolves them. Every other
# Bandit check still runs and is reported as ``bandit:<id>`` (see ``StaticFinding.blocking``).
BANDIT_KINDS = {
    "B608": "sql_injection",
    "B105": "hardcoded_secret", "B106": "hardcoded_secret", "B107": "hardcoded_secret",
    "B602": "shell_injection", "B604": "shell_injection", "B605": "shell_injection",
    "B102": "code_execution", "B307": "code_execution",
    "B301": "insecure_deserialization", "B506": "insecure_deserialization",
    "B501": "tls_verification_disabled",
    "B324": "weak_hash",
    "B113": "request_without_timeout",
}
# Kinds always blocking whatever the scanner's own severity says: Bandit rates a hardcoded password LOW.
_ALWAYS_BLOCKING = frozenset(BANDIT_KINDS.values())
SCANNED_SUFFIXES = {"bandit": frozenset({".py"})}


class ScanFailed(RuntimeError):
    """The scanner could not complete: never to be read as "found nothing"."""

# SonarQube rule key -> the same Finding kinds, across the languages its default rule sets cover.
# sql_injection only: the equivalent Python rule keys for hardcoded credentials and OS command
# injection were not confirmed against SonarQube's own documentation, so they are deliberately
# left unmapped rather than guessed — a wrong key would silently match nothing, which is worse
# than an honest gap.
SONARQUBE_KINDS = {"python:S2077": "sql_injection", "java:S2077": "sql_injection", "js:S2077": "sql_injection"}


@dataclass(frozen=True)
class StaticFinding:
    kind: str
    file: str
    line: int
    detail: str
    severity: str = "medium"

    @property
    def blocking(self) -> bool:
        """Whether this finding alone stops a release: every mapped kind, and any other finding the
        scanner rates medium or high. A low-severity unmapped one is reported as advisory."""
        return self.kind in _ALWAYS_BLOCKING or self.severity in ("medium", "high", "critical", "major", "blocker")

    def as_finding(self) -> Finding:
        """Feed the same Defender/patch-catalog pipeline a dynamic breach would."""
        return Finding(self.kind, tool="", agent="", detail=f"{self.detail} ({self.file}:{self.line})",
                       source="static")


class Scanner(Protocol):
    def scan(self, repo: Path) -> list[StaticFinding]: ...


class BanditScanner:
    """Bandit: local, offline Python security linting. No account, no network. Runs every Bandit
    check (not only the mapped ones), so a fix that introduces any new issue is caught on rescan."""

    languages = SCANNED_SUFFIXES["bandit"]

    def __init__(self, kinds: dict[str, str] = BANDIT_KINDS) -> None:
        self._kinds = kinds

    def scan(self, repo: Path) -> list[StaticFinding]:
        excluded = ",".join(f"*/{name}/*" for name in EXCLUDED_DIRS)
        try:
            result = subprocess.run(["bandit", "-r", str(repo), "-f", "json", "-q", "-x", excluded],
                                    capture_output=True, timeout=_SCAN_TIMEOUT, text=True)
        except FileNotFoundError as error:
            raise ScanFailed("bandit is not installed") from error
        except subprocess.TimeoutExpired as error:
            raise ScanFailed(f"bandit did not finish within {_SCAN_TIMEOUT}s") from error
        try:
            report = json.loads(result.stdout)
        except ValueError as error:  # exit 1 only means "issues found"; no JSON at all means it broke
            raise ScanFailed(f"bandit produced no report (exit {result.returncode})") from error
        if report.get("errors"):
            files = ", ".join(sorted(Path(e.get("filename", "?")).name for e in report["errors"])[:5])
            raise ScanFailed(f"bandit could not analyse {len(report['errors'])} file(s): {files}")
        findings = []
        for issue in report.get("results", []):
            test_id = issue.get("test_id", "")
            kind = self._kinds.get(test_id, f"bandit:{test_id}")
            findings.append(StaticFinding(kind, issue["filename"], issue["line_number"], issue["issue_text"],
                                          issue.get("issue_severity", "medium").lower()))
        return findings


def unscanned_sources(repo: Path, scanned: frozenset[str]) -> dict[str, int]:
    """Source files, by suffix, that no configured scanner reads -- so a clean scan is never
    presented as covering code nobody looked at. Dependencies and build output are not counted."""
    counts: dict[str, int] = {}
    for path in repo.rglob("*"):
        if path.suffix.lower() in _SOURCE_SUFFIXES and path.suffix.lower() not in scanned and path.is_file() \
                and not any(part in EXCLUDED_DIRS for part in path.relative_to(repo).parts):
            counts[path.suffix.lower()] = counts.get(path.suffix.lower(), 0) + 1
    return counts


_SOURCE_SUFFIXES = frozenset({".py", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".go", ".java", ".kt", ".rb", ".php",
                              ".cs", ".rs", ".swift", ".scala", ".c", ".cc", ".cpp", ".h"})


def bandit_available() -> bool:
    try:
        subprocess.run(["bandit", "--version"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


class SonarQubeScanner:
    """Reads issues already found by a self-hosted SonarQube instance for one project; never
    triggers or uploads a scan itself, and never talks to SonarCloud (see module docstring)."""

    languages = _SOURCE_SUFFIXES  # the server analyses every language its rule sets cover

    def __init__(self, base_url: str, token, project_key: str, http=None, kinds: dict[str, str] = SONARQUBE_KINDS) -> None:
        host = base_url.rstrip("/").lower()
        if "sonarcloud.io" in host:
            raise ValueError("SonarCloud is a third-party host; point this at a self-hosted SonarQube instance")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._project_key = project_key
        self._kinds = kinds
        if http is None:
            import httpx
            http = httpx
        self._http = http

    def scan(self, repo: Path) -> list[StaticFinding]:  # repo unused: the server already holds the analysis
        secret = self._token.get_secret_value() if hasattr(self._token, "get_secret_value") else self._token
        response = self._http.get(f"{self._base_url}/api/issues/search",
                                   params={"componentKeys": self._project_key, "resolved": "false"},
                                   auth=(secret, ""), timeout=30)
        response.raise_for_status()
        findings = []
        for issue in response.json().get("issues", []):
            kind = self._kinds.get(issue.get("rule", ""))
            if kind is None:
                continue
            location = issue.get("textRange", {})
            findings.append(StaticFinding(kind, issue.get("component", ""), location.get("startLine", 0),
                                          issue.get("message", ""), issue.get("severity", "medium").lower()))
        return findings
