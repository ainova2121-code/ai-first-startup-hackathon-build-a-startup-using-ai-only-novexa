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

_SCAN_TIMEOUT = 120

# Bandit test ID -> the Finding kind the patch catalog already answers (purpleteam.patches.catalog).
# Only mapped IDs are kept; an unmapped Bandit finding would have nowhere to route.
BANDIT_KINDS = {"B608": "sql_injection"}

# SonarQube rule key -> the same Finding kinds, across the languages its default rule sets cover.
SONARQUBE_KINDS = {"python:S2077": "sql_injection", "java:S2077": "sql_injection", "js:S2077": "sql_injection"}


@dataclass(frozen=True)
class StaticFinding:
    kind: str
    file: str
    line: int
    detail: str
    severity: str = "medium"

    def as_finding(self) -> Finding:
        """Feed the same Defender/patch-catalog pipeline a dynamic breach would."""
        return Finding(self.kind, tool="", agent="", detail=f"{self.detail} ({self.file}:{self.line})",
                       source="static")


class Scanner(Protocol):
    def scan(self, repo: Path) -> list[StaticFinding]: ...


class BanditScanner:
    """Bandit: local, offline Python security linting. No account, no network."""

    def __init__(self, kinds: dict[str, str] = BANDIT_KINDS) -> None:
        self._kinds = kinds

    def scan(self, repo: Path) -> list[StaticFinding]:
        try:
            result = subprocess.run(
                ["bandit", "-r", str(repo), "-f", "json", "-t", ",".join(self._kinds)],
                capture_output=True, timeout=_SCAN_TIMEOUT, text=True)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []
        try:
            report = json.loads(result.stdout or "{}")
        except ValueError:
            return []
        findings = []
        for issue in report.get("results", []):
            kind = self._kinds.get(issue.get("test_id", ""))
            if kind is None:
                continue
            findings.append(StaticFinding(kind, issue["filename"], issue["line_number"], issue["issue_text"],
                                          issue.get("issue_severity", "medium").lower()))
        return findings


def bandit_available() -> bool:
    try:
        subprocess.run(["bandit", "--version"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


class SonarQubeScanner:
    """Reads issues already found by a self-hosted SonarQube instance for one project; never
    triggers or uploads a scan itself, and never talks to SonarCloud (see module docstring)."""

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
