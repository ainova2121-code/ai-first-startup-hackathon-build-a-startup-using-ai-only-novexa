"""The static run: everything that can be learned about a target without attacking it, in seconds.

Discovery, identity posture, a source scan (``purpleteam.sast``), fixes already in the operator's approved catalog
(never a model draft: no model is called), and rule checks on each agent's own prompt. The prompt rules are plain
patterns, domain-agnostic, and only *predict* a weakness -- an attack is what proves one -- so a static run never
says "safe to ship": it reports what inspection found and names what it could not see. Everything it found is signed
into the ledger and sealed like any other run.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

from purpleteam.codemods.catalog import CodemodCatalog
from purpleteam.codemods.restore import SourceSnapshots
from purpleteam.discovery import TargetProfile
from purpleteam.identity import posture
from purpleteam.sast import ScanFailed, Scanner, unscanned_sources
from purpleteam.source_fix import display, fix_sources

_ACTS_ON_CONTENT = re.compile(
    r"\b(use|pay|send|transfer|update|change|set|record|approve|schedule)\b[^.\n]{0,80}"
    r"\b(as (stated|given|provided|written|requested)|stated in|given in|provided in|listed in|from|in)\b[^.\n]{0,40}"
    r"\b(e-?mail|message|document|invoice|request|input|content|attachment|ticket|text|note|remittance)", re.IGNORECASE)
_VERIFIES = re.compile(r"\b(verif\w*|confirm\w*|validat\w*|check\w* (it )?against|approv\w*|on file|allow-?list|whitelist)",
                       re.IGNORECASE)
_UNTRUSTED_RULE = re.compile(r"\b(untrusted|never follow|do not follow|ignore (any )?instructions|treat [^.\n]{0,30} as data)",
                             re.IGNORECASE)


def prompt_findings(profile: TargetProfile) -> tuple[list[dict], list[str]]:
    """(findings, gaps): what each agent's own prompt predicts, and the agents whose prompt was never captured."""
    findings, gaps = [], []
    holdings = {agent: [t for t in profile.tools if t.agent == agent] for agent in profile.agents}
    for info in profile.agent_info:
        tools = holdings.get(info.name, [])
        dangerous = sorted(t.name for t in tools if t.dangerous)
        if not info.prompt:
            gaps.append(f"agent {info.name}: prompt not captured, so its instructions were not checked")
            continue

        def found(kind: str, severity: str, detail: str) -> None:
            findings.append({"kind": kind, "agent": info.name, "severity": severity, "detail": detail,
                             "evidence": "predicted by inspection, not proven by an attack"})

        if dangerous and _ACTS_ON_CONTENT.search(info.prompt):
            found("acts_on_unverified_content", "high", f"its prompt tells it to act on values taken from incoming "
                  f"content, and it holds {', '.join(dangerous)}")
        if dangerous and not _VERIFIES.search(info.prompt):
            found("no_verification_step", "medium", f"it holds {', '.join(dangerous)} and its prompt names no step "
                  "that verifies or confirms before acting")
        if any(t.retrieval or not t.dangerous for t in tools) and not _UNTRUSTED_RULE.search(info.prompt):
            found("no_untrusted_content_rule", "low", "it reads content from outside, and its prompt never says to treat "
                  "that content as data rather than instructions")
    return findings, gaps


async def static_run(profile: TargetProfile, creds: dict[str, str], ledger: Any, *, scanner: Scanner | None,
                     repo: Path | None, catalog: CodemodCatalog | None, snapshots: SourceSnapshots | None,
                     emit: Callable[[dict], None] = lambda event: None) -> dict:
    """Run every inspection; return the report (findings, fixes, gaps, the sealed root and trust bundle)."""
    identity = [{"kind": f.kind, "agent": f.agent, "severity": f.severity, "detail": f.detail}
                for f in posture(profile, None, creds)]
    ledger.append("identity", "identity", {"agents": len(profile.agents), "findings": identity})
    prompts, gaps = prompt_findings(profile)
    ledger.append("scanner", "prompt_rules", {"findings": [{k: f[k] for k in ("kind", "agent", "severity")} for f in prompts],
                                              "gaps": gaps})
    emit({"type": "prompt_findings", "findings": prompts, "gaps": gaps})
    static, fixed = [], []
    if scanner is not None and repo is not None:
        try:
            static = scanner.scan(repo)
        except ScanFailed as error:
            gaps.append(f"the static scan did not complete: {error}")
        languages = getattr(scanner, "languages", None)
        unread = unscanned_sources(repo, languages) if languages is not None else {}
        if unread:
            gaps.append("source no configured scanner reads was not statically checked ("
                        + ", ".join(f"{n} {s}" for s, n in sorted(unread.items())) + " files)")
        ledger.append("scanner", "static", {"findings": [{"kind": f.kind, "file": f.file, "line": f.line,
                                                         "severity": f.severity} for f in static], "gaps": gaps})
        emit({"type": "static_scan", "gaps": gaps, "findings": [
            {"kind": f.kind, "file": display(repo, f.file), "line": f.line, "severity": f.severity, "detail": f.detail,
             "blocking": f.blocking} for f in static]})
        if static and catalog is not None:  # only fixes approved before: no model is called in a static run
            result = await fix_sources(static, repo, scanner, catalog, complete=None, snapshots=snapshots,
                                       ledger=ledger, emit=emit)
            fixed = result.changes
            static = [f for f in static if (f.kind, f.file, f.line) not in result.resolved]
    root = ledger.seal()
    ledger.append("audit", "seal", {"merkle_root": root})
    return {"identity": identity, "prompts": prompts, "static": static, "fixed": fixed, "gaps": gaps,
            "sealed_root": root, "trust": ledger.export_trust()}
