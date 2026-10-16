"""Render an AssessmentReport as a Markdown document a compliance officer can hand to an auditor.

``to_dict()`` already gives the raw evidence as JSON; this turns the same data into something readable,
organised the way an auditor actually works: what was found, what was done about it, which regulatory
clauses that evidences, and — the part a vendor's own say-so can't provide — exact instructions for
verifying the whole thing independently, without trusting us. Nothing here computes new evidence; it only
presents what the assessment and ``audit.compliance`` already produced.

Markdown, not PDF or HTML: it renders cleanly as-is, diffs and version-controls like any other document, and
converts to PDF or HTML with any standard tool if a customer wants that. Building a document generator is out
of scope for this project; formatting plain text well enough to hand to a person is not.
"""

from __future__ import annotations

from purpleteam.identity import DRIFT_KINDS, SCOPE_KINDS

ANCHORED_NOTE = (
    "This checkpoint is also anchored to one or more outside timestamp authorities (RFC 3161), proving the "
    "assessment existed by the anchored time even to a party that does not trust this organisation's clock."
)

def render(report) -> str:
    """``report``: an ``assessment.AssessmentReport``. Returns a self-contained Markdown document."""
    sections = [
        _header(report),
        _verification_instructions(report),
        _boundary_compliance(report),
        _findings(report),
        _coverage(report),
        _limits(report),
    ]
    return "\n\n".join(s for s in sections if s)


def _header(report) -> str:
    verdict = "SAFE TO SHIP" if report.safe_to_ship else "NOT SAFE TO SHIP"
    lines = [
        f"# Compliance Evidence Report — {report.target}",
        "",
        f"**Verdict:** {verdict}",
        f"**Findings:** {len(report.findings)}",
        f"**Log integrity (checked internally):** {'intact' if report.chain_ok else 'FAILED — do not rely on this report'}",
    ]
    checkpoint = report.trust.get("checkpoint")
    if checkpoint:
        lines.append(f"**Sealed at:** {checkpoint['size']} events, Merkle root `{checkpoint['root'][:16]}…`")
    if report.anchor_errors:
        lines.append(f"**Timestamp anchoring:** requested but failed ({'; '.join(report.anchor_errors)})")
    elif report.trust.get("anchors"):
        lines.append(f"**Timestamp anchoring:** confirmed by {len(report.trust['anchors'])} authority(ies)")
    return "\n".join(lines)


def _verification_instructions(report) -> str:
    checkpoint = report.trust.get("checkpoint")
    if not checkpoint:
        return ""
    keys = report.trust.get("keys", {})
    key_lines = "\n".join(f"  - `{actor}`: key id `{kid}`" for actor, by_kid in keys.items() for kid in by_kid)
    anchored_note = f"\n\n{ANCHORED_NOTE}" if report.trust.get("anchors") else ""
    return (
        "## Verify this report independently\n\n"
        "This report is generated from a signed, tamper-evident audit log — a hash chain per actor, folded into "
        "a Merkle root and signed with a hybrid post-quantum key pair. Nobody has to take our word for it:\n\n"
        "1. Obtain the raw event log and the trust bundle pinned below (keep them separate — that separation is "
        "what makes tampering detectable).\n"
        "2. Run `purpleteam.audit.verify.verify_log(events, trust)`.\n"
        "3. `ok=True` and `anchored=True` means no event was added, removed, reordered or altered after it was "
        f"signed, and the checkpoint committing to all {checkpoint['size']} events was itself signed by the keys "
        "below — not asserted by us after the fact.\n\n"
        f"**Pinned trust bundle** (store apart from the log):\n{key_lines}\n"
        f"  - Checkpoint: size={checkpoint['size']}, root=`{checkpoint['root']}`, "
        f"signed at {checkpoint['ts']}{anchored_note}"
    )


def _boundary_compliance(report) -> str:
    """Whether each agent's deployed tools matched its declared scope and its last baseline — proven by checking
    the discovered setup itself, not inferred from whether an attack happened to stumble onto a violation. This
    is recorded every time, clean or not (see ``Assessment._check_identity``), so the record below is never
    silence standing in for "nothing to report"."""
    identity = report.identity
    if not identity:
        return ""
    manifest_state = ("a declared permission manifest" if identity["manifest"] == "declared"
                      else "no declared manifest (inferred from what each agent holds)")
    baseline_state = "checked against a saved baseline" if report.baseline_checked else "no baseline was supplied for comparison"
    by_agent: dict[str, list[dict]] = {}
    for finding in identity["findings"]:
        for name in finding["agent"].split(","):  # a shared-credential finding names more than one agent
            by_agent.setdefault(name, []).append(finding)
    rows = [
        "## Agent boundary compliance", "",
        f"Checked against {manifest_state}; {baseline_state}.", "",
        "| Agent | Tools | In declared scope | Matches baseline |", "|---|---|---|---|",
    ]
    for agent in identity["agents"]:
        findings = by_agent.get(agent["name"], [])
        in_scope = "**NO — see findings**" if any(f["kind"] in SCOPE_KINDS for f in findings) else "yes"
        if not report.baseline_checked:
            matches = "not checked"
        else:
            matches = "**NO — see findings**" if any(f["kind"] in DRIFT_KINDS for f in findings) else "yes"
        rows.append(f"| {agent['name']} | {len(agent['tools'])} | {in_scope} | {matches} |")
    return "\n".join(rows)


def _findings(report) -> str:
    if not report.findings:
        return "## Findings\n\nNo vulnerabilities were proven in this assessment."
    rows = ["## Findings", ""]
    verified = report.verification
    for finding in report.findings:
        if finding.source == "static":
            rows.append(f"### {finding.kind} — found by reading the source")
        else:
            rows.append(f"### {finding.kind} — `{finding.tool}` ({finding.agent or 'unknown agent'})")
        rows.append(finding.detail)
        if finding.signals:
            named = ", ".join(sorted({f"{s.scorer} ({s.pattern})" for s in finding.signals}))
            rows.append(f"- **Additional pattern evidence:** {named}")
        if report.defense:
            rows.append(f"- **Patched with:** {', '.join(report.defense.patch_ids) or 'nothing — see limits below'}")
        if verified:
            legit = "preserved" if verified.legit_passed else "BROKEN"
            if finding.source == "static":
                rows.append(f"- **Patched; legitimate behaviour {legit}** (found by reading the source — no "
                            "working payload exists to replay and confirm the attack itself is blocked)")
            else:
                held = "held" if verified.attack_blocked else "NOT held"
                rows.append(f"- **Re-verified after the patch:** attack {held}; legitimate behaviour {legit}")
        rows.append("")
    return "\n".join(rows).rstrip()


def _coverage(report) -> str:
    """``report.coverage`` keys are ``"<framework> · <clause>"`` strings (see ``assessment._seal``), each
    holding only a description and the evidencing event numbers — the framework is parsed back out of the key."""
    if not report.coverage:
        return ""
    by_framework: dict[str, list[tuple[str, dict]]] = {}
    for key, entry in report.coverage.items():
        framework, _, clause = key.partition(" · ")
        by_framework.setdefault(framework or key, []).append((clause or key, entry))
    rows = ["## Regulatory coverage", "",
           "Which controls this assessment exercised, and the exact signed events that evidence each one. This "
           "records what was tested, never a certification.", ""]
    for framework in sorted(by_framework):
        rows.append(f"### {framework}")
        rows.append("| Clause | Description | Evidence (event #) |")
        rows.append("|---|---|---|")
        for clause, entry in sorted(by_framework[framework], key=lambda item: item[0]):
            events = ", ".join(str(seq) for seq in entry["events"][:6])
            if len(entry["events"]) > 6:
                events += f", +{len(entry['events']) - 6} more"
            rows.append(f"| {clause} | {entry['description']} | {events} |")
        rows.append("")
    return "\n".join(rows).rstrip()


def _limits(report) -> str:
    notes = []
    if report.scope:
        notes.append(f"- Scoped to: {', '.join(report.scope.get('focus') or ['default corpus'])}" +
                     (f", agent `{report.scope['agent']}`" if report.scope.get("agent") else ""))
        for topic, reason in (report.scope.get("skipped") or {}).items():
            notes.append(f"- **Not tested** ({topic}): {reason}")
    for assumption in (report.blast.get("assumptions") or []):
        notes.append(f"- Blast-radius assumption: {assumption}")
    if report.verification and report.verification.errored:
        notes.append("- **The verification step itself hit an error** — see `verification.errors`; not proof of safety")
    if any(f.source == "static" for f in report.findings):
        notes.append("- Findings found by reading the source were not dynamically re-exploited after patching — "
                     "there is no working attack payload to replay for them, only the patch and the "
                     "legitimate-behaviour check")
    if not notes:
        return ""
    return "## What this report does not cover\n\n" + "\n".join(notes)
