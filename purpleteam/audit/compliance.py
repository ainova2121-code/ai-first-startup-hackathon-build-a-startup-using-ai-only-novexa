"""Map audit events to the regulatory controls they provide evidence for.

This is what turns a tamper-evident log into a regulator-ready evidence pack: each event
(an attack, a breach, a patch, a verdict, a seal) is tagged to the clauses it satisfies across
the EU AI Act, NIST AI RMF, DORA, ISO 42001, OWASP LLM, SOC 2 and HIPAA. The mapping is
deliberately conservative — it records which controls an engagement *exercised*, not a
certification.

SOC 2 citations name only the top-level Trust Services Criteria group (CC3 risk assessment, CC6
access, CC7 operations/monitoring, CC8 change management): AICPA's own criteria text is
copyrighted and not reproduced here, and published vendor crosswalks of the finer sub-points
(CC6.1, CC7.2, ...) disagree with each other, so a specific sub-point is not claimed. HIPAA cites
45 CFR Part 164 sections directly, a public federal regulation. Neither framework was written for
AI agents, so — same as EU AI Act/ISO 42001 elsewhere in this mapping — the fit is an informed
analogy, not a quotation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    framework: str
    clause: str
    description: str


_BY_KIND: dict[str, list[Control]] = {
    "attack": [
        Control("EU AI Act", "Art. 15", "Robustness & cybersecurity — adversarial testing"),
        Control("NIST AI RMF", "MEASURE 2.7", "Security and resilience are measured"),
        Control("DORA", "Art. 24-25", "Resilience testing programme: penetration and scenario-based tests"),
        Control("OWASP LLM", "LLM01", "Prompt injection exercised"),
        Control("SOC 2", "CC7", "System operations — vulnerabilities probed before they are exploited in production"),
        Control("HIPAA", "§164.308(a)(8)", "Evaluation — periodic technical testing of security safeguards"),
    ],
    "breach": [
        Control("EU AI Act", "Art. 9", "Risk management — vulnerability identified"),
        Control("HIPAA", "§164.308(a)(6)", "Security incident procedures — a security weakness is identified"),
    ],
    "patch": [
        Control("EU AI Act", "Art. 15", "Mitigation applied"),
        Control("NIST AI RMF", "MANAGE 2.1", "Identified risk is treated"),
        Control("SOC 2", "CC8", "Change management — a remediating change is authorized, tested and applied"),
        Control("HIPAA", "§164.308(a)(1)(ii)(B)", "Risk management — a measure is implemented to reduce the risk"),
    ],
    "verdict": [
        Control("NIST AI RMF", "MEASURE 2.1", "Efficacy of the mitigation is verified"),
        Control("EU AI Act", "Art. 15", "Robustness re-verified after mitigation"),
        Control("DORA", "Art. 24", "Findings remedied and the fix validated as closing the gap"),
        Control("SOC 2", "CC8", "Change management — the change is tested before and confirmed after it is relied on"),
    ],
    "identity": [
        Control("OWASP LLM", "LLM06", "Excessive agency — agent permissions inventoried and checked"),
        Control("PCI SSC AI principles", "Own credentials", "Each agent's credential and access reviewed"),
        Control("SOC 2", "CC6", "Logical access — each agent's permissions and credential reviewed"),
        Control("HIPAA", "§164.308(a)(4)", "Information access management — access is reviewed against what is needed"),
    ],
    "decision": [
        Control("EU AI Act", "Art. 12", "Automatic recording of each AI decision and tool call"),
        Control("NIST AI RMF", "GOVERN 1.1", "Accountability and traceability"),
        Control("ISO 42001", "A.9", "AI system audit trail"),
        Control("SOC 2", "CC7", "System operations — activity is monitored on an ongoing basis"),
        Control("HIPAA", "§164.312(b)", "Audit controls — activity in a system handling records is recorded and examinable"),
    ],
    "tool_result": [
        Control("EU AI Act", "Art. 12", "Automatic recording of the data a tool returned"),
        Control("HIPAA", "§164.312(b)", "Audit controls — what a tool returned is recorded and examinable"),
    ],
    "drill": [
        Control("EU AI Act", "Art. 14", "Human oversight — the ability to intervene and stop the system, tested"),
        Control("NIST AI RMF", "MANAGE 2.4", "Mechanisms to supersede or deactivate the system are tested"),
        Control("SOC 2", "CC7", "System operations — the ability to respond to and contain an incident is tested"),
        Control("HIPAA", "§164.308(a)(6)", "Security incident procedures — the response capability is tested"),
    ],
    "blast_radius": [
        Control("EU AI Act", "Art. 9", "Risk management — risks identified and ranked before deployment"),
        Control("OWASP LLM", "LLM06", "Excessive agency — how far each agent's permissions reach was quantified"),
        Control("SOC 2", "CC3", "Risk assessment — risk is identified and ranked before it is relied on"),
        Control("HIPAA", "§164.308(a)(1)(i)", "Security management process — a risk analysis is conducted"),
    ],
    "seal": [
        Control("EU AI Act", "Art. 12", "Automatic record-keeping / logging"),
        Control("NIST AI RMF", "GOVERN 1.1", "Accountability and traceability"),
        Control("ISO 42001", "A.9", "AI system audit trail"),
        Control("SOC 2", "CC7", "System operations — the activity record is tamper-evident and retained"),
        Control("HIPAA", "§164.312(c)", "Integrity — mechanisms confirm the record has not been altered"),
    ],
}

_BY_PATCH: dict[str, list[Control]] = {
    "P2": [Control("OWASP LLM", "LLM01", "Input prompt-injection defense")],
    "P4": [Control("EU AI Act", "Art. 14", "Human oversight of a consequential action")],
    "P8": [Control("OWASP LLM", "LLM05", "Improper output handling — SQL firewall")],
    "P9": [
        Control("OWASP LLM", "LLM02", "Sensitive information disclosure — output redaction"),
        Control("HIPAA", "§164.312(e)(1)", "Transmission security — sensitive data is stripped before it leaves"),
    ],
    "P10": [
        Control("OWASP LLM", "LLM02", "Sensitive information disclosure — egress guard"),
        Control("HIPAA", "§164.312(e)(1)", "Transmission security — a secret cannot leave through a tool call"),
    ],
    "P11": [
        Control("OWASP LLM", "LLM06", "Excessive agency — each agent limited to its permitted tools"),
        Control("PCI SSC AI principles", "Least privilege", "AI access limited to what the use case needs"),
        Control("SOC 2", "CC6", "Logical access — each agent limited to its permitted tools"),
        Control("HIPAA", "§164.312(a)(1)", "Access control — each agent limited to its permitted tools"),
    ],
}


def controls_for(event: dict) -> list[Control]:
    controls = list(_BY_KIND.get(event.get("kind", ""), []))
    payload = event.get("payload") or {}
    if event.get("kind") == "patch":
        for patch_id in payload.get("patch_ids", []):
            controls += _BY_PATCH.get(patch_id, [])
    if event.get("kind") == "decision" and payload.get("verdict") in ("blocked", "withheld"):
        controls.append(Control("OWASP LLM", "LLM06", "Excessive agency — an out-of-policy action was stopped at runtime"))
    return controls


def evidence_report(events: list[dict]) -> dict[str, dict]:
    """Clause -> {control, the event seqs that provide evidence for it}."""
    coverage: dict[str, dict] = {}
    for event in events:
        for control in controls_for(event):
            key = f"{control.framework} · {control.clause}"
            entry = coverage.setdefault(key, {"control": control, "events": []})
            entry["events"].append(event.get("seq"))
    return coverage
