"""Audit events map to the regulatory controls they evidence."""

from purpleteam.audit.compliance import controls_for, evidence_report


def test_attack_evidences_robustness():
    controls = controls_for({"kind": "attack", "payload": {}})
    assert any(c.framework == "EU AI Act" and c.clause == "Art. 15" for c in controls)
    dora = [c for c in controls if c.framework == "DORA"]
    assert [c.clause for c in dora] == ["Art. 24-25"]
    assert "threat-led" not in dora[0].description.lower()  # threat-led testing is Arts. 26-27, not claimed


def test_verified_fix_evidences_dora_remediation_validation():
    controls = controls_for({"kind": "verdict", "payload": {}})
    assert any(c.framework == "DORA" and c.clause == "Art. 24" for c in controls)


def test_patch_with_p4_adds_human_oversight():
    controls = controls_for({"kind": "patch", "payload": {"patch_ids": ["P2", "P4"]}})
    clauses = {c.clause for c in controls}
    assert "Art. 14" in clauses  # P4 -> human oversight
    assert "LLM01" in clauses  # P2 -> injection defense


def test_evidence_report_aggregates_events_by_clause():
    events = [
        {"seq": 0, "kind": "attack", "payload": {}},
        {"seq": 1, "kind": "patch", "payload": {"patch_ids": ["P4"]}},
        {"seq": 2, "kind": "seal", "payload": {}},
    ]
    report = evidence_report(events)
    assert any("Art. 12" in key for key in report)  # seal -> record-keeping
    oversight = report["EU AI Act · Art. 14"]
    assert oversight["events"] == [1]


def test_soc2_cites_only_the_top_level_group_never_an_invented_sub_point():
    for kind in ("attack", "patch", "verdict", "identity", "decision", "drill", "blast_radius", "seal"):
        controls = controls_for({"kind": kind, "payload": {}})
        soc2 = [c for c in controls if c.framework == "SOC 2"]
        assert soc2, kind  # every one of our own event kinds has a SOC 2 story
        for c in soc2:
            assert c.clause in ("CC3", "CC6", "CC7", "CC8")  # a bare group id, no fabricated sub-point like "CC7.2"


def test_hipaa_cites_a_real_45_cfr_164_section_for_the_audit_trail_events():
    for kind in ("decision", "tool_result", "seal"):
        controls = controls_for({"kind": kind, "payload": {}})
        hipaa = {c.clause for c in controls if c.framework == "HIPAA"}
        assert hipaa  # the audit-trail events all cite something
        assert all(c.startswith("§164.3") for c in hipaa)


def test_p9_and_p10_evidence_hipaa_transmission_security():
    controls = controls_for({"kind": "patch", "payload": {"patch_ids": ["P9", "P10"]}})
    transmission = {(c.clause, c.description) for c in controls
                    if c.framework == "HIPAA" and c.clause == "§164.312(e)(1)"}
    assert len(transmission) == 2  # P9 and P10 each get their own description under the same clause, not merged away
    # the "patch" event itself also evidences risk management (§164.308), on top of the two patch-specific ones
    assert {c.clause for c in controls if c.framework == "HIPAA"} == {"§164.312(e)(1)", "§164.308(a)(1)(ii)(B)"}


def test_p11_least_privilege_evidences_both_soc2_access_and_hipaa_access_control():
    controls = controls_for({"kind": "patch", "payload": {"patch_ids": ["P11"]}})
    assert any(c.framework == "SOC 2" and c.clause == "CC6" for c in controls)
    assert any(c.framework == "HIPAA" and c.clause == "§164.312(a)(1)" for c in controls)


def test_soc2_and_hipaa_show_up_in_the_aggregated_evidence_report():
    events = [{"seq": 0, "kind": "seal", "payload": {}}, {"seq": 1, "kind": "identity", "payload": {}}]
    report = evidence_report(events)
    assert "SOC 2 · CC7" in report and report["SOC 2 · CC7"]["events"] == [0]
    assert "HIPAA · §164.312(c)" in report and report["HIPAA · §164.312(c)"]["events"] == [0]
    assert "HIPAA · §164.308(a)(4)" in report and report["HIPAA · §164.308(a)(4)"]["events"] == [1]
