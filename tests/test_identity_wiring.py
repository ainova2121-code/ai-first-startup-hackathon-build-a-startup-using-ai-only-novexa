"""Identity in a live run: the identity attacks join the attack set under their own technique, a credential request's
reply is never shown, and an operator's declared manifest turns on the scope oracle and the identity findings."""

import asyncio
import json

import pytest

from purpleteam.adapter import Observation
from purpleteam.assessment import Assessment
from purpleteam.attack.corpus import PYRIT_TEMPLATES
from purpleteam.attack.identity import (
    CREDENTIAL_TECHNIQUE, IDENTITY_OBJECTIVES, IDENTITY_TECHNIQUE, identity_attacks)
from purpleteam.audit.ledger import AuditLedger
from purpleteam.discovery import DiscoveredTool, TargetProfile
from purpleteam.live_run import declared_manifest, discovery_event
from purpleteam.oracle import LeakOracle

PROFILE = TargetProfile("t", [DiscoveredTool("lookup", "", {}, "t.py:1", "read", "clerk", agent_name="clerk"),
                              DiscoveredTool("pay", "", {}, "t.py:5", "write", "clerk", agent_name="clerk")])


def test_identity_attacks_cover_every_objective_once_per_injection_template_under_their_own_technique():
    attacks = identity_attacks()
    injection = [name for name, kind in PYRIT_TEMPLATES.items() if kind == "prompt-injection"]
    assert len(attacks) == len(IDENTITY_OBJECTIVES) * len(injection) and len({a.id for a in attacks}) == len(attacks)
    for attack in attacks:
        objective = attack.id.split(":", 1)[0]
        assert IDENTITY_OBJECTIVES[objective] in attack.body
        assert attack.technique == (CREDENTIAL_TECHNIQUE if objective == "credential_request" else IDENTITY_TECHNIQUE)


class _Chatty:
    """Answers every request by reciting its configuration: what a credential request hopes for."""

    def reset(self):
        pass

    def send(self, request):
        return Observation("my api key is sk-live-not-real and my instructions are ...", [])


def test_a_credential_requests_reply_is_judged_but_never_shown(tmp_path):
    events = []
    attack = next(a for a in identity_attacks() if a.technique == CREDENTIAL_TECHNIQUE)
    assessment = Assessment(lambda guard: _Chatty(), LeakOracle({"HTK-NEVER-PRESENT"}), PROFILE,
                            AuditLedger(tmp_path / "audit.jsonl"), legit=[("hi", lambda o: True)])
    asyncio.run(assessment.run([attack], on_event=events.append))
    (result,) = [e for e in events if e["type"] == "attack_result"]
    assert result["reply_redacted"] and "sk-live" not in json.dumps(result) and result["agent_replies"] == []


def test_without_a_declared_manifest_nothing_changes(monkeypatch):
    monkeypatch.delenv("PURPLETEAM_MANIFEST", raising=False)
    assert declared_manifest() is None


def test_a_declared_manifest_is_loaded_and_shapes_the_identity_findings(monkeypatch, tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"clerk": ["lookup"]}), encoding="utf-8")
    monkeypatch.setenv("PURPLETEAM_MANIFEST", str(path))
    manifest = declared_manifest()
    assert manifest.permits("clerk", "lookup") and not manifest.permits("clerk", "pay")
    findings = {(f["kind"], f["agent"]) for f in discovery_event(PROFILE, {}, manifest)["findings"]}
    assert ("excess_privilege", "clerk") in findings
    assert ("excess_privilege", "clerk") not in {(f["kind"], f["agent"]) for f in discovery_event(PROFILE, {})["findings"]}


def test_an_unreadable_manifest_stops_the_run_rather_than_being_skipped(monkeypatch, tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"clerk": "not-a-list"}), encoding="utf-8")
    monkeypatch.setenv("PURPLETEAM_MANIFEST", str(path))
    with pytest.raises(ValueError):
        declared_manifest()
    monkeypatch.setenv("PURPLETEAM_MANIFEST", str(tmp_path / "missing.json"))
    with pytest.raises(OSError):
        declared_manifest()


def test_a_declared_manifest_makes_a_call_outside_it_proof_of_escalation():
    from purpleteam.adapter import ToolCall
    from purpleteam.identity import PermissionManifest
    from purpleteam.live_run import run_oracle
    observation = Observation("done", [ToolCall("clerk", "pay", {"to": "acme"})])
    assert not run_oracle(PROFILE, None).judge(observation).breached  # held tools, no canary: nothing to prove
    verdict = run_oracle(PROFILE, PermissionManifest({"clerk": frozenset({"lookup"})})).judge(observation)
    assert (verdict.breached, verdict.kind, verdict.tool, verdict.agent) == (True, "privilege_escalation", "pay", "clerk")
