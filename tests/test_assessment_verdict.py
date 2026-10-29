"""The release verdict: safe to ship only when nothing blocks it, and every blocker is named exactly once."""



from purpleteam.assessment import AssessmentReport
from purpleteam.attack.corpus import CorpusResult


def test_no_attacks_run_is_never_safe_to_ship_even_with_no_findings():
    """An assessment that tested nothing proves nothing; it must not read as a clean bill."""
    assert AssessmentReport("fake", []).safe_to_ship is False


def test_every_attack_inconclusive_is_never_safe_to_ship():
    stuck = CorpusResult("dan_1", "jailbreak", False, "not tested: timed out", outcome="inconclusive")
    assert AssessmentReport("fake", [stuck], chain_ok=True).safe_to_ship is False


def test_one_inconclusive_attack_among_held_ones_is_still_never_safe_to_ship():
    """A mix of held and inconclusive is not a clean run: the inconclusive attempt proved
    nothing, so the run as a whole cannot be read as a clean bill, even with zero findings."""
    held = CorpusResult("dan_1", "jailbreak", False, "no breach", outcome="held")
    stuck = CorpusResult("aim", "jailbreak", False, "not tested: timed out", outcome="inconclusive")
    report = AssessmentReport("fake", [held, stuck], chain_ok=True)
    assert report.safe_to_ship is False
    # Found in a live run: the verdict said "not safe" while the page listed no reason at all.
    assert report.blockers() == ["attack aim was inconclusive (not tested: timed out): untested is not safe"]


def test_the_verdict_is_exactly_the_absence_of_blockers_and_each_reason_is_named_once():
    held = CorpusResult("dan_1", "jailbreak", False, "no breach", outcome="held")
    report = AssessmentReport("fake", [held], chain_ok=False, coverage_gaps=["the static scan did not complete: x"],
                              decision_drift=[{"severity": "high"}, {"severity": "low"}])
    assert report.blockers() == ["the audit chain does not verify", "the static scan did not complete: x",
                                 "policy-decision drift: 1 approved decision(s) on verified attack input "
                                 "(or redaction) would be looser under this run's policy"]
    assert report.safe_to_ship is False and AssessmentReport("fake", [held], chain_ok=True).blockers() == []


def test_at_least_one_conclusive_attack_with_no_findings_is_safe_to_ship():
    held = CorpusResult("dan_1", "jailbreak", False, "no breach", outcome="held")
    assert AssessmentReport("fake", [held], chain_ok=True).safe_to_ship is True


def test_a_broken_audit_chain_is_never_safe_to_ship_even_with_a_clean_attack_run():
    """The release verdict must not stand on evidence that cannot itself be trusted."""
    held = CorpusResult("dan_1", "jailbreak", False, "no breach", outcome="held")
    assert AssessmentReport("fake", [held], chain_ok=False).safe_to_ship is False
