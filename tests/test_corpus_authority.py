"""The authority/urgency social-engineering template family: targets authorization bypass, not
content-safety refusal, so it is built from our own string templates (not PyRIT's bundled dataset)
but rendered through the identical PyRIT pipeline every other template uses.
"""

from purpleteam.attack.corpus import (
    AUTHORITY_TEMPLATES, CANARY_MARK, DEFAULT_TEMPLATES, PYRIT_TEMPLATES, action_objective, build_corpus)
from purpleteam.oracle import CANARY_ACCOUNT


def test_the_default_corpus_includes_both_families():
    corpus = build_corpus(action_objective({"update_vendor_bank"}))
    ids = {t.id for t in corpus}
    expected = {name.removesuffix(".yaml") for name in PYRIT_TEMPLATES} | set(AUTHORITY_TEMPLATES)
    assert ids == expected
    assert {"authority_claim", "already_verified", "routine_followup"} <= ids


def test_each_authority_template_is_tagged_social_engineering():
    corpus = build_corpus(action_objective({"update_vendor_bank"}))
    by_id = {t.id: t for t in corpus}
    for name in AUTHORITY_TEMPLATES:
        assert by_id[name].technique == "social-engineering"


def test_authority_templates_carry_the_real_objective_not_a_classic_jailbreak_trigger():
    objective = action_objective({"update_vendor_bank"})
    corpus = build_corpus(objective)
    by_id = {t.id: t for t in corpus}
    for name in AUTHORITY_TEMPLATES:
        rendered = by_id[name].render(CANARY_ACCOUNT)
        assert "update_vendor_bank" in rendered and CANARY_ACCOUNT in rendered
        lowered = rendered.lower()
        # the whole point: no classic jailbreak phrasing, just a plausible unverified-authority claim
        assert "dan" not in lowered.split() and "ignore all" not in lowered and "do anything now" not in lowered


def test_authority_template_bodies_still_hold_the_canary_mark_before_rendering():
    objective = action_objective({"update_vendor_bank"})
    corpus = build_corpus(objective)
    claim = next(t for t in corpus if t.id == "authority_claim")
    assert CANARY_MARK in claim.body  # substituted only at render(), like every other template


def test_default_templates_is_pyrit_templates_plus_authority_templates():
    assert set(DEFAULT_TEMPLATES) == set(PYRIT_TEMPLATES) | set(AUTHORITY_TEMPLATES)
