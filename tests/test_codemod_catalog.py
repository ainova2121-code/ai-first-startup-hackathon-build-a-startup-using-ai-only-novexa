"""The approved-codemod catalog: persisted, keyed by the exact pattern it was proven against,
never reused for a different piece of code just because the finding kind matches."""

from purpleteam.codemods.base import VerifiedCodemod
from purpleteam.codemods.catalog import CodemodCatalog, pattern_key

CODEMOD = VerifiedCodemod("sql_injection", "cursor.execute(f'...')", "cursor.execute('...', (x,))", "parameterized")


def test_approve_then_get_round_trips(tmp_path):
    catalog = CodemodCatalog(tmp_path)
    key = pattern_key(CODEMOD.kind, CODEMOD.original)
    assert catalog.get(key) is None

    catalog.approve(key, CODEMOD)
    assert catalog.get(key) == CODEMOD


def test_persists_across_catalog_instances(tmp_path):
    key = pattern_key(CODEMOD.kind, CODEMOD.original)
    CodemodCatalog(tmp_path).approve(key, CODEMOD)
    reopened = CodemodCatalog(tmp_path)
    assert reopened.get(key) == CODEMOD


def test_pattern_key_is_stable_and_distinguishes_different_originals():
    a = pattern_key("sql_injection", "cursor.execute(f'A')")
    b = pattern_key("sql_injection", "cursor.execute(f'A')")
    c = pattern_key("sql_injection", "cursor.execute(f'B')")
    assert a == b and a != c


def test_pattern_key_distinguishes_different_kinds_for_the_same_text():
    a = pattern_key("sql_injection", "same text")
    b = pattern_key("shell_command", "same text")
    assert a != b


def test_an_unknown_key_returns_none(tmp_path):
    assert CodemodCatalog(tmp_path).get("never-approved") is None
