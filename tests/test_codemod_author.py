"""Drafting a candidate fix: structured output only, a skip (never a guess) on anything that
isn't a confident, parseable reply. No real network call — complete() is a fake in every test."""

import asyncio
import json

from purpleteam.codemods.author import draft
from purpleteam.sast import StaticFinding

FINDING = StaticFinding("sql_injection", "vendor.py", 42, "string-built SQL query")


def _draft(reply: str):
    async def fake_complete(system_prompt: str, user_content: str) -> str:
        fake_complete.calls.append((system_prompt, user_content))
        return reply
    fake_complete.calls = []
    result = asyncio.run(draft(FINDING, "cursor.execute(f'SELECT * FROM t WHERE id={x}')", complete=fake_complete))
    return result, fake_complete.calls


def test_a_confident_reply_becomes_a_candidate():
    reply = json.dumps({"replacement": "cursor.execute('SELECT * FROM t WHERE id=?', (x,))",
                        "explanation": "parameterized the query"})
    candidate, calls = _draft(reply)
    assert candidate.kind == "sql_injection"
    assert candidate.replacement == "cursor.execute('SELECT * FROM t WHERE id=?', (x,))"
    assert candidate.explanation == "parameterized the query"
    assert len(calls) == 1 and FINDING.kind in calls[0][1]


def test_a_null_replacement_is_a_skip_not_a_guess():
    reply = json.dumps({"replacement": None, "explanation": "too ambiguous to fix automatically"})
    candidate, _ = _draft(reply)
    assert candidate is None


def test_unparseable_json_is_a_skip():
    candidate, _ = _draft("not json at all")
    assert candidate is None


def test_a_json_array_instead_of_an_object_is_a_skip():
    candidate, _ = _draft(json.dumps(["replacement", "explanation"]))
    assert candidate is None


def test_a_missing_replacement_key_is_a_skip():
    candidate, _ = _draft(json.dumps({"explanation": "no replacement field at all"}))
    assert candidate is None


def test_a_non_string_replacement_is_a_skip():
    candidate, _ = _draft(json.dumps({"replacement": 12345, "explanation": "wrong type"}))
    assert candidate is None


def test_a_missing_explanation_defaults_to_empty():
    reply = json.dumps({"replacement": "fixed_line()"})
    candidate, _ = _draft(reply)
    assert candidate.replacement == "fixed_line()" and candidate.explanation == ""
