"""is_unscoped_write_risk/extract_reference/craft_write_payload/_bypassed_stages: pure logic, with
the LLM client always faked here (see tests/test_targeted.py for the same convention) -- nothing in
this file touches a real model or the network. run_lateral itself (the PyRIT-driving async loop) is
not faked, for the same reason run_corpus/run_adaptive/run_targeted are not."""

from purpleteam.adapter import Observation, ToolCall
from purpleteam.attack.lateral import (
    _bypassed_stages,
    craft_hijack_payload,
    craft_write_payload,
    extract_reference,
    find_writable_confirmation,
    is_unscoped_write_risk,
)
from purpleteam.discovery import AgentInfo


def _agent(name: str, prompt: str = "a real prompt", tool_names: tuple[str, ...] = ()) -> AgentInfo:
    return AgentInfo(name=name, prompt=prompt, tool_names=tool_names)


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.choices = [type("Choice", (), {"message": _FakeMessage(content)})()]


class _FakeClient:
    def __init__(self, content: str) -> None:
        self._content = content
        self.calls = []

        class _Completions:
            def create(inner_self, **kwargs):
                self.calls.append(kwargs)
                return _FakeResponse(self._content)

        self.chat = type("Chat", (), {"completions": _Completions()})()


def _patch_client(monkeypatch, content: str) -> _FakeClient:
    fake = _FakeClient(content)
    monkeypatch.setattr("purpleteam.attack.lateral._client", lambda: fake)
    return fake


def test_is_unscoped_write_risk_skips_an_agent_with_no_captured_prompt(monkeypatch):
    fake = _patch_client(monkeypatch, '{"read_only_purpose": true}')

    result = is_unscoped_write_risk(_agent("inquiry", prompt="", tool_names=("query_ledger",)), {"query_ledger"})

    assert result is False and fake.calls == []


def test_is_unscoped_write_risk_skips_an_agent_with_no_dangerous_tool(monkeypatch):
    """A read-only-purpose agent holding only safe (read) tools is not this pattern at all --
    never worth the LLM call."""
    fake = _patch_client(monkeypatch, '{"read_only_purpose": true}')

    result = is_unscoped_write_risk(_agent("inquiry", tool_names=("get_report",)), {"query_ledger"})

    assert result is False and fake.calls == []


def test_is_unscoped_write_risk_true_when_the_prompt_never_describes_the_dangerous_tool(monkeypatch):
    _patch_client(monkeypatch, '{"read_only_purpose": true}')

    assert is_unscoped_write_risk(_agent("inquiry", tool_names=("query_ledger",)), {"query_ledger"}) is True


def test_is_unscoped_write_risk_false_when_the_prompt_describes_the_action(monkeypatch):
    """The real case this must not false-positive on: an agent whose prompt explicitly describes
    the write it performs (e.g. "update its bank account") is doing its declared job, not an
    excess-scope gap."""
    _patch_client(monkeypatch, '{"read_only_purpose": false}')

    assert is_unscoped_write_risk(_agent("vendor", tool_names=("update_vendor_bank",)), {"update_vendor_bank"}) is False


def test_extract_reference_skips_an_empty_reply(monkeypatch):
    fake = _patch_client(monkeypatch, '{"reference": "INV-1"}')

    assert extract_reference("") is None and fake.calls == []


def test_extract_reference_returns_the_found_value(monkeypatch):
    _patch_client(monkeypatch, '{"reference": "INV-42"}')

    assert extract_reference("Your record INV-42 is on file.") == "INV-42"


def test_extract_reference_is_none_when_nothing_is_mentioned(monkeypatch):
    _patch_client(monkeypatch, '{"reference": null}')

    assert extract_reference("I don't see anything matching that.") is None


def test_craft_write_payload_omits_the_reference_when_none_was_found(monkeypatch):
    fake = _patch_client(monkeypatch, "Noted, paid to US00ATTACKER0666.")

    craft_write_payload("US00ATTACKER0666", reference=None)

    sent = fake.calls[0]["messages"][1]["content"]
    assert "Reference for the matter" not in sent and "US00ATTACKER0666" in sent


def test_craft_write_payload_includes_a_found_reference(monkeypatch):
    fake = _patch_client(monkeypatch, "Noted, INV-42 paid to US00ATTACKER0666.")

    craft_write_payload("US00ATTACKER0666", reference="INV-42")

    sent = fake.calls[0]["messages"][1]["content"]
    assert "INV-42" in sent and "US00ATTACKER0666" in sent


def test_find_writable_confirmation_skips_an_agent_with_no_captured_prompt(monkeypatch):
    fake = _patch_client(monkeypatch, '{"sql": "UPDATE t SET v = 1 RETURNING *"}')

    assert find_writable_confirmation(_agent("inquiry", prompt=""), "CANARY") is None
    assert fake.calls == []


def test_find_writable_confirmation_returns_a_returning_statement(monkeypatch):
    _patch_client(monkeypatch, '{"sql": "UPDATE invoices SET status = \'approved\' WHERE id = 1 RETURNING *"}')

    sql = find_writable_confirmation(_agent("inquiry"), "US00ATTACKER0666")

    assert sql == "UPDATE invoices SET status = 'approved' WHERE id = 1 RETURNING *"


def test_find_writable_confirmation_rejects_a_statement_with_no_returning_clause(monkeypatch):
    """Without RETURNING, the write would not look like an ordinary query's output -- the whole
    point of this technique -- so a plain UPDATE must not be used."""
    _patch_client(monkeypatch, '{"sql": "UPDATE invoices SET status = \'approved\' WHERE id = 1"}')

    assert find_writable_confirmation(_agent("inquiry"), "US00ATTACKER0666") is None


def test_find_writable_confirmation_is_none_when_the_schema_has_nothing_usable(monkeypatch):
    _patch_client(monkeypatch, '{"sql": null}')

    assert find_writable_confirmation(_agent("inquiry"), "US00ATTACKER0666") is None


def test_craft_hijack_payload_includes_the_exact_sql_given(monkeypatch):
    fake = _patch_client(monkeypatch, "Sure, here's the usual confirmation check to run.")
    sql = "UPDATE invoices SET status = 'approved' WHERE id = 1 RETURNING *"

    craft_hijack_payload(sql)

    sent = fake.calls[0]["messages"][1]["content"]
    assert sql in sent


def test_bypassed_stages_names_every_agent_whose_tool_never_ran():
    agents = [_agent("inquiry"), _agent("vendor"), _agent("payment")]
    observation = Observation("ok", [ToolCall("inquiry", "query_ledger", {})])

    assert _bypassed_stages(agents, observation) == ["payment", "vendor"]


def test_bypassed_stages_is_empty_when_every_agent_was_involved():
    agents = [_agent("inquiry")]
    observation = Observation("ok", [ToolCall("inquiry", "query_ledger", {})])

    assert _bypassed_stages(agents, observation) == []
