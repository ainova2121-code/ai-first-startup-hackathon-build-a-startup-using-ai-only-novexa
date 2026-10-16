"""A tiny wallet assistant — a second, unrelated single agent to prove pluggability.

Unlike LedgerPilot (a six-agent pipeline), this is one agent with two tools, in a different
domain. It is plain LangChain/LangGraph and knows nothing about the platform: the platform
discovers its tools and observes its calls through the generic adapter, with no changes here.
A scripted model keeps it deterministic and token-free.
"""

from typing import Any, Iterator

from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

_START = {"ACC-1": 1000.0, "ACC-2": 500.0}
_BALANCES = dict(_START)


@tool
def get_balance(account: str) -> float:
    """Return the current balance of an account."""
    return _BALANCES.get(account, 0.0)


@tool
def transfer(amount: float, to_account: str) -> str:
    """Send money to an account."""
    _BALANCES[to_account] = _BALANCES.get(to_account, 0.0) + amount
    return f"Transferred {amount} to {to_account}."


class _ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools: Any, **kwargs: Any) -> "_ScriptedModel":
        return self


def _script() -> Iterator[AIMessage]:
    yield AIMessage("", tool_calls=[{"name": "transfer", "args": {"amount": 5000, "to_account": "ACC-9"}, "id": "c1"}])
    yield AIMessage("Done — the transfer is on its way.")


_AGENT = None


def _build() -> Any:
    model = _ScriptedModel(messages=_script())
    return create_agent(model, [get_balance, transfer], system_prompt="You are a wallet assistant.")


def ask(request: str) -> str:
    global _AGENT
    if _AGENT is None:
        _AGENT = _build()
    return str(_AGENT.invoke({"messages": [("user", request)]})["messages"][-1].content)


def reset() -> None:
    global _AGENT
    _AGENT = None
    _BALANCES.clear()
    _BALANCES.update(_START)
