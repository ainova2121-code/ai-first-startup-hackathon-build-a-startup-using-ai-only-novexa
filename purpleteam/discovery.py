"""Discover a target's tools and classify their risk — domain-agnostic.

Given a target's entry point (``package.module:callable``), we import it and scan the
modules under its package for LangChain tool objects (``BaseTool`` — what ``@tool``,
``create_agent``, LangGraph and most agent frameworks produce). Risk is classified by what a
tool does to the world, not by any domain: a tool either only reads, or it has a side effect
(writes state, deletes, executes code, or contacts the outside). Nothing here knows about
money, invoices, or any specific domain.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

# Generic capability classes, ordered most-dangerous first. "read" is the only safe one.
READ, WRITE, DELETE, EXECUTE, EXTERNAL = "read", "write", "delete", "execute", "external"
RISKS = (READ, WRITE, DELETE, EXECUTE, EXTERNAL)

_WRITE_VERBS = {"create", "update", "set", "edit", "modify", "register", "save", "add",
                "change", "replace", "insert", "schedule", "issue", "grant", "assign",
                "approve", "confirm", "submit", "book", "order", "write", "upload",
                "enable", "disable", "reset", "rename", "move", "apply", "store", "put"}
_DELETE_VERBS = {"delete", "drop", "remove", "truncate", "purge", "revoke", "cancel",
                 "wipe", "clear", "destroy", "erase"}
_EXECUTE_VERBS = {"execute", "run", "eval", "exec", "invoke", "compile", "execution", "bash", "shell", "terminal",
                  "powershell"}
_EXTERNAL_VERBS = {"send", "email", "post", "notify", "publish", "fetch", "request",
                   "webhook", "dispatch", "forward", "transfer", "share", "sms"}
_READ_VERBS = {"get", "list", "find", "lookup", "search", "show", "view", "read",
               "check", "retrieve", "count", "describe", "load", "extract", "parse", "compute",
               "calculate", "validate", "verify", "summarize", "analyze", "compare", "inspect",
               "classify", "detect", "estimate", "scan", "explain"}
_EXECUTE_ARGS = {"sql", "query", "code", "command", "cmd", "script", "expression", "statement"}
_CLASS_VERBS = ((_EXECUTE_VERBS, "execute"), (_DELETE_VERBS, "delete"),
                (_EXTERNAL_VERBS, "external"), (_WRITE_VERBS, "write"), (_READ_VERBS, "read"))


def load_callable(ref: str) -> Any:
    """``"pkg.module:attr"`` -> the attribute."""
    module_name, _, attr = ref.partition(":")
    obj: Any = importlib.import_module(module_name)
    for part in attr.split("."):
        obj = getattr(obj, part)
    return obj


def _tokens(text: str) -> list[str]:
    spaced = re.sub(r"([a-z])([A-Z])", r"\1_\2", text or "")
    return [w for w in re.split(r"[^a-zA-Z]+", spaced.lower()) if w]


name_tokens = _tokens  # the words in a tool or agent name, for code that reasons about what a name suggests


def _words(*texts: str) -> set[str]:
    out: set[str] = set()
    for text in texts:
        out |= set(_tokens(text))
    return out


@dataclass(frozen=True)
class DiscoveredTool:
    name: str
    description: str
    args: dict[str, dict]
    source: str
    risk: str
    module: str
    tool: Any = field(repr=False, default=None)
    agent_name: str = ""  # set when the tool was seen being given to a named agent
    risk_by: str = "name"  # "name": guessed from the tool's name; "operator": set by a person

    @property
    def dangerous(self) -> bool:
        return self.risk != READ

    @property
    def agent(self) -> str:
        return self.agent_name or self.module.rsplit(".", 1)[-1]


@dataclass(frozen=True)
class AgentInfo:
    """An agent seen being built: its name, the system prompt it was given and the tools it holds.

    The prompt is kept so the platform can reason about the agent's purpose, but it is target data
    and may hold secrets: reports and logs use ``prompt_sha256`` and ``prompt_chars``, never the text.
    """

    name: str
    prompt: str = field(repr=False)
    tool_names: tuple[str, ...] = ()
    authenticated: bool | None = None  # True: its key says who it is. False: guessed. None: not known (in-process)
    claimed_other: int = 0  # requests under its key that claimed to be a different agent
    model: str | None = None  # the model name its traffic carried, if seen through the gateway

    @property
    def prompt_sha256(self) -> str:
        return hashlib.sha256(self.prompt.encode("utf-8")).hexdigest()

    @property
    def prompt_chars(self) -> int:
        return len(self.prompt)


@dataclass
class TargetProfile:
    name: str
    tools: list[DiscoveredTool]
    agent_info: list[AgentInfo] = field(default_factory=list)

    @property
    def dangerous_tools(self) -> set[str]:
        return {t.name for t in self.tools if t.dangerous}

    @property
    def agents(self) -> set[str]:
        return {t.agent for t in self.tools} | {a.name for a in self.agent_info}


def with_risks(profile: TargetProfile, overrides: dict[str, str]) -> TargetProfile:
    """The profile with person-set risks for named tools. A typo or an unknown risk fails loudly: a silently
    ignored override would leave a dangerous tool labelled by its name alone."""
    known = {t.name for t in profile.tools}
    for name, risk in overrides.items():
        if name not in known:
            raise ValueError(f"no discovered tool is named {name!r}")
        if risk not in RISKS:
            raise ValueError(f"risk must be one of {', '.join(RISKS)}")
    tools = [replace(t, risk=overrides[t.name], risk_by="operator") if t.name in overrides else t
             for t in profile.tools]
    return TargetProfile(profile.name, tools, list(profile.agent_info))


def needs_review(profile: TargetProfile) -> list[str]:
    """Tools called read-only from their name alone: the one label that hides a tool from every control."""
    return sorted({f"{t.agent}.{t.name}" for t in profile.tools if t.risk == READ and t.risk_by == "name"})


def classify_risk(name: str, description: str, args: dict[str, dict]) -> str:
    """What this tool does to the world, from its name and argument names.

    A raw code/query argument means it executes. Otherwise the tool's leading action word
    decides (names are conventionally verb_noun, e.g. get_order vs create_order); if that is
    unknown, any side-effect verb elsewhere in the name does. Description is left to the
    optional model classifier, as it is too noisy for keyword matching.

    A name whose action word is not recognised is treated as a **write**: mislabelling a tool that
    changes the world as read-only hides it from every control, while the reverse only costs a
    review. Only the known read-only verbs earn the read label.
    """
    if _words(*args) & _EXECUTE_ARGS:
        return EXECUTE
    name_tokens = _tokens(name)
    first = name_tokens[0] if name_tokens else ""
    for verbs, risk in _CLASS_VERBS:
        if first in verbs:
            return risk
    rest = set(name_tokens)
    for verbs, risk in _CLASS_VERBS[:-1]:  # any side-effect verb in the name (not read)
        if rest & verbs:
            return risk
    return WRITE


def _source_of(tool: Any) -> str:
    fn = getattr(tool, "func", None) or getattr(type(tool), "_run", None)
    try:
        return f"{Path(inspect.getsourcefile(fn)).name}:{inspect.getsourcelines(fn)[1]}"
    except (TypeError, OSError):
        return "?"


def describe_tool(tool: Any, *, module: str = "", agent_name: str = "") -> DiscoveredTool:
    """Record a LangChain tool's name, arguments and risk (the one place a ``DiscoveredTool`` is built)."""
    description = (tool.description or "").strip()
    args = dict(tool.args)
    return DiscoveredTool(
        name=tool.name, description=description, args=args, source=_source_of(tool),
        risk=classify_risk(tool.name, description, args), module=module, tool=tool, agent_name=agent_name,
    )


def discover_tools(entry_ref: str) -> list[DiscoveredTool]:
    from langchain_core.tools import BaseTool

    entry = importlib.import_module(entry_ref.split(":")[0])
    root = Path(entry.__file__).resolve().parent
    found: dict[int, DiscoveredTool] = {}
    for name, module in list(sys.modules.items()):
        file = getattr(module, "__file__", None)
        if not file or not Path(file).resolve().is_relative_to(root):
            continue
        for obj in vars(module).values():
            if isinstance(obj, BaseTool) and id(obj) not in found:
                found[id(obj)] = describe_tool(obj, module=name)
    return sorted(found.values(), key=lambda t: t.name)


def profile_target(name: str, entry_ref: str) -> TargetProfile:
    return TargetProfile(name=name, tools=discover_tools(entry_ref))
