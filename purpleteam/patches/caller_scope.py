"""P16: a query tool may read only the rows that belong to the caller its request was made for.

P8 makes a raw-query tool read-only, but a read-only query can still return every tenant's rows -- the
cross-tenant leak and the "I am actually customer #3" identity spoof. This binds each request to its caller and
allows a query only when every table it reads is pinned to that caller's id.

The caller is read from the application's own framing at the very start of the agent's input (an operator-supplied
pattern such as ``^Customer #(\\d+) asks:``), never from anything the user typed after it. Each request runs in its
own context, so the binding never crosses from one request to another. Everything the analysis cannot prove scoped
-- an unknown table, an OR, an outer join's condition, a query that does not parse -- is refused, never guessed.
Domain-agnostic: which tables, which id column, and the framing pattern all come from the operator's facts.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextvars import ContextVar
from typing import Any

import sqlglot
from sqlglot import exp

from purpleteam.patches.base import Blocked, Patch

_Key = tuple[str, str, str]  # ("col", table alias, column) or ("lit", value, "")


class CallerScopeGuard(Patch):
    """Allow a query tool to read only rows pinned to the caller its request was made for."""

    id, layer, answers = "P16", "tenancy", ("exfiltration", "unscoped_execution")

    def __init__(self, tools: set[str], columns: dict[str, str], caller_pattern: str, arg: str = "sql") -> None:
        self._tools, self._arg = set(tools), arg
        self._columns = {table.lower(): column.lower() for table, column in columns.items()}
        self._pattern = re.compile(caller_pattern)
        self._callers: ContextVar[dict[str, str | None] | None] = ContextVar(f"p16_callers_{id(self)}", default=None)

    def screen(self, agent: str, text: str, source: str) -> str:
        if source == "input":  # a new task for this agent: bind (or, with no framing, clear) its caller
            match = self._pattern.match(str(text))
            self._callers.set({**(self._callers.get() or {}), agent: _normal(match.group(1)) if match else None})
        return text

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        if tool not in self._tools:
            return
        caller = (self._callers.get() or {}).get(agent)
        if caller is None:
            raise Blocked(f"{tool}: no caller is bound to this request, so its query cannot be scoped")
        reason = self._unscoped(str(args.get(self._arg, "")), caller)
        if reason:
            raise Blocked(f"{tool}: {reason}")

    def _unscoped(self, sql: str, caller: str) -> str | None:
        try:
            statements = [s for s in sqlglot.parse(sql, read="sqlite") if s]
        except sqlglot.errors.SqlglotError:
            return "the query could not be parsed"
        if len(statements) != 1 or not isinstance(statements[0], exp.Select):
            return "only a single SELECT can be scoped to the caller"
        ctes = {cte.alias_or_name.lower() for cte in statements[0].find_all(exp.CTE)}
        if ctes & set(self._columns):
            return "a CTE may not take the name of a scoped table"
        for select in statements[0].find_all(exp.Select):  # every subquery, CTE and set-operation side on its own
            reason = self._select_unscoped(select, ctes, caller)
            if reason:
                return reason
        return None

    def _select_unscoped(self, select: exp.Select, ctes: set[str], caller: str) -> str | None:
        sources = [source.this for source in [select.args.get("from_"), *(select.args.get("joins") or [])] if source]
        if any(not isinstance(source, (exp.Table, exp.Subquery)) for source in sources):
            return "a query source other than a table or a subquery cannot be scoped"
        tables: dict[str, str] = {}  # alias -> table, for the tables this SELECT itself reads
        for table in (s for s in sources if isinstance(s, exp.Table)):
            name = table.name.lower() if isinstance(table.this, exp.Identifier) else ""
            if name in ctes and not table.db:
                continue  # a CTE reference: the CTE's own SELECT is checked where it is defined
            if name not in self._columns:
                return f"table '{table.sql()}' is outside the caller scope"
            tables[table.alias_or_name.lower()] = name
        if not tables:
            return None
        equal = _Classes()
        for clause in self._pinning_clauses(select):
            if isinstance(clause, exp.EQ):
                left, right = (_key(side, tables) for side in (clause.left, clause.right))
                if left and right and "col" in (left[0], right[0]):  # literal = literal pins nothing
                    equal.union(left, right)
        target = ("lit", caller, "")
        for alias, name in tables.items():
            if equal.find(("col", alias, self._columns[name])) != equal.find(target):
                return f"'{name}' is not pinned to the caller ({self._columns[name]} = {caller})"
        return None

    @staticmethod
    def _pinning_clauses(select: exp.Select) -> Iterator[exp.Expression]:
        """The conditions every returned row must meet: WHERE's top-level ANDs and an inner join's ON (an outer
        join's ON does not filter the rows it keeps, so it never counts)."""
        where = select.args.get("where")
        if where is not None:
            yield from _conjuncts(where.this)
        for join in select.args.get("joins") or []:
            if not join.side and join.args.get("on") is not None:
                yield from _conjuncts(join.args["on"])


def _conjuncts(condition: exp.Expression) -> Iterator[exp.Expression]:
    if isinstance(condition, exp.Paren):
        yield from _conjuncts(condition.this)
    elif isinstance(condition, exp.And):
        yield from _conjuncts(condition.left)
        yield from _conjuncts(condition.right)
    else:
        yield condition


def _key(side: exp.Expression, tables: dict[str, str]) -> _Key | None:
    if isinstance(side, exp.Literal):
        return ("lit", _normal(side.this), "")
    if not isinstance(side, exp.Column):
        return None
    alias = side.table.lower()
    if not alias:
        if len(tables) != 1:
            return None  # an unqualified column over several tables is ambiguous: never assume whose it is
        alias = next(iter(tables))
    return ("col", alias, side.name.lower()) if alias in tables else None


def _normal(value: str) -> str:
    value = str(value).strip()
    return str(int(value)) if value.isdigit() else value


class _Classes:
    """Union-find over columns and literals that the pinning conditions make equal."""

    def __init__(self) -> None:
        self._parent: dict[_Key, _Key] = {}

    def find(self, key: _Key) -> _Key:
        self._parent.setdefault(key, key)
        while self._parent[key] != key:
            self._parent[key] = self._parent[self._parent[key]]
            key = self._parent[key]
        return key

    def union(self, left: _Key, right: _Key) -> None:
        self._parent[self.find(left)] = self.find(right)
