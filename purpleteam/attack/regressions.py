"""A persisted corpus of exploits this platform has already proven, so a later run re-tests every
past breach, not only the ones this run happens to find — the point the review raised: "keep
successful exploits as regression cases so future changes don't reopen them."

Domain-agnostic and target-agnostic: a case is just the exact payload that once breached, with the
finding it proved. One file can serve any target; callers pick which file by path. Writes are
atomic (a temp file, then an OS-level rename) so a crash mid-write never corrupts the store, and a
case is deduplicated by a hash of its own content, never by a run-specific id that could collide
or drift.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

_SCHEMA_FIELDS = ("id", "kind", "tool", "agent", "payload")


@dataclass(frozen=True)
class RegressionCase:
    id: str
    kind: str
    tool: str
    agent: str
    payload: str  # the exact text that breached; replayed verbatim, never re-rendered from a template


def case_id(kind: str, tool: str, agent: str, payload: str) -> str:
    """Deterministic from content alone, so the same exploit found again (same run or a later one)
    is always the same case — never a new, duplicate entry."""
    digest = hashlib.sha256("\x00".join((kind, tool, agent, payload)).encode("utf-8")).hexdigest()
    return digest[:16]


def load_regressions(path: Path | None) -> list[RegressionCase]:
    """Every case saved so far, or [] the first time there is nothing yet. A present but malformed
    file fails loud: a regression store silently read as empty would quietly stop protecting
    every exploit it was supposed to remember."""
    if path is None or not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise ValueError(f"the regression store at {path} is not readable JSON ({error})") from error
    if not isinstance(raw, list):
        raise ValueError(f"the regression store at {path} does not hold a list of cases")
    cases = []
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) != set(_SCHEMA_FIELDS):
            raise ValueError(f"the regression store at {path} holds a malformed case: {entry!r}")
        cases.append(RegressionCase(**entry))
    return cases


def _save(path: Path, cases: list[RegressionCase]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f"{path.suffix}.tmp")
    tmp.write_text(json.dumps([asdict(c) for c in cases], indent=2), encoding="utf-8")
    tmp.replace(path)  # atomic on POSIX and Windows alike


def record_breaches(path: Path | None, breaches: Iterable) -> list[RegressionCase]:
    """Add every proven breach in ``breaches`` (anything with ``.kind``, ``.tool``, ``.agent``,
    ``.payload`` — a ``CorpusResult`` already does) to the store at ``path`` that is not already
    there, and return the cases that were newly added. A no-op, returning [], with no path."""
    if path is None:
        return []
    existing = {c.id: c for c in load_regressions(path)}
    added: list[RegressionCase] = []
    for breach in breaches:
        if not getattr(breach, "payload", ""):
            continue  # nothing to replay without the exact text that breached
        new = RegressionCase(case_id(breach.kind, breach.tool, breach.agent, breach.payload),
                             breach.kind, breach.tool, breach.agent, breach.payload)
        if new.id not in existing:
            existing[new.id] = new
            added.append(new)
    if added:
        _save(path, sorted(existing.values(), key=lambda c: c.id))
    return added


def retest_against(cases: list[RegressionCase], target: Any, oracle: Any) -> tuple[list[Any], list[dict]]:
    """Replay every case against ``target`` (reset between attempts) and judge with ``oracle`` —
    a historical breach is never assumed still true. Returns (a ``CorpusResult`` for each case
    that still reproduces, a log entry per case naming whether it did — the caller's audit trail).
    An error re-testing a case is not evidence either way, so it is logged, never turned into a
    breach."""
    from purpleteam.attack.corpus import CorpusResult  # local: corpus.py does not need this module

    log, breaches = [], []
    for case in cases:
        target.reset()
        try:
            verdict = oracle.judge(target.send(case.payload))
        except Exception as error:
            log.append({"id": case.id, "kind": case.kind, "reproduced": None, "error": type(error).__name__})
            continue
        log.append({"id": case.id, "kind": case.kind, "reproduced": verdict.breached})
        if verdict.breached:
            breaches.append(CorpusResult(case.id, "regression", True, verdict.detail, kind=verdict.kind,
                                        tool=verdict.tool, agent=verdict.agent, evidence=verdict.evidence,
                                        payload=case.payload, reached=verdict.reached_tools))
    return breaches, log
