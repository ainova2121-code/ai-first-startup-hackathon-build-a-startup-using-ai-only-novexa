"""Compliance trend across repeated assessments, read from one audit ledger's full history.

A customer re-runs ``Assessment.run()`` on a schedule of their own choosing — in CI, a cron job,
or before each deploy — pointing at the same ledger path each time. Every run appends its own
identity/attack/breach/patch/verdict events and closes with a ``seal``; this module only re-reads
that already-signed history and groups it back into runs. It starts nothing and watches no traffic:
the customer owns the schedule, so "continuous compliance" here means repeated, evidenced testing
over time, never a runtime monitor (out of scope for a pre-deployment platform).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from purpleteam.identity import DRIFT_KINDS, SCOPE_KINDS


@dataclass(frozen=True)
class RunRecord:
    seq: int                      # 0-based position among the runs sealed in this ledger
    size: int                     # ledger size (event count) once this run's seal was appended
    sealed_at: float
    baseline_checked: bool
    scope_violations: frozenset = field(default_factory=frozenset)
    drift: frozenset = field(default_factory=frozenset)
    breach_kinds: frozenset = field(default_factory=frozenset)
    patch_ids: tuple[str, ...] = ()
    unpatched: tuple[str, ...] = ()
    safe_to_ship: bool = True


def runs(events: list[dict]) -> list[RunRecord]:
    """Split one ledger's full history into runs, one per sealed ``Assessment.run()`` call."""
    out: list[RunRecord] = []
    batch: list[dict] = []
    for event in events:
        batch.append(event)
        if event["kind"] == "seal":
            out.append(_summarize(len(out), batch))
            batch = []
    return out


def _summarize(seq: int, batch: list[dict]) -> RunRecord:
    identity = next((e["payload"] for e in batch if e["kind"] == "identity"), None)
    patch = next((e["payload"] for e in batch if e["kind"] == "patch"), None)
    verdict = next((e["payload"] for e in batch if e["kind"] == "verdict"), None)
    seal = next(e for e in batch if e["kind"] == "seal")
    breach_kinds = frozenset(e["payload"]["kind"] for e in batch if e["kind"] == "breach" and e["payload"].get("kind"))
    finding_kinds = frozenset(f["kind"] for f in (identity or {}).get("findings", []))
    return RunRecord(
        seq=seq, size=seal["seq"] + 1, sealed_at=seal["ts"],
        baseline_checked=bool(identity.get("baseline_checked")) if identity else False,
        scope_violations=finding_kinds & SCOPE_KINDS,
        drift=finding_kinds & DRIFT_KINDS,
        breach_kinds=breach_kinds,
        patch_ids=tuple(patch.get("patch_ids", [])) if patch else (),
        unpatched=tuple(patch.get("unpatched", [])) if patch else (),
        safe_to_ship=verdict["safe_to_ship"] if verdict else True,
    )


def render(history: list[RunRecord]) -> str:
    """A Markdown table a compliance officer can read as a trend line, oldest run first."""
    if not history:
        return ""
    rows = [
        "## Compliance trend", "",
        "Each row is one sealed assessment run recorded on this ledger, oldest first — evidence of "
        "repeated testing over time, not a single point-in-time snapshot.", "",
        "| Run | Sealed at (UTC) | Events | Safe to ship | Breach kinds | Scope violations | Baseline drift |",
        "|---|---|---|---|---|---|---|",
    ]
    for run in history:
        ship = "yes" if run.safe_to_ship else "**NO**"
        breaches = ", ".join(sorted(run.breach_kinds)) or "none"
        scope = ", ".join(sorted(run.scope_violations)) or "none"
        drift = ", ".join(sorted(run.drift)) if run.baseline_checked else "not checked"
        rows.append(f"| {run.seq + 1} | {_when(run.sealed_at)} | {run.size} | {ship} | {breaches} | {scope} | {drift} |")
    notes = []
    newly = _new_breach_kinds(history)
    if newly:
        notes.append(f"**New since the previous run:** {', '.join(sorted(newly))}")
    for run in history:
        if run.unpatched:
            notes.append(f"**Run {run.seq + 1} had no patch for:** {', '.join(run.unpatched)}")
    if notes:
        rows += [""] + notes
    return "\n".join(rows)


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


def _new_breach_kinds(history: list[RunRecord]) -> frozenset:
    if len(history) < 2:
        return frozenset()
    return history[-1].breach_kinds - history[-2].breach_kinds
