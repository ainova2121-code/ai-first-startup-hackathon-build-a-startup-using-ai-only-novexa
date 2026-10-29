"""Policy-decision drift: does a policy still decide exactly what was decided when it was verified?

A defense is approved on evidence -- the attack replays it held and the legitimate work it let through.
Every decision behind that evidence (each tool call the guard allowed, held or blocked; each text it let
through, redacted or stopped) is recorded here with its exact inputs while the verified replays run.
Replaying those inputs through any other policy -- a newly approved one, an upgraded patch catalog, an
edited manifest, or a what-if without one patch -- shows exactly which decisions flipped and how badly.

A guard decision is a pure function of the policy and its inputs, so a replay needs no model and no
target: the same inputs give the same answer, and a flip is a real change, never sampling noise. Each
probe is decided by a freshly built guard, so a stateful patch (a loop budget, a review queue) never
carries one probe's state into the next. Inputs can hold target data, so the probes stay in the
operator's own run folder; the signed ledger holds only counts, keys and the digest that pins them.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass
from typing import Any, Callable

from purpleteam.audit.hashing import canonical
from purpleteam.patches.base import Blocked, CompositeGuard, HoldForReview

ALLOW, MODIFY, HOLD, BLOCK, ERROR = "allow", "modify", "hold", "block", "error"
_STRENGTH = {ALLOW: 0, MODIFY: 1, HOLD: 2, BLOCK: 3, ERROR: 3}  # how much each outcome restrains
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
MAX_PROBES = 2000
ATTACK, LEGIT = "attack", "legit"

GuardFactory = Callable[[], CompositeGuard]


@dataclass(frozen=True)
class Probe:
    """One decision's exact inputs: an ``authorize`` of a tool call, or a ``screen`` of a text."""

    check: str
    agent: str
    tool: str = ""
    args: str = ""  # canonical JSON, so a probe is hashable and replays byte-for-byte
    text: str = ""
    source: str = ""

    @property
    def key(self) -> str:
        return hashlib.sha256(canonical(asdict(self))).hexdigest()[:16]

    def label(self) -> str:
        if self.check == "authorize":
            return f"{self.agent} → {self.tool}({self.args[:100]})"
        return f"{self.agent} · {self.source}: {self.text[:100]!r}"


class ProbeLog:
    """Every distinct decision input seen, with where it came from; safe to fill from parallel replays."""

    def __init__(self, limit: int = MAX_PROBES) -> None:
        self._lock = threading.Lock()
        self._probes: dict[str, tuple[Probe, set[str]]] = {}
        self._stopped: dict[tuple[str, str], tuple[Probe, bool]] = {}  # (key, origin) -> (probe, held for review)
        self._limit = limit
        self.dropped = 0  # reported, never silently lost

    def stop(self, probe: Probe, origin: str, held: bool) -> None:
        """The live guard stopped this input during a replay (blocked it, or held it for review)."""
        with self._lock:
            self._stopped[(probe.key, origin)] = (probe, held)

    def stopped(self, origin: str) -> list[tuple[Probe, bool]]:
        with self._lock:
            return [entry for (_, seen_in), entry in sorted(self._stopped.items()) if seen_in == origin]

    def add(self, probe: Probe, origin: str) -> None:
        with self._lock:
            entry = self._probes.get(probe.key)
            if entry is not None:
                entry[1].add(origin)
            elif len(self._probes) < self._limit:
                self._probes[probe.key] = (probe, {origin})
            else:
                self.dropped += 1

    def items(self) -> list[tuple[Probe, set[str]]]:
        with self._lock:
            return list(self._probes.values())


class DecisionRecorder:
    """A Guard that hands every call straight to ``guard`` and records its inputs. It never changes a
    decision; anything else asked of it (``patches``, say) is the wrapped guard's."""

    def __init__(self, guard: Any, log: ProbeLog, origin: str) -> None:
        self._guard, self._log, self._origin = guard, log, origin

    def screen(self, agent: str, text: str, source: str) -> str:
        probe = Probe("screen", agent, text=text, source=source)
        return self._decided(probe, lambda: self._guard.screen(agent, text, source))

    def authorize(self, agent: str, tool: str, args: dict[str, Any]) -> None:
        probe = Probe("authorize", agent, tool, canonical(args).decode("utf-8"))
        return self._decided(probe, lambda: self._guard.authorize(agent, tool, args))

    def _decided(self, probe: Probe, call: Callable[[], Any]) -> Any:
        self._log.add(probe, self._origin)
        try:
            return call()
        except Blocked as stopped:  # noted, then raised exactly as before: the decision is never changed
            self._log.stop(probe, self._origin, held=isinstance(stopped, HoldForReview))
            raise

    def __getattr__(self, name: str) -> Any:
        return getattr(self._guard, name)


def decide(guard: CompositeGuard, probe: Probe) -> tuple[str, str]:
    """(outcome, the patch id(s) that decided it), walking the guard's patches in order exactly as
    ``CompositeGuard`` does, so the patch responsible for each decision is named."""
    if probe.check == "authorize":
        args = json.loads(probe.args or "{}")
        for patch in guard.patches:
            try:
                patch.authorize(probe.agent, probe.tool, args)
            except HoldForReview:
                return HOLD, patch.id
            except Blocked:
                return BLOCK, patch.id
            except Exception:  # a guard that crashes stops the call too, but is never mistaken for a block
                return ERROR, patch.id
        return ALLOW, ""
    text, changed_by = probe.text, []
    for patch in guard.patches:
        try:
            screened = patch.screen(probe.agent, text, probe.source)
        except Blocked:
            return BLOCK, patch.id
        except Exception:
            return ERROR, patch.id
        if screened != text:
            changed_by.append(patch.id)
            text = screened
    return (MODIFY, ",".join(changed_by)) if changed_by else (ALLOW, "")


def take_baseline(log: ProbeLog, factory: GuardFactory, policy: list | None = None) -> dict:
    """What the approved policy decides for every recorded input, pinned by a digest."""
    probes = []
    for probe, origins in sorted(log.items(), key=lambda item: item[0].key):
        outcome, by = decide(factory(), probe)
        probes.append({"key": probe.key, "probe": asdict(probe), "origins": sorted(origins),
                       "outcome": outcome, "by": by})
    return {"version": 1, "policy": policy or [], "probes": probes, "dropped": log.dropped,
            "digest": _digest(probes)}


def check_baseline(data: Any) -> dict:
    """A baseline read back from disk must still be exactly what was recorded (its digest is in the ledger)."""
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("probes"), list):
        raise ValueError("not a decision baseline")
    if _digest(data["probes"]) != data.get("digest"):
        raise ValueError("the decision baseline was altered after it was recorded")
    return data


def compare(baseline: dict, factory: GuardFactory) -> list[dict]:
    """Every recorded decision the given policy would now make differently, most severe first."""
    flips = []
    for entry in check_baseline(baseline)["probes"]:
        probe = Probe(**entry["probe"])
        outcome, by = decide(factory(), probe)
        if outcome == entry["outcome"]:
            continue
        severity, why = _judge(set(entry["origins"]), entry["outcome"], outcome)
        flips.append({"key": entry["key"], "label": probe.label(), "check": probe.check, "agent": probe.agent,
                      "tool": probe.tool, "origins": entry["origins"], "before": entry["outcome"],
                      "after": outcome, "by_before": entry["by"], "by_after": by, "severity": severity, "why": why})
    return sorted(flips, key=lambda flip: (_SEVERITY_ORDER[flip["severity"]], flip["key"]))


def require_no_loosening(baseline: dict, pinned_digest: str, factory: GuardFactory) -> list[dict]:
    """The release gate for a policy about to be enforced: the baseline must be exactly the one pinned
    (by its digest in a signed ledger), and the policy must not loosen any of its decisions. Raises
    ``ValueError`` naming what failed; returns the (non-loosening) flips otherwise."""
    if check_baseline(baseline)["digest"] != pinned_digest:
        raise ValueError("the decision baseline is not the one pinned in the signed ledger")
    flips = compare(baseline, factory)
    loosened = [flip for flip in flips if flip["severity"] == "high"]
    if loosened:
        where = "; ".join(f"{f['agent']}.{f['tool'] or f['check']}: {f['before']} -> {f['after']}" for f in loosened[:5])
        raise ValueError(f"this policy loosens {len(loosened)} approved decision(s) ({where}) -- re-run the "
                         "assessment and re-approve before enforcing it")
    return flips


def without(factory: GuardFactory, patch_ids: set[str]) -> GuardFactory:
    """A what-if: the same policy with some patches removed."""
    return lambda: CompositeGuard([p for p in factory().patches if p.id not in patch_ids])


def summarize(flips: list[dict]) -> dict[str, int]:
    return {level: sum(1 for f in flips if f["severity"] == level) for level in _SEVERITY_ORDER}


def _judge(origins: set[str], before: str, after: str) -> tuple[str, str]:
    if _STRENGTH[after] < _STRENGTH[before]:  # looser
        if ATTACK in origins:
            return "high", (f"input from a verified attack: the approved policy decided '{before}', this policy "
                            f"decides '{after}'")
        if before == MODIFY:
            return "high", "text the approved policy redacted would now pass through unredacted"
        return "medium", f"less oversight than approved: '{before}' becomes '{after}'"
    if _STRENGTH[after] > _STRENGTH[before] and LEGIT in origins:
        return "medium", f"legitimate work the approved policy decided '{before}' would now be '{after}'"
    return "low", f"'{before}' becomes '{after}' (no weaker than approved)"


def _digest(probes: list) -> str:
    return hashlib.sha256(canonical(probes)).hexdigest()
