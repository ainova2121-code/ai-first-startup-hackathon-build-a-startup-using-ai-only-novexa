"""Read a past run's pinned decisions and ask what-if questions of its policy (``purpleteam.decisions``).

``POST /runs/{id}/what-if`` rebuilds the run's verified policy from its saved inputs, removes the named
patches, and replays every pinned decision through it. Before answering, the rebuild with nothing removed
must reproduce every pinned decision exactly; if it does not, that is reported instead of a what-if built
on a policy that is not the one that was verified.
"""

from __future__ import annotations

from collections import Counter
from typing import Annotated

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, StringConstraints

from purpleteam.decisions import check_baseline, compare, summarize, without
from purpleteam.defender.policy import rebuild
from purpleteam.run_history import Run, RunStore

PatchId = Annotated[str, StringConstraints(pattern=r"^P\d{1,3}$")]


class WhatIf(BaseModel):
    without: list[PatchId] = Field(default_factory=list, max_length=32)


def drift_routes(runs: RunStore) -> APIRouter:
    router = APIRouter()

    def _pinned(run_id: str) -> tuple[Run, dict]:
        run = runs.get(run_id)
        baseline = run.read_json("decisions") if run else None
        if baseline is None:
            raise HTTPException(404, "this run pinned no decisions (no defense was verified)")
        try:
            return run, check_baseline(baseline)
        except ValueError as error:
            raise HTTPException(409, str(error)) from error

    @router.get("/runs/{run_id}/decisions")
    def decisions(run_id: str) -> dict:
        run, baseline = _pinned(run_id)
        origins = Counter(origin for entry in baseline["probes"] for origin in entry["origins"])
        outcomes = Counter(entry["outcome"] for entry in baseline["probes"])
        return {"run": run.id, "digest": baseline["digest"], "probes": len(baseline["probes"]),
                "dropped": baseline["dropped"], "origins": dict(origins), "outcomes": dict(outcomes),
                "patches": [pid for pid, _ in baseline["policy"]], "what_if": run.read_json("policy") is not None}

    @router.post("/runs/{run_id}/what-if")
    def what_if(run_id: str, body: WhatIf) -> dict:
        run, baseline = _pinned(run_id)
        policy = run.read_json("policy")
        if policy is None:
            raise HTTPException(404, "this run kept no rebuildable policy")
        removed = set(body.without)
        unknown = removed - {pid for pid, _ in baseline["policy"]}
        if unknown:
            raise HTTPException(422, f"not in this run's policy: {', '.join(sorted(unknown))}")
        try:
            rebuild(policy)  # refused if this installation's patch code differs from what was verified
        except ValueError as error:
            raise HTTPException(409, f"this run's policy cannot be rebuilt here: {error}") from error

        def factory():
            return rebuild(policy).guard

        fidelity = compare(baseline, factory)
        if fidelity:
            raise HTTPException(409, f"rebuilding this run's policy changes {len(fidelity)} pinned decision(s), "
                                     "so a what-if on it would not describe the verified policy")
        flips = compare(baseline, without(factory, removed)) if removed else []
        return {"run": run.id, "without": sorted(removed), "compared": len(baseline["probes"]),
                "counts": summarize(flips), "flips": flips}

    return router
