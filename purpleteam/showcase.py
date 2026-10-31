"""The Showcase suite: the attacks that breached in a target's latest earlier run, plus a few that held, sent again so a
short demo shows real breaches without running the whole dataset.

Every attack is sent live and judged again. A past breach is only the reason an attack is picked, never its result:
a model that resists it this time shows "held". Part of the live console (like ``live_run``).
"""

from __future__ import annotations

from purpleteam.attack.corpus import AttackTemplate
from purpleteam.run_history import RunStore

BREACHES, CONTROLS = 6, 2  # a demo-sized set: the breaches to show, and attacks that held, side by side


def _past(runs: RunStore | None, target: str) -> tuple[list[str], list[str]]:
    """(ids that breached, ids that held) in the newest earlier run of ``target`` with a breach; re-attacks of the
    patched agent are not the agent as it is, so they never count."""
    for meta in runs.all() if runs else []:
        run = runs.get(meta.get("id", "")) if meta.get("target") == target else None
        results = [e for e in run.events() if e.get("type") == "attack_result" and e.get("technique") != "reverify"
                   and e.get("id")] if run else []
        breached = list(dict.fromkeys(e["id"] for e in results if e.get("breached")))
        if breached:
            held = [i for i in dict.fromkeys(e["id"] for e in results if e.get("outcome") == "held") if i not in breached]
            return breached, held
    return [], []


def available(runs: RunStore | None, target: str) -> bool:
    return bool(_past(runs, target)[0])


def showcase(runs: RunStore | None, target: str, pool: list[AttackTemplate], breaches: int = BREACHES,
             controls: int = CONTROLS) -> list[AttackTemplate]:
    """The past breaches and controls, as templates from ``pool`` (today's dataset), so each is rendered and sent
    exactly as a full run would. Controls come first from kinds that did not breach, to show what resisted. Raises
    ValueError when there is no past breach to show, rather than run an empty suite."""
    by_id = {template.id: template for template in pool}
    breached, held = _past(runs, target)
    breached, held = [i for i in breached if i in by_id], [i for i in held if i in by_id]
    if not breached:
        raise ValueError("no earlier run of this target has a breach to showcase: run the Full dataset first")
    kinds = {by_id[i].technique for i in breached}
    held.sort(key=lambda i: by_id[i].technique in kinds)
    return [by_id[i] for i in breached[:breaches] + held[:controls]]
