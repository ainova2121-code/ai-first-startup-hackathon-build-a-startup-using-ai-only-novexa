"""Every live run's evidence, kept in the operator's own folder so any past run can be reopened and its
signed ledger re-verified later -- not lost in a temp folder when the process exits.

One directory per run: ``audit.jsonl`` (the signed ledger), ``events.jsonl`` (what the page was shown,
in order), ``trust.json`` (the public keys and signed checkpoint the run sealed with -- without it a
later reader could check only internal consistency, not who signed), ``meta.json``, and -- once a
defense was verified -- ``decisions.json`` (every verified decision, pinned by a digest in the ledger)
and ``policy.json`` (the inputs that rebuild that exact defense).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path

from purpleteam.audit.compliance import controls_for
from purpleteam.audit.anchor import AnchorError, freetsa
from purpleteam.audit.explain import explain_log
from purpleteam.audit.verify import verify_log

_RUN_ID = re.compile(r"\d{8}T\d{6}-[0-9a-f]{6}")


class Run:
    def __init__(self, directory: Path) -> None:
        self.dir, self.id = directory, directory.name
        self.ledger_path = directory / "audit.jsonl"

    def record(self, event: dict) -> None:
        with (self.dir / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event) + "\n")

    def write_meta(self, **meta) -> None:
        current = self.meta()
        (self.dir / "meta.json").write_text(json.dumps({**current, **meta}, indent=2), encoding="utf-8")

    def write_trust(self, trust: dict) -> None:
        self.write_json("trust", trust)

    def write_json(self, name: str, data: dict) -> None:
        """``name``: one of this module's fixed file names, never caller input. Written whole or not at all, so a
        reader during a live run never sees half a file."""
        staged = self.dir / f"{name}.json.tmp"
        staged.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(staged, self.dir / f"{name}.json")

    def read_json(self, name: str) -> dict | None:
        path = self.dir / f"{name}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def meta(self) -> dict:
        path = self.dir / "meta.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"id": self.id}

    def events(self) -> list[dict]:
        return _lines(self.dir / "events.jsonl")

    def ledger(self) -> dict:
        """The signed ledger, its verification against the trust bundle the run sealed with, and the
        compliance clauses each event evidences."""
        trust_path = self.dir / "trust.json"
        events = _lines(self.ledger_path, live=not trust_path.exists())
        if trust_path.exists():
            result = verify_log(events, json.loads(trust_path.read_text(encoding="utf-8")))
            verification = {"ok": result.ok, "anchored": result.anchored, "count": result.count,
                            "broken_at": result.broken_at, "reason": result.reason}
        else:
            verification = {"ok": None, "anchored": False, "count": len(events), "broken_at": None,
                            "reason": "the run has not been sealed yet, so there is no checkpoint to verify against"}
        rows = [{"seq": e.get("seq"), "ts": e.get("ts"), "actor": e.get("actor"), "kind": e.get("kind"),
                 "hash": e.get("hash", "")[:16], "payload": e.get("payload"),
                 "clauses": [f"{c.framework} · {c.clause}" for c in controls_for(e)]} for e in events]
        return {"run": self.meta(), "verification": verification, "events": rows}

    def explain(self) -> dict | None:
        """Every verification step for every event and the checkpoint (``audit.explain``). Before the run is sealed,
        each event is still checked against its actor's public key (``keys.json``, written as each signer appears),
        with no checkpoint yet; None until the first event is signed."""
        trust = self.read_json("trust")
        sealed = bool(trust)
        if not sealed:
            keys = self.read_json("keys")
            if not keys:
                return None
            trust = {"keys": keys}
        meta = self.meta()  # how this run was configured to sign and anchor, and what went wrong if anchoring did
        return {**explain_log(_lines(self.ledger_path, live=not sealed), trust, _authorities()), "sealed": sealed,
                "hardware_note": meta.get("hardware", ""), "anchoring": meta.get("anchoring", "off"),
                "anchor_errors": meta.get("anchor_errors", [])}


def _authorities() -> dict:
    """The timestamp authorities whose pinned certificates this installation holds (audit.anchor)."""
    try:
        return {"freetsa": freetsa()}
    except (AnchorError, OSError):  # missing or altered pinned files: no token can then be shown as verified
        return {}


class RunStore:
    def __init__(self, root: Path) -> None:
        self._root = root

    def new(self) -> Run:
        run_id = f"{time.strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}"
        directory = self._root / run_id
        directory.mkdir(parents=True)
        run = Run(directory)
        run.write_meta(id=run_id, started_at=time.time(), status="running")
        return run

    def get(self, run_id: str) -> Run | None:
        """None for anything that is not a well-formed id of an existing run: never a path the caller built."""
        if not _RUN_ID.fullmatch(run_id or ""):
            return None
        directory = self._root / run_id
        return Run(directory) if directory.is_dir() else None

    def all(self) -> list[dict]:
        if not self._root.is_dir():
            return []
        runs = [Run(d).meta() for d in self._root.iterdir() if d.is_dir() and _RUN_ID.fullmatch(d.name)]
        return sorted(runs, key=lambda m: m.get("started_at", 0), reverse=True)

    def mark_interrupted(self) -> list[str]:
        """Runs a previous process left "running": none of them can still be, so say what really happened."""
        stale = [meta["id"] for meta in self.all() if meta.get("status") == "running"]
        for run_id in stale:
            self.get(run_id).write_meta(status="interrupted", detail="the server stopped before this run finished")
        return stale

    def last_approved(self, target: str) -> Run | None:
        """The newest run of ``target`` that passed the release gate and pinned its decisions: the policy a
        later run of the same target must not loosen (``purpleteam.decisions``)."""
        for meta in self.all():
            run = self.get(meta.get("id", ""))
            if (meta.get("target") == target and meta.get("status") == "done" and meta.get("safe_to_ship")
                    and run and run.read_json("decisions")):
                return run
        return None


def _lines(path: Path, live: bool = False) -> list[dict]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    if live and not text.endswith("\n"):  # mid-run only: the record still being written is not read yet
        text = text.rpartition("\n")[0]
    return [json.loads(line) for line in text.splitlines() if line.strip()]
