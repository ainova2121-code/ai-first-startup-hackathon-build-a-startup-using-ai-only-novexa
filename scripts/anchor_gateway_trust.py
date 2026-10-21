"""Anchor the gateway's pinned trust file to outside RFC 3161 timestamp authorities
(``purpleteam.audit.anchor``) — the stronger, continuous protection ``gateway_crypto.save_trust``'s
own docstring names but never wires up on its own: a local pin only defends restart-to-restart,
against a log whose host could still be rewritten while the gateway keeps running.

    uv run python scripts/anchor_gateway_trust.py <trust_file> [retained_record]

Run this on a schedule (cron, a Kubernetes CronJob) separate from the gateway process, the same
way an Assessment's anchorer never sits on its attack path. Each run re-anchors the trust file's
*current* checkpoint and overwrites it in place — useful for a restart, but an administrator who
controls this file can simply run an old copy back over it before the next anchor, so that alone
proves little. ``retained_record``, when given, gets one JSON line appended (never overwritten)
per run, with this checkpoint and its anchor: keep that file somewhere the gateway's own
administrator does not control — your own retention bucket, object-lock storage, a copy mailed to
an auditor — since an append-only history outside their reach is what actually makes a later
rollback provable, not the anchor by itself.

With ``retained_record``, this script also refuses to anchor a checkpoint smaller than the last
one it already retained for the same log: a real log only ever grows, so a shrink is rollback, not
progress, and anchoring it would hand that rolled-back state a fresh, legitimate-looking
timestamp — the exact thing retention exists to prevent. A changed log id is refused the same way
(the ledger's identity itself changed, which anchoring-as-usual would quietly launder). Both stop
the run rather than merely warn; an operator who genuinely intended a reset has to clear the stale
retained record on purpose, not have this script decide that for them.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from purpleteam.audit.anchor import anchor_trust, freetsa
from purpleteam.gateway_crypto import save_trust


def _last_retained(retained_record: Path) -> dict | None:
    """The most recent record in an append-only retained-anchor file, or None if it doesn't exist
    yet or holds no records. A present but unparseable file fails loud rather than being read as
    "nothing retained yet" — that reading would quietly erase the protection it exists to provide."""
    if not retained_record.exists():
        return None
    last = None
    for line in retained_record.read_text(encoding="utf-8").splitlines():
        if line.strip():
            last = json.loads(line)
    if last is not None and "checkpoint" not in last:
        raise ValueError(f"{retained_record} holds a record with no checkpoint")
    return last


def _check_not_a_rollback(checkpoint: dict, previous: dict | None, retained_record: Path) -> str | None:
    """None if ``checkpoint`` may be anchored, or the reason it must not be."""
    if previous is None:
        return None
    prior = previous["checkpoint"]
    if checkpoint["log"] != prior["log"]:
        return (f"this log's id changed since the last anchor retained in {retained_record} "
               f"({prior['log']} -> {checkpoint['log']}) — the ledger's identity itself changed, "
               "not just its size; investigate before anchoring this one")
    if checkpoint["size"] < prior["size"]:
        return (f"this checkpoint has {checkpoint['size']} events, fewer than the {prior['size']} "
               f"already retained in {retained_record} for this log — a real log only grows, so "
               "this is rollback, not progress")
    return None


def run(trust_path: Path, retained_record: Path | None = None) -> int:
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    if "checkpoint" not in trust:
        print(f"anchor_gateway_trust: {trust_path} has no checkpoint yet (empty log) — nothing to anchor",
             file=sys.stderr)
        return 1
    if retained_record is not None:
        reason = _check_not_a_rollback(trust["checkpoint"], _last_retained(retained_record), retained_record)
        if reason is not None:
            print(f"anchor_gateway_trust: refusing to anchor — {reason}", file=sys.stderr)
            return 1
    anchored, errors = anchor_trust(trust, [freetsa()])
    for error in errors:
        print(f"anchor_gateway_trust: {error}", file=sys.stderr)
    if not anchored.get("anchors"):
        print("anchor_gateway_trust: no authority anchored this checkpoint; trust file left unchanged",
             file=sys.stderr)
        return 1

    save_trust(trust_path, anchored)
    if retained_record is not None:
        record = {"anchored_at": time.time(), "checkpoint": trust["checkpoint"], "anchors": anchored["anchors"]}
        with open(retained_record, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    else:
        print("anchor_gateway_trust: no retained_record given — this only refreshes the gateway's own "
             "trust file, which the same administrator who could roll back the ledger also controls; "
             "it proves nothing to anyone else unless you also retain it somewhere they do not.",
             file=sys.stderr)
    print(f"anchor_gateway_trust: anchored by {', '.join(a['authority'] for a in anchored['anchors'])}")
    return 0


def _main() -> None:
    if len(sys.argv) not in (2, 3):
        print("usage: python scripts/anchor_gateway_trust.py <trust_file> [retained_record]")
        raise SystemExit(2)
    retained = Path(sys.argv[2]) if len(sys.argv) == 3 else None
    raise SystemExit(run(Path(sys.argv[1]), retained))


if __name__ == "__main__":
    _main()
