"""Remember a target file's original bytes before the platform first edits it, so every edit the
platform ever made can be undone in one step.

Only the first ``record`` for a path keeps its "before" -- a file patched twice is still restored to
what it was before the platform ever touched it. ``restore_all`` writes an original back only if the
file still holds exactly what the platform last wrote: a file someone edited by hand since is left
alone and reported, never silently overwritten. The store lives in the operator's own directory
(BYOC); it holds target source, so it is never written to the signed ledger.

The store is sealed by the operator (``purpleteam.operator_seal``): an original is only ever written back from a
store this operator sealed. One written or edited by anyone else -- or by a version before seals -- is never
trusted to write a file: a restore skips it, a new run's baseline keeps the files as they are, and a new edit
starts a fresh store rather than re-sealing what it held.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from purpleteam.operator_seal import OperatorSeal

_PURPOSE = "source-snapshots"
UNTRUSTED = "the snapshot store is not sealed by this operator; nothing is written back from it"


def read_exact(path: Path) -> str:
    """A file's text exactly as stored: no newline translation, so a CRLF file stays CRLF through an
    edit and is restored to the very same bytes."""
    return path.read_bytes().decode("utf-8")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_atomic(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".restore", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise


class SourceSnapshots:
    def __init__(self, store: str | Path, seal: OperatorSeal | None = None) -> None:
        self._store = Path(store)
        self._seal = seal

    def record(self, relative: str, before: str, after: str) -> None:
        """``relative``: the path inside the target repo; ``after``: exactly what was written."""
        entries, trusted = self._load()
        entries = entries if trusted else {}  # never seal what someone else wrote
        entry = entries.setdefault(relative, {"original": before})
        entry["written_sha256"] = _sha(after)
        self._save(entries)

    def modified(self) -> list[str]:
        return sorted(self._load()[0])

    def restore_all(self, repo: Path) -> list[dict]:
        """One result per recorded file: ``restored``, or ``skipped`` with the reason."""
        entries, trusted = self._load()
        if not trusted:
            return [{"path": relative, "status": "skipped", "reason": UNTRUSTED} for relative in sorted(entries)]
        results = []
        for relative, entry in sorted(entries.items()):
            path = (repo / relative).resolve()
            if not path.is_relative_to(repo.resolve()):
                results.append({"path": relative, "status": "skipped", "reason": "outside the target repository"})
                continue
            current = read_exact(path) if path.is_file() else None
            if current is not None and _sha(current) == _sha(entry["original"]):
                # Already the original (a prior patch was reverted outside the platform, e.g. by git): nothing to
                # undo, so just forget it -- an orphaned snapshot must never block a run or read as a manual edit.
                del entries[relative]
                results.append({"path": relative, "status": "restored", "reason": "already at the original"})
                continue
            if current is not None and _sha(current) != entry["written_sha256"]:
                results.append({"path": relative, "status": "skipped",
                                "reason": "edited since the platform patched it; left untouched"})
                continue
            _write_atomic(path, entry["original"])
            del entries[relative]
            results.append({"path": relative, "status": "restored"})
        self._save(entries)
        return results

    def rebaseline(self, repo: Path) -> list[dict]:
        """Prepare the target baseline for a run. A file the platform patched that nothing has touched since is
        put back to its original; a file the operator has since edited by hand is kept as-is and adopted as the
        new baseline -- the operator changed the target, so the run attacks what they now have. All entries are
        then forgotten. Unlike ``restore_all`` this never leaves a file 'skipped', so a hand edit never blocks a
        run and the edited source is what every run discovers, attacks and shows. An unsealed store writes
        nothing: every file it names is adopted as it is."""
        entries, trusted = self._load()
        if not trusted:
            self._save({})
            return [{"path": relative, "status": "adopted"} for relative in sorted(entries)]
        results = []
        for relative, entry in sorted(entries.items()):
            path = (repo / relative).resolve()
            if not path.is_relative_to(repo.resolve()):
                results.append({"path": relative, "status": "skipped", "reason": "outside the target repository"})
                continue
            current = read_exact(path) if path.is_file() else None
            if current is None or _sha(current) == entry["written_sha256"]:
                _write_atomic(path, entry["original"])  # the platform's own patch, untouched -> back to original
                results.append({"path": relative, "status": "restored"})
            else:
                results.append({"path": relative, "status": "adopted"})  # the operator's own edit -> keep, baseline it
            del entries[relative]
        self._save(entries)
        return results

    def _load(self) -> tuple[dict, bool]:
        """(entries, whether this operator sealed them). A store from before seals has no seal: never trusted."""
        if not self._store.exists():
            return {}, True
        data = json.loads(self._store.read_text(encoding="utf-8"))
        if isinstance(data, dict) and set(data) == {"entries", "seal"} and isinstance(data["entries"], dict):
            return data["entries"], self._sealer().verify(_PURPOSE, data["entries"], data["seal"])
        return (data if isinstance(data, dict) else {}), False

    def _save(self, entries: dict) -> None:
        self._store.parent.mkdir(parents=True, exist_ok=True)
        if not entries:
            self._store.unlink(missing_ok=True)
            return
        sealed = {"entries": entries, "seal": self._sealer().seal(_PURPOSE, entries)}
        _write_atomic(self._store, json.dumps(sealed, indent=2))

    def _sealer(self) -> OperatorSeal:
        if self._seal is None:
            self._seal = OperatorSeal.default()
        return self._seal
