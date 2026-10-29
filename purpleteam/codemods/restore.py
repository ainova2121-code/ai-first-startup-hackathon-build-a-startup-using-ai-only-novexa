"""Remember a target file's original bytes before the platform first edits it, so every edit the
platform ever made can be undone in one step.

Only the first ``record`` for a path keeps its "before" -- a file patched twice is still restored to
what it was before the platform ever touched it. ``restore_all`` writes an original back only if the
file still holds exactly what the platform last wrote: a file someone edited by hand since is left
alone and reported, never silently overwritten. The store lives in the operator's own directory
(BYOC); it holds target source, so it is never written to the signed ledger.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path


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
    def __init__(self, store: str | Path) -> None:
        self._store = Path(store)

    def record(self, relative: str, before: str, after: str) -> None:
        """``relative``: the path inside the target repo; ``after``: exactly what was written."""
        entries = self._load()
        entry = entries.setdefault(relative, {"original": before})
        entry["written_sha256"] = _sha(after)
        self._save(entries)

    def modified(self) -> list[str]:
        return sorted(self._load())

    def restore_all(self, repo: Path) -> list[dict]:
        """One result per recorded file: ``restored``, or ``skipped`` with the reason."""
        entries, results = self._load(), []
        for relative, entry in sorted(entries.items()):
            path = (repo / relative).resolve()
            if not path.is_relative_to(repo.resolve()):
                results.append({"path": relative, "status": "skipped", "reason": "outside the target repository"})
                continue
            current = read_exact(path) if path.is_file() else None
            if current is not None and _sha(current) != entry["written_sha256"]:
                results.append({"path": relative, "status": "skipped",
                                "reason": "edited since the platform patched it; left untouched"})
                continue
            _write_atomic(path, entry["original"])
            del entries[relative]
            results.append({"path": relative, "status": "restored"})
        self._save(entries)
        return results

    def _load(self) -> dict:
        if not self._store.exists():
            return {}
        return json.loads(self._store.read_text(encoding="utf-8"))

    def _save(self, entries: dict) -> None:
        self._store.parent.mkdir(parents=True, exist_ok=True)
        if not entries:
            self._store.unlink(missing_ok=True)
            return
        _write_atomic(self._store, json.dumps(entries, indent=2))
