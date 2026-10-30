"""Cooperative pause/stop controls for a live assessment.

An in-flight model/provider request cannot be safely killed from another thread. Controls therefore
take effect before the next target send or attack case; stopping seals a partial run as incomplete.
"""

from __future__ import annotations

import threading
from collections.abc import Callable


class RunStopped(Exception):
    """Raised before a target request when the operator has stopped the run."""


class RunControl:
    def __init__(self) -> None:
        self._resume = threading.Event()
        self._resume.set()
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._lock = threading.Lock()
        self._paused_notified = False
        self._notify: Callable[[dict], None] | None = None

    def set_notifier(self, notify: Callable[[dict], None]) -> None:
        self._notify = notify

    @property
    def stop_requested(self) -> bool:
        return self._stop.is_set()

    @property
    def status(self) -> str:
        if self._stop.is_set():
            return "stopping"
        if not self._pause.is_set():
            return "running"
        with self._lock:
            return "paused" if self._paused_notified else "pausing"

    @property
    def pause_requested(self) -> bool:
        return self._pause.is_set() and not self._stop.is_set()

    def pause(self) -> bool:
        if self._stop.is_set():
            return False
        with self._lock:
            if self._pause.is_set():
                return False
            self._pause.set()
            self._resume.clear()
            self._paused_notified = False
        return True

    def resume(self) -> bool:
        if self._stop.is_set():
            return False
        with self._lock:
            self._pause.clear()
            self._resume.set()
            self._paused_notified = False
        return True

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            self._pause.clear()
            self._resume.set()

    def checkpoint(self) -> bool:
        """Block at a safe checkpoint while paused; return false once stop was requested."""
        while not self._stop.is_set():
            if self._resume.wait(0.1):
                return not self._stop.is_set()
            if self._pause.is_set():
                notify = None
                with self._lock:
                    if not self._paused_notified and self._pause.is_set() and not self._stop.is_set():
                        self._paused_notified = True
                        notify = self._notify
                if notify is not None:
                    notify({"type": "run_paused"})
        return False
