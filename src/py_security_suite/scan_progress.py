"""Best-effort progress delivery with bounded buffering and shutdown."""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable
from typing import Generic, TypeVar


_Event = TypeVar("_Event")


class ProgressDispatcher(Generic[_Event]):
    """One callback at a time; retain the newest 64 pending events on overflow."""

    def __init__(self, callback: Callable[[_Event], None]) -> None:
        self._callback = callback
        self._pending: deque[_Event] = deque(maxlen=64)
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._disabled = False

    def submit(self, event: _Event) -> None:
        with self._lock:
            if self._disabled:
                return
            self._pending.append(event)
            if self._worker is None:
                self._worker = threading.Thread(
                    target=self._deliver, name="pysec-progress", daemon=True
                )
                try:
                    self._worker.start()
                except RuntimeError:
                    self._disabled = True
                    self._pending.clear()
                    self._worker = None

    def _deliver(self) -> None:
        while True:
            with self._lock:
                if not self._pending:
                    self._worker = None
                    return
                event = self._pending.popleft()
            try:
                self._callback(event)
            except Exception:  # noqa: BLE001 -- telemetry must not affect scan results
                with self._lock:
                    self._disabled = True
                    self._pending.clear()
                    self._worker = None
                return

    def finish(self) -> None:
        """Drain briefly, then discard pending telemetry without waiting on a sink."""
        with self._lock:
            worker = self._worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=0.25)
        with self._lock:
            if self._worker is not None:
                self._disabled = True
                self._pending.clear()
