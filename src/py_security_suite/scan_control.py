"""Cooperative scan cancellation and secret-free progress events."""

from __future__ import annotations

import signal
import os
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from .process_memory import process_tree_resident_bytes as _process_tree_resident_bytes
from .scan_progress import ProgressDispatcher


ProgressState = Literal[
    "started",
    "completed",
    "stopped",
    "failed",
    "timed_out",
    "parse_error",
    "skipped",
    "unavailable",
]


class StopCause(StrEnum):
    CANCELLED = "cancelled"
    DEADLINE = "deadline"
    MEMORY_LIMIT = "memory_limit"
    MEMORY_UNAVAILABLE = "memory_unavailable"


class ScanInterrupted(ValueError):
    """Stop optional work while retaining already completed evidence."""


def analysis_checkpoint() -> None:
    if reason := stop_reason():
        raise ScanInterrupted(reason)


def stop_cause(reason: str | None = None) -> StopCause | None:
    return {
        "scan cancelled by operator": StopCause.CANCELLED,
        "scan deadline exceeded": StopCause.DEADLINE,
        "scan process-tree memory budget exceeded": StopCause.MEMORY_LIMIT,
        "scan process-tree memory accounting unavailable": StopCause.MEMORY_UNAVAILABLE,
    }.get(stop_reason() if reason is None else reason)


@dataclass(frozen=True)
class ScanProgress:
    stage: str
    state: ProgressState
    elapsed_seconds: float
    tool: str = ""


@dataclass
class ScanControl:
    timeout_seconds: int = 0
    progress: Callable[[ScanProgress], None] | None = None
    max_memory_bytes: int = 0
    started: float = field(default_factory=time.monotonic)
    _cancelled: threading.Event = field(default_factory=threading.Event)
    _progress_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _limits_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _next_memory_check: float = 0.0
    _memory_failure: str = ""
    _parent: ScanControl | None = field(default=None, repr=False)
    _dispatcher: ProgressDispatcher[ScanProgress] | None = field(
        default=None, init=False, repr=False
    )

    def __post_init__(self) -> None:
        for name in ("timeout_seconds", "max_memory_bytes"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")

    def cancel(self) -> None:
        self._cancelled.set()

    @property
    def reason(self) -> str:
        if self._parent is not None and (reason := self._parent.reason):
            return reason
        if self._cancelled.is_set():
            return "scan cancelled by operator"
        if (
            self.timeout_seconds
            and time.monotonic() - self.started >= self.timeout_seconds
        ):
            return "scan deadline exceeded"
        if self.max_memory_bytes:
            with self._limits_lock:
                if (
                    not self._memory_failure
                    and time.monotonic() >= self._next_memory_check
                ):
                    try:
                        if (
                            _process_tree_resident_bytes(os.getpid())
                            > self.max_memory_bytes
                        ):
                            self._memory_failure = (
                                "scan process-tree memory budget exceeded"
                            )
                    except RuntimeError:
                        self._memory_failure = (
                            "scan process-tree memory accounting unavailable"
                        )
                    self._next_memory_check = time.monotonic() + 0.1
        return self._memory_failure

    def emit(
        self,
        stage: str,
        state: ProgressState,
        tool: str = "",
    ) -> None:
        if self._parent is not None:
            self._parent.emit(stage, state, tool)
            return
        with self._progress_lock:
            if self.progress is not None:
                if self._dispatcher is None:
                    self._dispatcher = ProgressDispatcher(self.progress)
                self._dispatcher.submit(
                    ScanProgress(
                        stage, state, round(time.monotonic() - self.started, 3), tool
                    )
                )

    def finish_progress(self) -> None:
        if self._dispatcher is not None:
            self._dispatcher.finish()


_CONTROL: ContextVar[ScanControl | None] = ContextVar(
    "pysec_scan_control", default=None
)


def stop_reason() -> str:
    control = _CONTROL.get()
    return control.reason if control is not None else ""


def emit_progress(stage: str, state: ProgressState, tool: str = "") -> None:
    control = _CONTROL.get()
    if control is not None:
        control.emit(stage, state, tool)


@contextmanager
def scan_session(timeout_seconds: int, max_memory_bytes: int = 0) -> Iterator[None]:
    with controlled_scan(
        ScanControl(
            timeout_seconds, max_memory_bytes=max_memory_bytes, _parent=_CONTROL.get()
        )
    ):
        yield


@contextmanager
def controlled_scan(
    control: ScanControl, *, handle_interrupt: bool = False
) -> Iterator[None]:
    token = _CONTROL.set(control)
    previous = None
    install = handle_interrupt and threading.current_thread() is threading.main_thread()
    try:
        if install:
            previous = signal.signal(
                signal.SIGINT, lambda _signal, _frame: control.cancel()
            )
        yield
    finally:
        if install and previous is not None:
            signal.signal(signal.SIGINT, previous)
        _CONTROL.reset(token)
        if token.old_value is not control:
            control.finish_progress()
