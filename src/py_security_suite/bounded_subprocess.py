from __future__ import annotations

import queue
import math
import os
import signal
import subprocess
import sys
import threading
import time
from io import BufferedReader
from typing import cast
from dataclasses import dataclass
from collections.abc import Mapping, Sequence

import psutil

from .scan_control import stop_reason
from .process_containment import apply_windows_job_limits, close_windows_handle

# The trusted launcher cannot start caller code until the supervisor assigns its
# Job Object and writes the gate byte. Read exactly one byte without buffering
# so the eventual command receives the original stdin payload unchanged.
_WINDOWS_GATE = (
    "import os,subprocess,sys; "
    "gate=os.read(0,1); "
    "sys.exit(subprocess.call(sys.argv[1:]) if gate == b'\\x00' else 125)"
)


class BoundedSubprocessError(ValueError):
    """Raised when a subprocess violates timeout or output containment."""


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Best-effort termination of the exact child and every descendant."""

    try:
        parent = psutil.Process(process.pid)
        descendants = parent.children(recursive=True)
    except psutil.Error:
        descendants = []
        parent = None
    for child in reversed(descendants):
        try:
            child.kill()
        except psutil.Error:
            continue
    if parent is not None:
        try:
            parent.kill()
        except psutil.Error:
            pass
    elif process.poll() is None:
        process.kill()
    if descendants:
        psutil.wait_procs(descendants, timeout=2.0)


def run_bounded_subprocess(
    argv: Sequence[str],
    *,
    input_bytes: bytes = b"",
    timeout_seconds: float,
    maximum_stdout_bytes: int,
    maximum_stderr_bytes: int,
    environment: Mapping[str, str],
) -> BoundedProcessResult:
    """Execute without a shell while bounding both pipes during the run."""
    if (
        not argv
        or not 0.1 <= timeout_seconds <= 60.0
        or not 1 <= maximum_stdout_bytes <= 16 * 1024 * 1024
        or not 1 <= maximum_stderr_bytes <= 16 * 1024 * 1024
    ):
        raise BoundedSubprocessError("bounded subprocess configuration is invalid")
    if stop_reason():
        raise BoundedSubprocessError(stop_reason())
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(  # noqa: S603 - caller validates executable trust
            [sys.executable, "-I", "-c", _WINDOWS_GATE, *argv]
            if os.name == "nt"
            else list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=dict(environment),
            start_new_session=os.name != "nt",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            if os.name == "nt"
            else 0,
        )
    except OSError as exc:
        raise BoundedSubprocessError("bounded subprocess could not be started") from exc
    job: int | None = None
    try:
        if os.name == "nt":
            _, _, job = apply_windows_job_limits(
                process, timeout_seconds=math.ceil(timeout_seconds)
            )
    except BaseException:
        _kill_process_tree(process)
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        raise

    def terminate() -> None:
        nonlocal job
        if job is not None:
            close_windows_handle(job)
            job = None
        elif os.name != "nt":
            try:
                os.__dict__["killpg"](process.pid, signal.__dict__["SIGKILL"])
            except ProcessLookupError:
                pass
            except PermissionError:
                # macOS can deny killpg after the leader exits. Still attempt
                # termination through the exact process handles we own.
                _kill_process_tree(process)
        if process.poll() is None:
            _kill_process_tree(process)

    streams = (process.stdout, process.stderr)
    limits = (maximum_stdout_bytes, maximum_stderr_bytes)
    chunks: list[list[bytes]] = [[], []]
    totals = [0, 0]
    failures: queue.SimpleQueue[OSError] = queue.SimpleQueue()
    overflow = threading.Event()

    def drain(index: int) -> None:
        stream = streams[index]
        if stream is None:  # pragma: no cover - established by Popen arguments
            return
        try:
            while piece := cast(BufferedReader, stream).read1(8192):
                totals[index] += len(piece)
                if totals[index] <= limits[index]:
                    chunks[index].append(piece)
                else:
                    overflow.set()
        except OSError as exc:  # pragma: no cover - platform pipe failure
            failures.put(exc)
        finally:
            stream.close()

    def feed() -> None:
        if process.stdin is None:  # pragma: no cover - established by Popen
            return
        try:
            if os.name == "nt":
                process.stdin.write(b"\x00")
                process.stdin.flush()
            process.stdin.write(input_bytes)
        except BrokenPipeError:
            pass  # A child may legitimately exit without consuming all input.
        except OSError as exc:
            failures.put(exc)
        finally:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
            except OSError as exc:
                failures.put(exc)

    readers = [
        threading.Thread(target=drain, args=(index,), daemon=True) for index in range(2)
    ]
    workers = [*readers, threading.Thread(target=feed, daemon=True)]
    violation: str | None = None
    started_workers: list[threading.Thread] = []
    try:
        for reader in workers:
            reader.start()
            started_workers.append(reader)
        while True:
            if overflow.is_set():
                violation = "bounded subprocess output exceeded limit"
                break
            if stop_reason() or time.monotonic() >= deadline:
                violation = stop_reason() or "bounded subprocess timed out"
                break
            if process.poll() is not None:
                # Close the OS boundary before waiting for pipe EOF, including
                # when the leader exits successfully but leaves children behind.
                break
            time.sleep(0.01)
    finally:
        terminate()
        process.wait(timeout=5)
        for reader in started_workers:
            reader.join(timeout=2.0)
        if any(reader.is_alive() for reader in started_workers):
            violation = "bounded subprocess pipe cleanup did not complete"
        else:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
    if violation is not None:
        raise BoundedSubprocessError(violation)
    if not failures.empty():
        raise BoundedSubprocessError("bounded subprocess output capture failed")
    if overflow.is_set():
        raise BoundedSubprocessError("bounded subprocess output exceeded limit")
    return BoundedProcessResult(
        process.returncode, b"".join(chunks[0]), b"".join(chunks[1])
    )
