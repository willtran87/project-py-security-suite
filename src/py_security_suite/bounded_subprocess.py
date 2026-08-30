from __future__ import annotations

import queue
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Mapping, Sequence


class BoundedSubprocessError(ValueError):
    """Raised when a subprocess violates timeout or output containment."""


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


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
    try:
        process = subprocess.Popen(  # noqa: S603 - caller validates executable trust
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=dict(environment),
        )
    except OSError as exc:
        raise BoundedSubprocessError("bounded subprocess could not be started") from exc
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
            while piece := stream.read(8192):
                totals[index] += len(piece)
                if totals[index] <= limits[index]:
                    chunks[index].append(piece)
                else:
                    overflow.set()
        except OSError as exc:  # pragma: no cover - platform pipe failure
            failures.put(exc)

    readers = [
        threading.Thread(target=drain, args=(index,), daemon=True) for index in range(2)
    ]
    for reader in readers:
        reader.start()
    violation: str | None = None
    try:
        if process.stdin is None:  # pragma: no cover - established by Popen arguments
            violation = "bounded subprocess input pipe is unavailable"
        else:
            try:
                process.stdin.write(input_bytes)
            except BrokenPipeError:
                pass
            finally:
                process.stdin.close()
        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None:
            if overflow.is_set():
                violation = "bounded subprocess output exceeded limit"
                process.kill()
                break
            if time.monotonic() >= deadline:
                violation = "bounded subprocess timed out"
                process.kill()
                break
            time.sleep(0.01)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        for reader in readers:
            reader.join(timeout=1.0)
    if violation is not None:
        raise BoundedSubprocessError(violation)
    if not failures.empty():
        raise BoundedSubprocessError("bounded subprocess output capture failed")
    if overflow.is_set():
        raise BoundedSubprocessError("bounded subprocess output exceeded limit")
    return BoundedProcessResult(
        process.returncode, b"".join(chunks[0]), b"".join(chunks[1])
    )
