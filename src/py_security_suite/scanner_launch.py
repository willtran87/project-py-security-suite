"""Supervised scanner launch: limit gate, launch-failure signalling, cleanup.

The trusted bootstrap applies POSIX quotas, waits for the supervisor's gate,
then launches the scanner. Any failure inside the bootstrap (including a
``fork``/``CreateProcess`` failure such as ``EAGAIN`` under ``RLIMIT_NPROC``)
is recorded in a private ``launch-failure.json`` marker and reported with the
reserved exit code. The supervisor treats the marker, not the exit code, as
authoritative so a scanner cannot be mistaken for a clean run when it never
started.

On Linux the bootstrap becomes a child subreaper (``PR_SET_CHILD_SUBREAPER``):
descendants that ``setsid``/double-fork are re-parented to it instead of
``init`` and are swept after the scanner exits. Other POSIX platforms keep the
process-group kill plus a supervisor-side descendant snapshot; a descendant
that escapes both the process group and the parent chain before termination
remains a documented residual risk there.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - supervised scanner lifecycle helpers
import threading
from pathlib import Path

from .path_safety import read_regular_file
from .strict_json import loads as strict_loads

LAUNCH_FAILURE_EXIT_CODE = 126
LAUNCH_FAILURE_MARKER = "launch-failure.json"
SCRATCH_CHECK_INTERVAL_SECONDS = 0.25
AGGREGATE_OUTPUT_BUDGET_BYTES = 2 * 1024**3

LIMIT_GATE_BOOTSTRAP = r"""
import json, os, subprocess, sys, time
gate, report = sys.argv[1:3]
failure = os.path.join(os.path.dirname(report), "launch-failure.json")
def fail(stage, exc):
    try:
        with open(failure, "x", encoding="utf-8") as handle:
            json.dump({"stage": stage, "error": (type(exc).__name__ + ": " + str(exc))[:512]}, handle)
    except BaseException:
        pass
    os._exit(126)
def descendants():
    me, found = os.getpid(), []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/" + name + "/stat", "rb") as handle:
                fields = handle.read().rsplit(b")", 1)[1].split()
            if int(fields[1]) == me:
                found.append(int(name))
        except (OSError, ValueError, IndexError):
            continue
    return found
def sweep():
    for _ in range(64):
        children = descendants()
        if not children:
            return
        for pid in children:
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        for pid in children:
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
    raise RuntimeError("scanner descendants kept respawning during cleanup")
enforced, errors = [], []
try:
    if os.name != "nt":
        import resource
        memory_limits = (
            ()
            if sys.platform == "darwin"
            else (("address-space", "RLIMIT_AS", 8 * 1024**3),)
        )
        requested_limits = (
            *memory_limits,
            ("process-count", "RLIMIT_NPROC", None if sys.platform == "darwin" else 256),
            ("open-files", "RLIMIT_NOFILE", 2048),
            ("file-size", "RLIMIT_FSIZE", int(sys.argv[5])),
            ("cpu-time", "RLIMIT_CPU", max(1, int(sys.argv[4]))),
        )
        for name, constant, requested in requested_limits:
            try:
                kind = getattr(resource, constant)
                current_soft, current_hard = resource.getrlimit(kind)
                value = requested
                if requested is None:
                    value = current_soft if current_soft != resource.RLIM_INFINITY else 4096
                if current_hard != resource.RLIM_INFINITY:
                    value = min(value, current_hard)
                if current_soft != resource.RLIM_INFINITY:
                    value = min(value, current_soft)
                # Drop the hard ceiling too: an untrusted scanner must not be
                # able to raise its soft quota back to the inherited maximum.
                resource.setrlimit(kind, (value, value))
                enforced.append(name)
            except (AttributeError, OSError, ValueError) as exc:
                errors.append(f"{name}:{exc}")
        if sys.platform.startswith("linux"):
            try:
                import ctypes
                libc = ctypes.CDLL(None, use_errno=True)
                if libc.prctl(36, 1, 0, 0, 0) != 0:
                    raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")
                enforced.append("descendant-subreaper")
            except (AttributeError, OSError) as exc:
                errors.append(f"descendant-subreaper:{exc}")
    temporary_report = report + ".tmp"
    with open(temporary_report, "x", encoding="utf-8") as handle:
        json.dump({"enforced": enforced, "errors": errors}, handle)
    os.replace(temporary_report, report)
    deadline = time.monotonic() + 10
    while not os.path.exists(gate):
        if time.monotonic() >= deadline:
            raise SystemExit(125)
        time.sleep(0.005)
except SystemExit:
    raise
except BaseException as exc:
    fail("bootstrap", exc)
try:
    child = subprocess.Popen(sys.argv[6:])
except BaseException as exc:
    fail("launch", exc)
code = child.wait()
if "descendant-subreaper" in enforced:
    try:
        sweep()
    except BaseException as exc:
        fail("descendant-cleanup", exc)
raise SystemExit(code)
""".strip()


def launch_failure(private_root: Path) -> str:
    """Return the bootstrap's recorded launch failure, if one was recorded."""
    marker = private_root / LAUNCH_FAILURE_MARKER
    if not marker.exists() and not marker.is_symlink():
        return ""
    try:
        _, payload = read_regular_file(
            marker,
            "scanner launch-failure marker",
            maximum_bytes=4096,
            boundary=private_root,
        )
        value = strict_loads(payload)
    except (OSError, TypeError, ValueError):
        return "scanner launch failed: unreadable launch-failure marker"
    if not isinstance(value, dict):
        return "scanner launch failed: invalid launch-failure marker"
    stage = str(value.get("stage") or "unknown")[:64]
    error = str(value.get("error") or "unknown error")[:512]
    return f"scanner launch failed during {stage}: {error}"


def directory_size_exceeds(root: Path, maximum: int) -> bool:
    total = 0
    entries = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = list(os.scandir(directory))
        except OSError:
            continue
        for child in children:
            entries += 1
            if entries > 100_000:
                return True
            try:
                if child.is_symlink():
                    continue
                if child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
                elif child.is_file(follow_symlinks=False):
                    total += child.stat(follow_symlinks=False).st_size
                    if total >= maximum:
                        return True
            except OSError:
                continue
    return False


def wait_quietly(process: subprocess.Popen[bytes], timeout: float) -> bool:
    """Wait during cleanup without letting a timeout mask the original error."""
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return True


def kill_then_wait(process: subprocess.Popen[bytes], timeout: float) -> bool:
    if wait_quietly(process, timeout):
        return True
    try:
        process.kill()
    except OSError:
        pass
    return wait_quietly(process, timeout)


def descendant_snapshot(pid: int) -> list[object]:
    """Capture the live descendant tree while its parent chain is intact."""
    try:
        import psutil

        return list(psutil.Process(pid).children(recursive=True))
    except Exception:  # noqa: BLE001 - best-effort snapshot; group kill remains
        return []


def kill_descendants(descendants: list[object]) -> None:
    for descendant in reversed(descendants):
        kill = getattr(descendant, "kill", None)
        if not callable(kill):
            continue
        try:
            kill()
        except Exception:  # noqa: BLE001,S110 - already exited or inaccessible
            pass


class OutputBudget:
    """Process-wide ceiling on bytes buffered from concurrent scanner pipes."""

    def __init__(self, maximum: int) -> None:
        self._maximum = maximum
        self._used = 0
        self._lock = threading.Lock()

    def reserve(self, size: int) -> bool:
        with self._lock:
            if self._used + size > self._maximum:
                return False
            self._used += size
            return True

    def release(self, size: int) -> None:
        with self._lock:
            self._used = max(0, self._used - size)


OUTPUT_BUDGET = OutputBudget(AGGREGATE_OUTPUT_BUDGET_BYTES)
