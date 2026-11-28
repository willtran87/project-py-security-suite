"""Sample a real scanner invocation and its private temporary workspace."""

from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import threading
import time

from py_security_suite.process_memory import process_tree_resident_bytes


def scratch_bytes(root: Path) -> int:
    total = 0
    for count, path in enumerate(root.rglob("*"), start=1):
        if count > 100000:
            raise ValueError("resource sample exceeds 100000 entries")
        try:
            if path.is_symlink():
                raise ValueError("resource sample contains a link")
            if path.is_file():
                total += path.stat().st_size
        except FileNotFoundError:
            continue
    return total


@contextmanager
def native_resources():
    record = {
        "scope": "sampled driver and native child process tree; private scratch only",
        "sample_interval_seconds": 0.1,
        "peak_rss_bytes": 0,
        "peak_scratch_bytes": 0,
        "samples": 0,
        "measurement_complete": False,
    }
    started = time.monotonic()
    done = threading.Event()
    # Keep the parent short: native Windows IPC paths have a small fixed limit.
    with tempfile.TemporaryDirectory(prefix="") as temporary:
        root = Path(temporary)
        previous = tempfile.tempdir
        # This driver executes one invocation at a time. run_command allocates its
        # isolated HOME/TMP beneath this root; external caches are outside the metric.
        tempfile.tempdir = temporary

        def sample():
            while not done.is_set():
                try:
                    record["peak_rss_bytes"] = max(
                        record["peak_rss_bytes"],
                        process_tree_resident_bytes(os.getpid()),
                    )
                    record["peak_scratch_bytes"] = max(
                        record["peak_scratch_bytes"], scratch_bytes(root)
                    )
                    record["samples"] += 1
                except (OSError, RuntimeError, ValueError) as exc:
                    record["error_category"] = type(exc).__name__
                    return
                done.wait(0.1)

        watcher = threading.Thread(target=sample, daemon=True)
        watcher.start()
        try:
            yield record
        finally:
            done.set()
            watcher.join()
            tempfile.tempdir = previous
            record["duration_seconds"] = round(time.monotonic() - started, 3)
            record["measurement_complete"] = (
                bool(record["samples"]) and "error_category" not in record
            )
