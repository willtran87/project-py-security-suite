"""Resident-memory accounting shared by scanner supervision."""

from __future__ import annotations


def process_tree_resident_bytes(pid: int) -> int:
    """Return current aggregate RSS for one live process tree."""
    import psutil

    try:
        root = psutil.Process(pid)
        processes = [root, *root.children(recursive=True)]
        total = 0
        for candidate in processes:
            try:
                total += candidate.memory_info().rss
            except psutil.NoSuchProcess:
                continue
        return total
    except psutil.NoSuchProcess:
        return 0
    except (psutil.AccessDenied, OSError) as exc:
        raise RuntimeError("resident-memory-watchdog:unavailable") from exc
