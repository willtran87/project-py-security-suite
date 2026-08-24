from __future__ import annotations

import os
import stat
from pathlib import Path


def read_bounded_regular(path: Path, maximum: int, label: str) -> bytes:
    """Read one bounded non-link file while holding a stable descriptor."""
    requested = path.expanduser().absolute()
    if requested.is_symlink() or bool(
        callable(getattr(requested, "is_junction", None)) and requested.is_junction()
    ):
        raise ValueError(f"{label} must not be a symbolic link or junction")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(requested, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError(f"{label} must be a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(maximum + 1)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError(f"{label} changed while it was being read")
        if len(payload) > maximum:
            raise ValueError(f"{label} exceeds its byte limit")
        return payload
    finally:
        os.close(descriptor)
