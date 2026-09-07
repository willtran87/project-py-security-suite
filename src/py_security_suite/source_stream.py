"""Bounded, interruptible source hashing and copying through verified handles."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO

from .path_safety import open_regular_file
from .scan_control import analysis_checkpoint


def stream_source(
    path: Path,
    boundary: Path,
    *,
    destination: BinaryIO | None = None,
    maximum_bytes: int | None = None,
    cancellable: bool = True,
) -> tuple[int, str]:
    if cancellable:
        analysis_checkpoint()
    limit = path.stat().st_size if maximum_bytes is None else maximum_bytes
    digest = hashlib.sha256()
    size = 0
    with open_regular_file(
        path, "source member", maximum_bytes=max(1, limit), boundary=boundary
    ) as (_, handle, _):
        while True:
            if cancellable:
                analysis_checkpoint()
            chunk = handle.read(min(1024 * 1024, limit - size + 1))
            if cancellable:
                analysis_checkpoint()
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError(
                    "source member exceeds its recorded size or copy limit"
                )
            digest.update(chunk)
            if destination is not None:
                destination.write(chunk)
    return size, digest.hexdigest()
