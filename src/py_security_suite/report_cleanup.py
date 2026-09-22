"""Cleanup issues must not replace a published result or its original failure."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path


def cleanup_directory(path: Path, *, recursive: bool = True) -> None:
    try:
        if recursive:
            shutil.rmtree(path)
        else:
            path.rmdir()
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "Report cleanup incomplete; retained directory %r (%s)",
            path,
            type(exc).__name__,
        )
