"""Cleanup issues must not replace a published result or its original failure.

Cleanup never raises, but it is never silent either: a retained directory is
reported at ERROR level with its path, and callers learn the outcome from the
return value so evidence-bearing leftovers (such as the previous report kept
as a publication backup) can be surfaced explicitly.
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
from pathlib import Path


def _make_writable(root: Path) -> None:
    """Clear read-only attributes that block deletion (common on Windows)."""
    for directory, names, files in os.walk(root, followlinks=False):
        for name in (*names, *files):
            try:
                os.chmod(
                    os.path.join(directory, name),
                    stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC,
                    follow_symlinks=False,
                )
            except (NotImplementedError, OSError):
                continue


def cleanup_directory(
    path: Path, *, recursive: bool = True, contents: str = "directory"
) -> bool:
    """Remove ``path``; return False (and log the retained path) on failure."""
    try:
        if not recursive:
            path.rmdir()
            return True
        try:
            shutil.rmtree(path)
        except OSError:
            if path.is_symlink():
                raise
            _make_writable(path)
            shutil.rmtree(path)
    except OSError as exc:
        logging.getLogger(__name__).error(
            "Report cleanup incomplete; retained %s at %s (%s). Remove it manually.",
            contents,
            str(path),
            type(exc).__name__,
        )
        return False
    return True
