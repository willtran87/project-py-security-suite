from __future__ import annotations

import re
from pathlib import PurePosixPath


_REPOSITORY_PATH = re.compile(r"[A-Za-z0-9_.\-/]+\Z")


def repository_relative_path(value: str, label: str) -> str:
    """Return a normalized, shell-inert repository-relative path."""
    candidate = PurePosixPath(value.replace("\\", "/"))
    if (
        candidate.is_absolute()
        or not candidate.parts
        or ".." in candidate.parts
        or any(not part or part == "." for part in candidate.parts)
        or _REPOSITORY_PATH.fullmatch(candidate.as_posix()) is None
    ):
        raise ValueError(f"{label} must be a normalized repository-relative path")
    return candidate.as_posix()
