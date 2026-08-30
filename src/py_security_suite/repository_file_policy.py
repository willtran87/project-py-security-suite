from __future__ import annotations

import os
from pathlib import Path


SKIPPED_DIRECTORIES = frozenset(
    {
        ".artifacts",
        ".git",
        ".mypy_cache",
        ".pysec-tools",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
    }
)


def maintained_repository_files(target: Path) -> list[Path]:
    """List maintained regular files while pruning generated and linked trees."""

    root = target.resolve()
    matches: list[Path] = []
    for current, directory_names, file_names in os.walk(root, topdown=True):
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in SKIPPED_DIRECTORIES
            and not (Path(current) / name).is_symlink()
        )
        current_path = Path(current)
        for name in sorted(file_names):
            candidate = current_path / name
            if not candidate.is_symlink():
                matches.append(candidate)
    return matches
