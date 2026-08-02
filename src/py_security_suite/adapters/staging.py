from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
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


def maintained_files(target: Path, suffixes: frozenset[str]) -> list[Path]:
    return [
        path
        for path in maintained_repository_files(target)
        if path.suffix.casefold() in suffixes
    ]


def maintained_repository_files(target: Path) -> list[Path]:
    """List maintained files while pruning generated and tool-owned trees."""
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
            if candidate.is_symlink():
                continue
            matches.append(candidate)
    return matches


@contextmanager
def mirrored_source_tree(target: Path) -> Iterator[Path]:
    root = target.resolve()
    with tempfile.TemporaryDirectory(prefix="pysec-source-") as directory:
        mirror = Path(directory) / "repository"
        mirror.mkdir()
        for current, directory_names, file_names in os.walk(root, topdown=True):
            directory_names[:] = sorted(
                name
                for name in directory_names
                if name not in SKIPPED_DIRECTORIES
                and not (Path(current) / name).is_symlink()
            )
            relative = Path(current).relative_to(root)
            destination = mirror / relative
            destination.mkdir(parents=True, exist_ok=True)
            for name in sorted(file_names):
                source = Path(current) / name
                if source.is_symlink():
                    continue
                shutil.copy2(source, destination / name)
        yield mirror
