from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from ..repository_file_policy import (
    SKIPPED_DIRECTORIES,
    maintained_repository_files,
)


def maintained_files(target: Path, suffixes: frozenset[str]) -> list[Path]:
    return [
        path
        for path in maintained_repository_files(target)
        if path.suffix.casefold() in suffixes
    ]


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
