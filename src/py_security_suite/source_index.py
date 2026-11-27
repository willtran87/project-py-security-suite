"""Bounded, scan-local source reuse; never persisted between snapshots."""

from __future__ import annotations

import ast
import hashlib
import os
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path

from .path_safety import read_regular_file


_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_CACHE_BYTES = 8 * 1024 * 1024
_MAX_AST_NODES = 100_000
_MAX_AST_BYTES = 8 * 1024 * 1024


class SourceLimitError(ValueError):
    """Source cannot be admitted within the parser's input budget."""


def read_python_source(path: Path, root: Path) -> str:
    try:
        _, payload = read_regular_file(
            path, "Python source", maximum_bytes=_MAX_FILE_BYTES, boundary=root
        )
    except ValueError as exc:
        raise SourceLimitError(
            "Python source exceeds limits or is not a safe file"
        ) from exc
    return payload.decode("utf-8-sig")


def _tree_size(tree: ast.Module) -> tuple[int, int]:
    """Account for AST attributes, containers and literal payloads once each."""
    pending: list[object] = [tree]
    seen: set[int] = set()
    nodes = size = 0
    while pending:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        size += sys.getsizeof(item)
        if isinstance(item, ast.AST):
            nodes += 1
            pending.append(vars(item))
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
        if size > _MAX_AST_BYTES or nodes > _MAX_AST_NODES:
            break
    return nodes, size


@dataclass
class SourceIndex:
    root: Path
    excerpts: dict[Path, tuple[str, ...] | None] = field(default_factory=dict)
    trees: dict[tuple[str, str], ast.Module] = field(default_factory=dict)
    retained_bytes: int = 0
    retained_nodes: int = 0
    retained_ast_bytes: int = 0
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def lines(self, path: Path) -> tuple[str, ...] | None:
        with self._lock:
            resolved = path.resolve()
            if not resolved.is_relative_to(self.root):
                raise ValueError("source excerpt is outside the scan snapshot")
            if resolved in self.excerpts:
                return self.excerpts[resolved]
            with resolved.open("rb") as handle:
                payload = handle.read(_MAX_FILE_BYTES + 1)
            if len(payload) > _MAX_FILE_BYTES:
                lines = None
            else:
                text = (
                    payload.decode("utf-8", errors="replace")
                    .replace("\r\n", "\n")
                    .replace("\r", "\n")
                )
                parts = text.split("\n")
                lines = tuple(parts[:-1] if parts[-1] == "" else parts)
            if (
                len(self.excerpts) < 256
                and self.retained_bytes + len(payload) <= _MAX_CACHE_BYTES
            ):
                self.excerpts[resolved] = lines
                self.retained_bytes += len(payload)
            return lines

    def parse(self, text: str, filename: str) -> ast.Module:
        if len(text) > _MAX_FILE_BYTES or len(text.encode("utf-8")) > _MAX_FILE_BYTES:
            raise SourceLimitError("Python source exceeds the 2 MiB parser input limit")
        with self._lock:
            key = (filename, hashlib.sha256(text.encode("utf-8")).hexdigest())
            if key in self.trees:
                return self.trees[key]
            tree = ast.parse(text, filename=filename)
            count, size = _tree_size(tree)
            if (
                len(self.trees) < 128
                and self.retained_nodes + count <= _MAX_AST_NODES
                and self.retained_ast_bytes + size <= _MAX_AST_BYTES
            ):
                self.trees[key] = tree
                self.retained_nodes += count
                self.retained_ast_bytes += size
            return tree


_INDEX: ContextVar[SourceIndex | None] = ContextVar("pysec_source_index", default=None)


@contextmanager
def source_analysis_session(root: Path) -> Iterator[SourceIndex]:
    index = _INDEX.get()
    if index is not None and index.root == root.resolve():
        yield index
        return
    index = SourceIndex(root.resolve())
    token = _INDEX.set(index)
    try:
        yield index
    finally:
        _INDEX.reset(token)


def parse_python(text: str, filename: str) -> ast.Module:
    """Return a shared read-only AST, keyed by exact content and source name."""
    index = _INDEX.get()
    return (
        index.parse(text, filename)
        if index is not None
        else SourceIndex(Path.cwd()).parse(text, filename)
    )


def source_lines(path: Path) -> tuple[str, ...] | None:
    index = _INDEX.get()
    return (index or SourceIndex(path.parent.resolve())).lines(path)


def source_files(root: Path, skipped: frozenset[str] | set[str]) -> list[Path]:
    """Prune excluded trees before descending, preserving lexical path order."""
    result: list[Path] = []
    for current, directories, names in os.walk(root, followlinks=False):
        parent = Path(current)
        directories[:] = [
            name
            for name in directories
            if name not in skipped and not (parent / name).is_symlink()
        ]
        result.extend(
            parent / name
            for name in names
            if not (parent / name).is_symlink() and (parent / name).is_file()
        )
    return sorted(result, key=lambda path: path.relative_to(root).as_posix())
