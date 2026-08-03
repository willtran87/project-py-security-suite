from __future__ import annotations

from pathlib import Path


def is_link_like(path: Path) -> bool:
    """Return whether the requested path is a symbolic link or junction."""
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(is_junction) and bool(is_junction()))


def resolve_unlinked_path(path: Path, label: str) -> Path:
    """Resolve a path only after validating the requested filesystem object."""
    requested = path.expanduser().absolute()
    if is_link_like(requested):
        raise ValueError(f"{label} cannot be a symbolic link or junction: {requested}")
    return requested.resolve()


def resolve_regular_file(path: Path, label: str) -> Path:
    resolved = resolve_unlinked_path(path, label)
    if not resolved.is_file():
        raise ValueError(f"{label} is not a regular file: {resolved}")
    return resolved


def resolve_regular_directory(path: Path, label: str) -> Path:
    resolved = resolve_unlinked_path(path, label)
    if not resolved.is_dir():
        raise ValueError(f"{label} is not a regular directory: {resolved}")
    return resolved
