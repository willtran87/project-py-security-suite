from __future__ import annotations

from pathlib import Path


def is_link_like(path: Path) -> bool:
    """Return whether the requested path is a symbolic link or junction."""
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(is_junction) and bool(is_junction()))


def resolve_unlinked_path(
    path: Path,
    label: str,
    *,
    boundary: Path | None = None,
) -> Path:
    """Resolve a path after validating its governed filesystem components."""
    requested = path.expanduser().absolute()
    components = [requested]
    if boundary is not None:
        governed_root = boundary.expanduser().absolute()
        try:
            relative = requested.relative_to(governed_root)
        except ValueError:
            pass
        else:
            if ".." in relative.parts:
                raise ValueError(f"{label} cannot traverse outside its boundary")
            components = [governed_root]
            current = governed_root
            for part in relative.parts:
                current /= part
                components.append(current)
    for component in components:
        if is_link_like(component):
            if component == requested:
                raise ValueError(
                    f"{label} cannot be a symbolic link or junction: {component}"
                )
            raise ValueError(
                f"{label} cannot contain a symbolic link or junction: {component}"
            )
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
