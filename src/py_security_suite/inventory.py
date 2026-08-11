from __future__ import annotations

import hashlib
import os
import tomllib
from pathlib import Path
from typing import Any

from .execution import resolve_executable, run_command
from .models import Inventory


_SKIP_DIRECTORIES = frozenset(
    {
        ".artifacts",
        ".git",
        ".hg",
        ".mypy_cache",
        ".nox",
        ".pysec-tools",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "env",
        "venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
    }
)
_INTEGRITY_SKIP_DIRECTORIES = _SKIP_DIRECTORIES - {"build", "dist"}
_DEPENDENCY_FILES = {
    "requirements.txt",
    "requirements-dev.txt",
    "poetry.lock",
    "pdm.lock",
    "pipfile.lock",
    "uv.lock",
    "pylock.toml",
    "pyproject.toml",
}
_LOCK_FILES = {
    "pipfile.lock",
    "poetry.lock",
    "pdm.lock",
    "uv.lock",
    "pylock.toml",
    "requirements.lock",
}


def inventory_target(
    target: Path, *, excluded_paths: tuple[Path, ...] = ()
) -> Inventory:
    inventory, _ = inventory_target_with_evidence(target, excluded_paths=excluded_paths)
    return inventory


def inventory_target_with_evidence(
    target: Path, *, excluded_paths: tuple[Path, ...] = ()
) -> tuple[Inventory, dict[str, Any]]:
    """Inventory a target and retain the exact file identities behind its digest."""
    python_files = 0
    dependency_files: list[str] = []
    lock_files: list[str] = []
    distribution_files = _distribution_files(target)
    maintained_files, skipped_symlinks = _maintained_files(target, excluded_paths)
    integrity_files, _ = _maintained_files(
        target,
        excluded_paths,
        skip_directories=_INTEGRITY_SKIP_DIRECTORIES,
    )
    source_evidence = _source_inventory(target, integrity_files)
    source_sha256 = str(source_evidence["source_sha256"])
    hashed_bytes = int(source_evidence["total_bytes"])
    for path in maintained_files:
        relative = path.relative_to(target).as_posix()
        if path.suffix == ".py":
            python_files += 1
        if path.name.casefold() in _DEPENDENCY_FILES:
            dependency_files.append(relative)
        if path.name.casefold() in _LOCK_FILES or path.name.casefold().startswith(
            "pylock."
        ):
            lock_files.append(relative)
    vcs_revision, vcs_revision_verified = _vcs_revision(target)
    inventory = Inventory(
        python_files=python_files,
        dependency_files=sorted(dependency_files),
        total_files=len(maintained_files),
        skipped_symlinks=skipped_symlinks,
        declared_dependencies=_declares_dependencies(target),
        lock_files=sorted(lock_files),
        vcs_history_available=(target / ".git").exists(),
        vcs_revision=vcs_revision,
        vcs_revision_verified=vcs_revision_verified,
        distribution_files=sorted(distribution_files),
        source_sha256=source_sha256,
        hashed_files=len(integrity_files),
        hashed_bytes=hashed_bytes,
    )
    return inventory, source_evidence


def _vcs_revision(target: Path) -> tuple[str, bool]:
    if not (target / ".git").exists():
        return "", False
    executable = resolve_executable("git")
    if executable is None:
        return "", False
    result = run_command(
        [
            executable,
            "-c",
            f"safe.directory={target.resolve()}",
            "rev-parse",
            "--verify",
            "HEAD",
        ],
        cwd=target,
        timeout_seconds=10,
        max_output_bytes=4096,
    )
    revision = result.stdout.strip().casefold()
    verified = (
        not result.timed_out
        and result.exit_code == 0
        and len(revision) == 40
        and all(character in "0123456789abcdef" for character in revision)
    )
    return (revision if verified else ""), verified


def source_snapshot(
    target: Path, *, excluded_paths: tuple[Path, ...] = ()
) -> tuple[str, int, int]:
    files, _ = _maintained_files(
        target,
        excluded_paths,
        skip_directories=_INTEGRITY_SKIP_DIRECTORIES,
    )
    digest, total_bytes = _source_digest(target, files)
    return digest, len(files), total_bytes


def _maintained_files(
    target: Path,
    excluded_paths: tuple[Path, ...],
    *,
    skip_directories: frozenset[str] = _SKIP_DIRECTORIES,
) -> tuple[list[Path], int]:
    resolved_target = target.resolve()
    excluded = tuple(path.resolve() for path in excluded_paths)
    files: list[Path] = []
    skipped_symlinks = 0
    for root, directories, filenames in os.walk(resolved_target, followlinks=False):
        root_path = Path(root)
        kept_directories: list[str] = []
        for directory in sorted(directories):
            path = root_path / directory
            if path.is_symlink():
                skipped_symlinks += 1
            elif directory not in skip_directories and not _is_excluded(path, excluded):
                kept_directories.append(directory)
        directories[:] = kept_directories
        for filename in sorted(filenames):
            path = root_path / filename
            if path.is_symlink():
                skipped_symlinks += 1
                continue
            if not _is_excluded(path, excluded):
                files.append(path)
    return sorted(
        files,
        key=lambda path: path.relative_to(resolved_target).as_posix(),
    ), skipped_symlinks


def _is_excluded(path: Path, excluded: tuple[Path, ...]) -> bool:
    resolved = path.resolve()
    for root in excluded:
        if resolved == root:
            return True
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _source_digest(target: Path, paths: list[Path]) -> tuple[str, int]:
    evidence = _source_inventory(target, paths)
    return str(evidence["source_sha256"]), int(evidence["total_bytes"])


def _source_inventory(target: Path, paths: list[Path]) -> dict[str, Any]:
    aggregate = hashlib.sha256()
    total_bytes = 0
    resolved_target = target.resolve()
    records: list[dict[str, Any]] = []
    for path in paths:
        content = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                content.update(chunk)
                size += len(chunk)
        relative = path.relative_to(resolved_target).as_posix().encode("utf-8")
        aggregate.update(len(relative).to_bytes(8, "big"))
        aggregate.update(relative)
        aggregate.update(size.to_bytes(8, "big"))
        aggregate.update(content.digest())
        total_bytes += size
        records.append(
            {
                "path": relative.decode("utf-8"),
                "size_bytes": size,
                "sha256": content.hexdigest(),
            }
        )
    return {
        "schema_version": "1.0",
        "scope": (
            "Exact regular-file identities included in the target source digest; "
            "generated scanner and report directories are excluded."
        ),
        "source_sha256": aggregate.hexdigest(),
        "total_files": len(records),
        "total_bytes": total_bytes,
        "files": records,
    }


def _declares_dependencies(target: Path) -> bool:
    pyproject = target / "pyproject.toml"
    if pyproject.is_file():
        try:
            with pyproject.open("rb") as handle:
                document: dict[str, Any] = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            return True
        project = document.get("project")
        if isinstance(project, dict):
            dependencies = project.get("dependencies")
            if isinstance(dependencies, list) and dependencies:
                return True
            optional = project.get("optional-dependencies")
            if isinstance(optional, dict) and any(optional.values()):
                return True
        poetry = document.get("tool", {}).get("poetry", {})
        if isinstance(poetry, dict):
            dependencies = poetry.get("dependencies")
            if isinstance(dependencies, dict) and any(
                str(name).casefold() != "python" for name in dependencies
            ):
                return True
        groups = document.get("dependency-groups")
        if isinstance(groups, dict) and any(groups.values()):
            return True

    for name in ("requirements.txt", "requirements-dev.txt"):
        path = target / name
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return True
        if any(
            line.strip() and not line.lstrip().startswith(("#", "--")) for line in lines
        ):
            return True
    return False


def _distribution_files(target: Path) -> list[str]:
    root = target / "dist"
    if not root.is_dir():
        return []
    return sorted(
        path.relative_to(target).as_posix()
        for path in root.iterdir()
        if path.is_file()
        and (
            path.suffix.casefold() == ".whl"
            or path.name.casefold().endswith((".tar.gz", ".zip"))
        )
    )
