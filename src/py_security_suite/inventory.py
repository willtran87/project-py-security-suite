from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from .models import Inventory


_SKIP_DIRECTORIES = {
    ".artifacts",
    ".git",
    ".hg",
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


def inventory_target(target: Path) -> Inventory:
    python_files = 0
    total_files = 0
    skipped_symlinks = 0
    dependency_files: list[str] = []
    lock_files: list[str] = []
    distribution_files = _distribution_files(target)
    for root, directories, filenames in os.walk(target, followlinks=False):
        root_path = Path(root)
        kept_directories: list[str] = []
        for directory in directories:
            path = root_path / directory
            if path.is_symlink():
                skipped_symlinks += 1
            elif directory not in _SKIP_DIRECTORIES:
                kept_directories.append(directory)
        directories[:] = kept_directories
        for filename in filenames:
            path = root_path / filename
            if path.is_symlink():
                skipped_symlinks += 1
                continue
            total_files += 1
            relative = path.relative_to(target).as_posix()
            if path.suffix == ".py":
                python_files += 1
            if filename.casefold() in _DEPENDENCY_FILES:
                dependency_files.append(relative)
            if filename.casefold() in _LOCK_FILES or filename.casefold().startswith(
                "pylock."
            ):
                lock_files.append(relative)
    return Inventory(
        python_files=python_files,
        dependency_files=sorted(dependency_files),
        total_files=total_files,
        skipped_symlinks=skipped_symlinks,
        declared_dependencies=_declares_dependencies(target),
        lock_files=sorted(lock_files),
        vcs_history_available=(target / ".git").exists(),
        distribution_files=sorted(distribution_files),
    )


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
            line.strip() and not line.lstrip().startswith(("#", "--"))
            for line in lines
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
