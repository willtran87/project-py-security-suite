"""Bind the interpreter's site directories into a scanner runtime closure.

``python -I`` still runs ``site``: every ``*.pth`` file in a site directory is
processed (``import`` lines execute code) and ``sitecustomize`` /
``usercustomize`` are imported. A file that no installed distribution owns is
therefore code the approved distribution closure never hashed. Unowned startup
files and unowned importable modules/packages fail the closure; every startup
file that remains is hashed into it. The virtual-environment bootstrap written
by ``virtualenv``/``uv`` (``_virtualenv.pth`` and ``_virtualenv.py``) is the
only accepted unowned content, only inside a virtual environment, and is
hashed like everything else.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import site
import sys
import sysconfig
from pathlib import Path, PurePath

from .path_safety import read_regular_file

_VIRTUALENV_BOOTSTRAP = frozenset({"_virtualenv.pth", "_virtualenv.py"})
_CUSTOMIZE = ("sitecustomize", "usercustomize")
_MODULE_SUFFIXES = (".py", ".pyc", ".pyd", ".so", ".pyw")
_METADATA_SUFFIXES = (".dist-info", ".egg-info")


def site_directories() -> tuple[tuple[Path, bool], ...]:
    """Return ``(directory, importable)`` for each existing site directory."""
    package_dirs = {
        Path(value).resolve()
        for value in (sysconfig.get_path("purelib"), sysconfig.get_path("platlib"))
        if value
    }
    candidates = set(package_dirs)
    get_site_packages = getattr(site, "getsitepackages", None)
    if callable(get_site_packages):
        candidates.update(Path(value).resolve() for value in get_site_packages())
    return tuple(
        sorted(
            (
                (path, path in package_dirs or path.name.casefold() == "site-packages")
                for path in candidates
                if path.is_dir()
            ),
            key=lambda item: str(item[0]),
        )
    )


def _owned_top_level(directories: tuple[Path, ...]) -> dict[Path, set[str]]:
    owned: dict[Path, set[str]] = {directory: set() for directory in directories}
    for distribution in importlib.metadata.distributions():
        base = Path(str(distribution.locate_file(""))).resolve()
        if base not in owned:
            continue
        # Read the manifest directly: ``Distribution.files`` stats every entry.
        record = distribution.read_text("RECORD")
        entries = (
            [row[0] for row in csv.reader(record.splitlines()) if row]
            if record is not None
            else [str(item) for item in distribution.files or ()]
        )
        for relative in entries:
            parts = PurePath(relative).parts
            if parts and parts[0] != "..":
                owned[base].add(parts[0].casefold())
    return owned


def _startup_file(name: str) -> bool:
    return name.endswith(".pth") or any(
        name == prefix + suffix for prefix in _CUSTOMIZE for suffix in _MODULE_SUFFIXES
    )


def _importable(entry: Path, name: str) -> bool:
    if entry.is_dir():
        return name != "__pycache__" and not name.endswith(_METADATA_SUFFIXES)
    return name.endswith(_MODULE_SUFFIXES)


def site_directory_records(
    directories: tuple[tuple[Path, bool], ...] | None = None,
) -> list[dict[str, object]]:
    """Hash site startup files; reject unowned startup files and modules."""
    directories = site_directories() if directories is None else directories
    owned = _owned_top_level(tuple(path for path, _ in directories))
    in_virtual_environment = sys.prefix != sys.base_prefix
    records: list[dict[str, object]] = []
    unowned: list[str] = []
    for directory, importable in directories:
        for entry in sorted(directory.iterdir()):
            name = entry.name.casefold()
            startup = _startup_file(name)
            is_owned = name in owned[directory] or (
                in_virtual_environment and name in _VIRTUALENV_BOOTSTRAP
            )
            if not is_owned and (startup or (importable and _importable(entry, name))):
                unowned.append(str(entry))
                continue
            if startup or name in _VIRTUALENV_BOOTSTRAP:
                _, payload = read_regular_file(
                    entry, "Python site startup file", maximum_bytes=16 * 1024**2
                )
                records.append(
                    {
                        "distribution": "<site-startup>",
                        "path": entry.relative_to(directory).as_posix(),
                        "site": directory.name,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size": len(payload),
                    }
                )
    if unowned:
        raise ValueError(
            "Python site directories contain files no installed distribution "
            "owns: " + ", ".join(unowned[:20])
        )
    return records
