"""Platform identity components used by runtime closure verification."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import sysconfig

from .path_safety import read_regular_file
from .strict_json import canonical_bytes


def _darwin_shared_cache_dependency(name: str) -> bool:
    """Identify Apple system libraries supplied by the sealed dyld cache."""
    return sys.platform == "darwin" and name.startswith(
        ("/System/Library/", "/usr/lib/")
    )


def _darwin_system_runtime_record() -> dict[str, object] | None:  # pragma: no cover
    """Bind cache-resident Mach-O dependencies to the sealed OS build identity."""
    if sys.platform != "darwin":
        return None
    version_files = (
        Path("/System/Library/CoreServices/SystemVersion.plist"),
        Path("/System/Library/CoreServices/SystemVersionCompat.plist"),
    )
    identities: list[dict[str, object]] = []
    total_bytes = 0
    for path in version_files:
        if not path.is_file():
            continue
        _, payload = read_regular_file(
            path,
            "Darwin sealed system version identity",
            maximum_bytes=1024 * 1024,
        )
        total_bytes += len(payload)
        identities.append(
            {
                "path": str(path),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    if not identities:
        raise ValueError("Darwin sealed system version identity is unavailable")
    kernel = os.uname()
    identity = {
        "kernel": {
            "machine": kernel.machine,
            "release": kernel.release,
            "sysname": kernel.sysname,
            "version": kernel.version,
        },
        "sealed_system_versions": identities,
    }
    return {
        "path": "<darwin-sealed-system-runtime>",
        "sha256": hashlib.sha256(canonical_bytes(identity)).hexdigest(),
        "size": total_bytes,
    }


def _native_runtime_components() -> list[Path]:
    """Return native libraries that form the interpreter's platform closure."""
    candidates: set[Path] = set()
    prefixes = {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}
    executable_parent = Path(sys.executable).resolve().parent
    for root in prefixes | {executable_parent}:
        for pattern in ("*.dll", "*.pyd", "libpython*.so*", "libpython*.dylib"):
            candidates.update(path.resolve() for path in root.glob(pattern))
        native_directory = root / "DLLs"
        if native_directory.is_dir():
            candidates.update(
                path.resolve()
                for pattern in ("*.dll", "*.pyd")
                for path in native_directory.glob(pattern)
            )
    library_directory = sysconfig.get_config_var("LIBDIR")
    library_name = sysconfig.get_config_var("LDLIBRARY")
    if library_directory and library_name:
        candidates.add((Path(str(library_directory)) / str(library_name)).resolve())
    if os.name == "nt":
        windows = Path(
            os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or "C:/Windows"
        )
        system = windows / "System32"
        candidates.update(
            path.resolve()
            for name in ("ucrtbase.dll", "vcruntime140.dll", "vcruntime140_1.dll")
            if (path := system / name).is_file()
        )
    return sorted(path for path in candidates if path.is_file())
