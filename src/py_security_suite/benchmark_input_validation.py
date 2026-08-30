from __future__ import annotations

import tarfile
import stat
import struct
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from .path_safety import open_regular_file
from .strict_json import loads as strict_loads


_MAX_INPUT_BYTES = 4 * 1024**3
_MAX_JSON_BYTES = 256 * 1024**2
_MAX_ARCHIVE_ENTRIES = 100_000
_MAX_EXPANDED_BYTES = 16 * 1024**3
_MAX_COMPRESSION_RATIO = 1000
_MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 64 * 1024**2


class BenchmarkInputError(ValueError):
    """Raised when a benchmark input is structurally unsafe or malformed."""


def validate_benchmark_input(path: Path) -> dict[str, Any]:
    """Return deterministic structural validation evidence for one pinned input."""
    try:
        with open_regular_file(
            path,
            "benchmark input",
            maximum_bytes=_MAX_INPUT_BYTES,
        ) as (_, handle, size):
            if not 1 <= size <= _MAX_INPUT_BYTES:
                raise BenchmarkInputError("benchmark input is empty or exceeds 4 GiB")
            suffixes = "".join(path.suffixes).lower()
            if suffixes.endswith(".json"):
                if size > _MAX_JSON_BYTES:
                    raise BenchmarkInputError("benchmark JSON input exceeds 256 MiB")
                try:
                    value = strict_loads(handle.read(_MAX_JSON_BYTES + 1))
                except (TypeError, ValueError) as exc:
                    raise BenchmarkInputError(
                        "benchmark JSON input is invalid"
                    ) from exc
                return {
                    "format": "json",
                    "size_bytes": size,
                    "entries": len(value) if isinstance(value, (dict, list)) else 1,
                    "validated": True,
                }
            if suffixes.endswith(".zip"):
                return _validate_zip(handle, size)
            if any(
                suffixes.endswith(suffix)
                for suffix in (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
            ):
                return _validate_tar(handle, size)
            return {
                "format": "opaque",
                "size_bytes": size,
                "entries": 1,
                "validated": True,
            }
    except BenchmarkInputError:
        raise
    except (OSError, ValueError) as exc:
        raise BenchmarkInputError("benchmark input is not a safe regular file") from exc


def _validate_zip(handle: BinaryIO, size: int) -> dict[str, Any]:
    try:
        declared_entries = _preflight_zip_directory(handle, size)
        handle.seek(0)
        with zipfile.ZipFile(handle) as archive:
            entries = archive.infolist()
            if len(entries) != declared_entries:
                raise BenchmarkInputError(
                    "benchmark ZIP central-directory entry count is inconsistent"
                )
            _validate_archive_names([item.filename for item in entries])
            if any(item.flag_bits & 0x1 for item in entries):
                raise BenchmarkInputError("benchmark ZIP contains encrypted entries")
            if any(not _safe_zip_entry_type(item) for item in entries):
                raise BenchmarkInputError(
                    "benchmark ZIP contains links or special entries"
                )
            expanded = sum(item.file_size for item in entries if not item.is_dir())
            compressed = sum(
                item.compress_size for item in entries if not item.is_dir()
            )
    except (OSError, zipfile.BadZipFile) as exc:
        raise BenchmarkInputError("benchmark ZIP input is invalid") from exc
    _validate_archive_bounds(len(entries), expanded, compressed)
    return {
        "format": "zip",
        "size_bytes": size,
        "entries": len(entries),
        "expanded_bytes": expanded,
        "validated": True,
    }


def _validate_tar(handle: BinaryIO, size: int) -> dict[str, Any]:
    entry_count = 0
    expanded = 0
    portable_names: set[str] = set()
    try:
        handle.seek(0)
        with tarfile.open(fileobj=handle, mode="r:*") as archive:
            for item in archive:
                entry_count += 1
                if entry_count > _MAX_ARCHIVE_ENTRIES:
                    raise BenchmarkInputError(
                        "benchmark archive entry count is invalid"
                    )
                _validate_archive_name(item.name, portable_names)
                if not (item.isfile() or item.isdir()):
                    # Fail closed for links, devices, FIFOs, sparse metadata, and
                    # implementation-specific extension records.
                    raise BenchmarkInputError(
                        "benchmark TAR contains links or special entries"
                    )
                if item.isfile():
                    expanded += item.size
                    if expanded > _MAX_EXPANDED_BYTES:
                        raise BenchmarkInputError(
                            "benchmark archive expanded size is invalid"
                        )
    except (OSError, tarfile.TarError) as exc:
        raise BenchmarkInputError("benchmark TAR input is invalid") from exc
    _validate_archive_bounds(entry_count, expanded, size)
    return {
        "format": "tar",
        "size_bytes": size,
        "entries": entry_count,
        "expanded_bytes": expanded,
        "validated": True,
    }


def _validate_archive_names(names: list[str]) -> None:
    portable_names: set[str] = set()
    for name in names:
        _validate_archive_name(name, portable_names)


def _validate_archive_name(name: str, portable_names: set[str]) -> None:
    normalized = PurePosixPath(name.replace("\\", "/"))
    parts = normalized.parts
    if (
        not name
        or normalized == PurePosixPath(".")
        or normalized.is_absolute()
        or ".." in parts
        or any(ord(character) < 32 for character in name)
        or any(":" in part or part.endswith((" ", ".")) for part in parts)
    ):
        raise BenchmarkInputError("benchmark archive contains an unsafe path")
    portable = normalized.as_posix().rstrip("/").casefold()
    if portable in portable_names:
        raise BenchmarkInputError("benchmark archive contains duplicate paths")
    portable_names.add(portable)


def _safe_zip_entry_type(item: zipfile.ZipInfo) -> bool:
    file_type = stat.S_IFMT(item.external_attr >> 16)
    return file_type in {0, stat.S_IFREG, stat.S_IFDIR}


def _preflight_zip_directory(handle: BinaryIO, size: int) -> int:
    """Bound ZIP metadata before ``ZipFile`` materializes the central directory."""
    maximum_tail = min(size, 65_557)  # EOCD plus the maximum legal comment.
    handle.seek(size - maximum_tail)
    tail = handle.read(maximum_tail)
    marker = tail.rfind(b"PK\x05\x06")
    if marker < 0 or len(tail) - marker < 22:
        raise BenchmarkInputError("benchmark ZIP end record is missing")
    (
        disk_number,
        directory_disk,
        disk_entries,
        total_entries,
        directory_size,
        directory_offset,
        comment_size,
    ) = struct.unpack_from("<4H2LH", tail, marker + 4)
    if marker + 22 + comment_size != len(tail):
        raise BenchmarkInputError("benchmark ZIP end record is malformed")
    if disk_number or directory_disk or disk_entries != total_entries:
        raise BenchmarkInputError("multi-disk benchmark ZIPs are unsupported")
    if (
        total_entries == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
    ):
        raise BenchmarkInputError("ZIP64 benchmark inputs are unsupported")
    if not 1 <= total_entries <= _MAX_ARCHIVE_ENTRIES:
        raise BenchmarkInputError("benchmark archive entry count is invalid")
    if directory_size > _MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
        raise BenchmarkInputError("benchmark ZIP central directory is too large")
    if directory_offset + directory_size > size - 22:
        raise BenchmarkInputError("benchmark ZIP central directory is out of bounds")
    return total_entries


def _validate_archive_bounds(entries: int, expanded: int, compressed: int) -> None:
    if not 1 <= entries <= _MAX_ARCHIVE_ENTRIES:
        raise BenchmarkInputError("benchmark archive entry count is invalid")
    if not 1 <= expanded <= _MAX_EXPANDED_BYTES:
        raise BenchmarkInputError("benchmark archive expanded size is invalid")
    if compressed <= 0 or expanded / compressed > _MAX_COMPRESSION_RATIO:
        raise BenchmarkInputError("benchmark archive compression ratio is unsafe")
