from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .path_safety import resolve_regular_file


_MAX_DOCUMENT_BYTES = 128 * 1024 * 1024
_MAX_FILES = 1_000_000
_MAX_PATH_BYTES = 4096
_MAX_U64 = (1 << 64) - 1
_DOCUMENT_KEYS = {
    "schema_version",
    "scope",
    "source_sha256",
    "total_files",
    "total_bytes",
    "files",
}
_RECORD_KEYS = {"path", "size_bytes", "sha256"}


@dataclass(frozen=True, slots=True)
class SourceInventoryIdentity:
    """Verified identity and member set for one sealed source snapshot."""

    source_sha256: str
    total_files: int
    total_bytes: int
    paths: frozenset[str]


def load_source_inventory(path: Path) -> dict[str, Any]:
    """Read a bounded source inventory from a regular, unlinked file."""
    source = resolve_regular_file(path, "source inventory")
    if source.stat().st_size > _MAX_DOCUMENT_BYTES:
        raise ValueError("source inventory exceeds the maximum document size")
    try:
        value = json.loads(source.read_bytes())
    except json.JSONDecodeError as exc:
        raise ValueError(f"source inventory JSON is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise TypeError("source inventory root must be an object")
    return value


def verify_source_inventory_file(
    path: Path,
    manifest_inventory: dict[str, Any],
    *,
    require_unchanged: bool = False,
) -> SourceInventoryIdentity:
    """Verify a source inventory and its binding to scan-manifest inventory data."""
    return verify_source_inventory(
        load_source_inventory(path),
        manifest_inventory,
        require_unchanged=require_unchanged,
    )


def verify_source_inventory(
    document: dict[str, Any],
    manifest_inventory: dict[str, Any],
    *,
    require_unchanged: bool = False,
) -> SourceInventoryIdentity:
    """Validate canonical records, aggregate identity, and manifest binding."""
    if set(document) != _DOCUMENT_KEYS:
        raise ValueError("source inventory fields do not match the schema contract")
    if document.get("schema_version") != "1.0":
        raise ValueError("source inventory schema_version must be '1.0'")
    scope = document.get("scope")
    if not isinstance(scope, str) or not scope.strip():
        raise ValueError("source inventory scope must be a non-empty string")
    files = document.get("files")
    if not isinstance(files, list):
        raise TypeError("source inventory files must be an array")
    if len(files) > _MAX_FILES:
        raise ValueError(f"source inventory exceeds {_MAX_FILES} files")

    aggregate = hashlib.sha256()
    paths: set[str] = set()
    previous = ""
    total_bytes = 0
    for record in files:
        if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
            raise ValueError(
                "source inventory file fields do not match the schema contract"
            )
        relative = _canonical_path(record.get("path"))
        if relative in paths:
            raise ValueError(f"source inventory path is duplicated: {relative}")
        if previous and relative <= previous:
            raise ValueError("source inventory paths must be strictly sorted")
        previous = relative
        size = record.get("size_bytes")
        digest = record.get("sha256")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > _MAX_U64
            or not isinstance(digest, str)
            or not _is_digest(digest)
        ):
            raise ValueError("source inventory contains an invalid file identity")
        encoded = relative.encode("utf-8")
        aggregate.update(len(encoded).to_bytes(8, "big"))
        aggregate.update(encoded)
        aggregate.update(size.to_bytes(8, "big"))
        aggregate.update(bytes.fromhex(digest))
        total_bytes += size
        paths.add(relative)

    file_count = len(files)
    aggregate_digest = aggregate.hexdigest()
    declared_files = document.get("total_files")
    declared_bytes = document.get("total_bytes")
    declared_digest = document.get("source_sha256")
    if (
        not isinstance(declared_files, int)
        or isinstance(declared_files, bool)
        or declared_files != file_count
        or not isinstance(declared_bytes, int)
        or isinstance(declared_bytes, bool)
        or declared_bytes != total_bytes
        or not isinstance(declared_digest, str)
        or declared_digest != aggregate_digest
    ):
        raise ValueError("source inventory totals or aggregate digest are invalid")
    _verify_manifest_binding(
        manifest_inventory,
        source_sha256=aggregate_digest,
        total_files=file_count,
        total_bytes=total_bytes,
        require_unchanged=require_unchanged,
    )
    return SourceInventoryIdentity(
        source_sha256=aggregate_digest,
        total_files=file_count,
        total_bytes=total_bytes,
        paths=frozenset(paths),
    )


def _canonical_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _MAX_PATH_BYTES
    ):
        raise ValueError("source inventory contains an invalid path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("source inventory path contains a control character")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or value != pure.as_posix()
        or not pure.parts
        or pure.parts == (".",)
        or ".." in pure.parts
        or "\\" in value
    ):
        raise ValueError("source inventory contains an unsafe or non-canonical path")
    return value


def _verify_manifest_binding(
    manifest_inventory: dict[str, Any],
    *,
    source_sha256: str,
    total_files: int,
    total_bytes: int,
    require_unchanged: bool,
) -> None:
    if not isinstance(manifest_inventory, dict):
        raise TypeError("scan manifest inventory must be an object")
    if (
        manifest_inventory.get("source_sha256") != source_sha256
        or manifest_inventory.get("hashed_files") != total_files
        or manifest_inventory.get("hashed_bytes") != total_bytes
    ):
        raise ValueError("source inventory is not bound to the scan manifest snapshot")
    if (
        require_unchanged
        and manifest_inventory.get("source_integrity_verified") is not True
    ):
        raise ValueError(
            "source inventory is not bound to an unchanged sealed source snapshot"
        )


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
