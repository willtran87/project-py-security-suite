#!/usr/bin/env python3
"""Bounded structural validation for a pinned OSV ecosystem snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 100_000
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1_000
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def validate_snapshot(archive: Path, expected_sha256: str) -> dict[str, Any]:
    source = archive.resolve(strict=True)
    if not source.is_file() or source.is_symlink():
        raise ValueError("OSV snapshot must be a regular file")
    size = source.stat().st_size
    if size <= 0 or size > MAX_ARCHIVE_BYTES:
        raise ValueError("OSV snapshot size is outside the approved bounds")
    expected = expected_sha256.strip().lower()
    if SHA256.fullmatch(expected) is None:
        raise ValueError("expected OSV snapshot SHA-256 is invalid")
    observed = _sha256(source)
    if observed != expected:
        raise ValueError("OSV snapshot SHA-256 does not match the approved digest")

    identifiers: set[str] = set()
    member_names: set[str] = set()
    modified: list[str] = []
    expanded = 0
    with zipfile.ZipFile(source) as bundle:
        members = bundle.infolist()
        if not members or len(members) > MAX_MEMBERS:
            raise ValueError("OSV archive member count is outside the approved bounds")
        for member in members:
            _validate_member(member, member_names)
            expanded += member.file_size
            if expanded > MAX_EXPANDED_BYTES:
                raise ValueError("OSV archive expanded size exceeds 2 GiB")
            record = json.loads(bundle.read(member))
            if not isinstance(record, dict):
                raise ValueError(f"OSV record is not an object: {member.filename}")
            identifier = record.get("id")
            if (
                not isinstance(identifier, str)
                or not identifier
                or len(identifier) > 512
                or identifier in identifiers
            ):
                raise ValueError(f"invalid or duplicate OSV ID: {member.filename}")
            if not isinstance(record.get("affected"), list):
                raise ValueError(f"OSV record lacks affected array: {member.filename}")
            timestamp = record.get("modified")
            if not isinstance(timestamp, str) or TIMESTAMP.fullmatch(timestamp) is None:
                raise ValueError(
                    f"OSV record has invalid modified time: {member.filename}"
                )
            identifiers.add(identifier)
            modified.append(timestamp)
        bad_member = bundle.testzip()
        if bad_member is not None:
            raise ValueError(f"OSV archive CRC failure: {bad_member}")
    return {
        "schema_version": "1.0",
        "sha256": observed,
        "size": size,
        "records": len(identifiers),
        "expanded_bytes": expanded,
        "newest_modified": max(modified),
        "structurally_validated": True,
    }


def _validate_member(member: zipfile.ZipInfo, seen: set[str]) -> None:
    path = PurePosixPath(member.filename)
    normalized = member.filename.casefold()
    mode = member.external_attr >> 16
    if (
        not member.filename
        or "\\" in member.filename
        or path.is_absolute()
        or ".." in path.parts
        or member.is_dir()
    ):
        raise ValueError(f"unsafe OSV archive member: {member.filename}")
    if normalized in seen:
        raise ValueError(f"duplicate OSV archive member: {member.filename}")
    seen.add(normalized)
    if stat.S_ISLNK(mode):
        raise ValueError(f"linked OSV archive member: {member.filename}")
    if member.flag_bits & 0x1:
        raise ValueError(f"encrypted OSV archive member: {member.filename}")
    if not member.filename.endswith(".json"):
        raise ValueError(f"unexpected OSV archive member: {member.filename}")
    if member.file_size > MAX_RECORD_BYTES:
        raise ValueError(f"oversized OSV record: {member.filename}")
    if member.file_size and not member.compress_size:
        raise ValueError(f"invalid compression metadata: {member.filename}")
    if (
        member.compress_size
        and member.file_size / member.compress_size > MAX_COMPRESSION_RATIO
    ):
        raise ValueError(f"excessive compression ratio: {member.filename}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    result: dict[str, object] = {}
    try:
        result = validate_snapshot(args.archive, args.expected_sha256)
    except (OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
