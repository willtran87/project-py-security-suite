from __future__ import annotations

import argparse
import base64
import csv
import email.parser
import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


_MAX_MEMBERS = 100_000
_MAX_UNCOMPRESSED = 4 * 1024 * 1024 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_member(name: str, seen: set[str]) -> None:
    pure = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or pure.is_absolute()
        or name != pure.as_posix()
        or ".." in pure.parts
        or name in seen
    ):
        raise ValueError(f"unsafe or duplicate archive member: {name!r}")
    seen.add(name)


def verify_wheel(path: Path) -> dict[str, Any]:
    seen: set[str] = set()
    payloads: dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if not entries or len(entries) > _MAX_MEMBERS:
            raise ValueError("wheel member count is invalid")
        for entry in entries:
            _safe_member(entry.filename, seen)
            if entry.flag_bits & 0x1:
                raise ValueError("encrypted wheel member is not allowed")
            total += entry.file_size
            if total > _MAX_UNCOMPRESSED:
                raise ValueError("wheel uncompressed size limit exceeded")
            payloads[entry.filename] = archive.read(entry)
    metadata_names = [name for name in seen if name.endswith(".dist-info/METADATA")]
    record_names = [name for name in seen if name.endswith(".dist-info/RECORD")]
    wheel_names = [name for name in seen if name.endswith(".dist-info/WHEEL")]
    if len(metadata_names) != 1 or len(record_names) != 1 or len(wheel_names) != 1:
        raise ValueError("wheel must contain one METADATA, WHEEL, and RECORD")
    record_name = record_names[0]
    rows = list(csv.reader(payloads[record_name].decode("utf-8").splitlines()))
    recorded: set[str] = set()
    for row in rows:
        if len(row) != 3 or row[0] in recorded:
            raise ValueError("wheel RECORD row is malformed or duplicated")
        name, encoded_digest, size = row
        recorded.add(name)
        if name not in payloads:
            raise ValueError(f"wheel RECORD names a missing member: {name}")
        if name == record_name:
            if encoded_digest or size:
                raise ValueError(
                    "wheel RECORD must leave its own digest and size empty"
                )
            continue
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(payloads[name]).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        if encoded_digest != f"sha256={expected}" or size != str(len(payloads[name])):
            raise ValueError(f"wheel RECORD mismatch for {name}")
    if recorded != seen:
        raise ValueError("wheel RECORD does not cover the exact member set")
    message = email.parser.BytesParser().parsebytes(payloads[metadata_names[0]])
    if not message.get("Name") or not message.get("Version"):
        raise ValueError("wheel metadata lacks package name or version")
    return {
        "name": path.name,
        "sha256": sha256(path),
        "members": len(seen),
        "uncompressed_bytes": total,
        "project": message["Name"],
        "version": message["Version"],
    }


def verify_sdist(path: Path, *, source_date_epoch: int) -> dict[str, Any]:
    seen: set[str] = set()
    roots: set[str] = set()
    total = 0
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if not members or len(members) > _MAX_MEMBERS:
            raise ValueError("sdist member count is invalid")
        if [item.name for item in members] != sorted(item.name for item in members):
            raise ValueError("sdist members are not canonically ordered")
        for member in members:
            _safe_member(member.name, seen)
            roots.add(PurePosixPath(member.name).parts[0])
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ValueError("sdist links and special files are not allowed")
            if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
                raise ValueError("sdist ownership metadata is not normalized")
            if member.mtime != source_date_epoch:
                raise ValueError("sdist timestamp does not match SOURCE_DATE_EPOCH")
            total += member.size
            if total > _MAX_UNCOMPRESSED:
                raise ValueError("sdist uncompressed size limit exceeded")
    if len(roots) != 1:
        raise ValueError("sdist must have exactly one top-level directory")
    return {
        "name": path.name,
        "sha256": sha256(path),
        "members": len(seen),
        "uncompressed_bytes": total,
        "root": next(iter(roots)),
        "source_date_epoch": source_date_epoch,
    }


def verify_directory(root: Path, *, source_date_epoch: int) -> dict[str, Any]:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("release path must be a directory")
    entries = sorted(resolved.iterdir())
    if any(not item.is_file() or item.is_symlink() for item in entries):
        raise ValueError("release directory must contain regular files only")
    wheels = [item for item in entries if item.suffix == ".whl"]
    sdists = [item for item in entries if item.name.endswith(".tar.gz")]
    if len(entries) != 2 or len(wheels) != 1 or len(sdists) != 1:
        raise ValueError(
            "release directory must contain exactly one wheel and one sdist"
        )
    return {
        "files": {item.name: sha256(item) for item in entries},
        "wheel": verify_wheel(wheels[0]),
        "sdist": verify_sdist(sdists[0], source_date_epoch=source_date_epoch),
    }


def compare(first: Path, second: Path, *, source_date_epoch: int) -> dict[str, Any]:
    if first.resolve() == second.resolve():
        raise ValueError("independent release directories must be distinct")
    first_result = verify_directory(first, source_date_epoch=source_date_epoch)
    second_result = verify_directory(second, source_date_epoch=source_date_epoch)
    if first_result["files"] != second_result["files"]:
        raise ValueError("independent release artifact bytes differ")
    return {
        "schema_version": "1.0",
        "analysis": "stdlib-independent-release-verification",
        "verified": True,
        "source_date_epoch": source_date_epoch,
        "artifacts": first_result,
        "second_artifact_digests": second_result["files"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("first", type=Path)
    parser.add_argument("second", nargs="?", type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    document = (
        compare(
            arguments.first,
            arguments.second,
            source_date_epoch=arguments.source_date_epoch,
        )
        if arguments.second is not None
        else {
            "schema_version": "1.0",
            "analysis": "stdlib-independent-release-verification",
            "verified": True,
            "source_date_epoch": arguments.source_date_epoch,
            "artifacts": verify_directory(
                arguments.first, source_date_epoch=arguments.source_date_epoch
            ),
        }
    )
    encoded = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
