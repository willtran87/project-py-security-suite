from __future__ import annotations

import hashlib
import json

from .strict_json import loads as strict_json_loads
import os
import re
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .execution import sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_file, resolve_unlinked_path
from .release_manifest import bound_report_digest

_MAX_FILE_BYTES = 128 * 1024 * 1024
_MAX_PACKAGE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_FILES = 10_000
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")


def create_audit_package(
    report: Path,
    output: Path,
    *,
    evidence: tuple[tuple[str, Path, str], ...] = (),
    overwrite: bool = False,
) -> dict[str, Any]:
    """Create a deterministic, portable archive of a sealed report and sidecars."""
    verification = verify_report(report)
    root = report.expanduser().resolve()
    destination = resolve_unlinked_path(output, "audit package output")
    if destination.exists() and not overwrite:
        raise ValueError(f"audit package output already exists: {destination}")
    if destination.is_relative_to(root):
        raise ValueError("audit package output must be outside the sealed report")
    records: list[dict[str, Any]] = []
    payloads: list[tuple[str, bytes]] = []
    for path in sorted(
        root.rglob("*"), key=lambda value: value.relative_to(root).as_posix()
    ):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        data = _bounded_bytes(path, f"report file {relative}")
        archive_path = f"report/{relative}"
        payloads.append((archive_path, data))
        records.append(_record(archive_path, data, "report"))
    names: set[str] = set()
    for name, path, expected in evidence:
        if not _NAME.fullmatch(name) or name in names:
            raise ValueError(
                "audit evidence names must be unique lowercase portable identifiers"
            )
        names.add(name)
        source = resolve_regular_file(path, f"audit evidence {name}")
        data = _bounded_bytes(source, f"audit evidence {name}")
        digest = _digest(expected, f"audit evidence {name} SHA-256")
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"audit evidence {name} does not match its SHA-256")
        document = strict_json_loads(data)
        if (
            not isinstance(document, dict)
            or bound_report_digest(document) != verification["checksums_sha256"]
        ):
            raise ValueError(f"audit evidence {name} is not bound to this report")
        archive_path = f"evidence/{name}.json"
        payloads.append((archive_path, data))
        records.append(_record(archive_path, data, "evidence"))
    manifest = {
        "schema_version": "1.0",
        "closed_set": True,
        "authoritative": False,
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
        },
        "files": sorted(records, key=lambda value: str(value["path"])),
        "required_authorities": [
            "controlled-signing",
            "organization-security",
            "release-approver",
        ],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            _write_entry(archive, "audit-manifest.json", manifest_bytes)
            for name, data in sorted(payloads):
                _write_entry(archive, name, data)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {
        "schema_version": "1.0",
        "status": "candidate",
        "authoritative": False,
        "package": {
            "path": str(destination),
            "sha256": sha256_file(destination),
            "files": len(records) + 1,
            "size_bytes": destination.stat().st_size,
        },
        "report": manifest["report"],
        "evidence_names": sorted(names),
    }


def verify_audit_package(package: Path, *, package_sha256: str) -> dict[str, Any]:
    """Verify archive structure, every digest, and the embedded report seal."""
    source = resolve_regular_file(package, "audit package")
    if source.stat().st_size > _MAX_PACKAGE_BYTES:
        raise ValueError("audit package exceeds 2 GiB")
    expected = _digest(package_sha256, "audit package SHA-256")
    if sha256_file(source) != expected:
        raise ValueError("audit package does not match its SHA-256")
    with zipfile.ZipFile(source) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > _MAX_FILES:
            raise ValueError("audit package must contain 1-10000 files")
        names = [info.filename for info in infos]
        if len(set(names)) != len(names) or any(
            not _safe_archive_name(name) for name in names
        ):
            raise ValueError("audit package contains duplicate or unsafe paths")
        if sum(info.file_size for info in infos) > _MAX_PACKAGE_BYTES:
            raise ValueError("audit package expanded size exceeds 2 GiB")
        if "audit-manifest.json" not in names:
            raise ValueError("audit package manifest is missing")
        manifest = strict_json_loads(
            _bounded_archive_read(archive, "audit-manifest.json")
        )
        _validate_manifest(manifest)
        declared = {str(value["path"]): value for value in manifest["files"]}
        actual = set(names) - {"audit-manifest.json"}
        if set(declared) != actual:
            raise ValueError("audit package file set does not match its manifest")
        for name, record in declared.items():
            data = _bounded_archive_read(archive, name)
            if (
                hashlib.sha256(data).hexdigest() != record["sha256"]
                or len(data) != record["size_bytes"]
            ):
                raise ValueError(f"audit package entry identity mismatch: {name}")
        with tempfile.TemporaryDirectory(prefix="pysec-audit-verify-") as directory:
            report_root = Path(directory) / "report"
            for name in sorted(
                value for value in actual if value.startswith("report/")
            ):
                relative = PurePosixPath(name).relative_to("report")
                target = report_root.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(_bounded_archive_read(archive, name))
            verification = verify_report(report_root)
    report = manifest["report"]
    if (
        verification["checksums_sha256"] != report["checksums_sha256"]
        or verification["scan_id"] != report["scan_id"]
    ):
        raise ValueError("audit package report identity does not match its manifest")
    evidence_names = sorted(
        PurePosixPath(name).stem for name in declared if name.startswith("evidence/")
    )
    return {
        "schema_version": "1.0",
        "verified": True,
        "authoritative": False,
        "package": {
            "path": str(source),
            "sha256": expected,
            "files_verified": len(declared) + 1,
        },
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
            "outcome": verification["outcome"],
        },
        "evidence_names": evidence_names,
        "admission": "requires_external_approval",
    }


def _write_entry(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def _record(path: str, data: bytes, kind: str) -> dict[str, Any]:
    return {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "kind": kind,
    }


def _bounded_bytes(path: Path, label: str) -> bytes:
    if path.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError(f"{label} exceeds 128 MiB")
    return path.read_bytes()


def _bounded_archive_read(archive: zipfile.ZipFile, name: str) -> bytes:
    info = archive.getinfo(name)
    if info.file_size > _MAX_FILE_BYTES:
        raise ValueError(f"audit package entry exceeds 128 MiB: {name}")
    return archive.read(info)


def _safe_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in name
        and not name.endswith("/")
    )


def _validate_manifest(value: object) -> None:
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "1.0"
        or value.get("closed_set") is not True
        or value.get("authoritative") is not False
    ):
        raise ValueError("audit package manifest contract is invalid")
    report = value.get("report")
    files = value.get("files")
    if (
        not isinstance(report, dict)
        or not isinstance(files, list)
        or len(files) > _MAX_FILES
    ):
        raise ValueError("audit package manifest report or files are invalid")
    _digest(str(report.get("checksums_sha256") or ""), "audit report checksum seal")
    for record in files:
        if not isinstance(record, dict) or set(record) != {
            "path",
            "sha256",
            "size_bytes",
            "kind",
        }:
            raise ValueError("audit package manifest contains an invalid file record")
        _digest(str(record["sha256"]), "audit file SHA-256")
        if (
            not isinstance(record["size_bytes"], int)
            or record["size_bytes"] < 0
            or record["kind"] not in {"report", "evidence"}
        ):
            raise ValueError("audit package manifest contains invalid file metadata")


def _digest(value: str, label: str) -> str:
    normalized = value.strip().casefold()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{label} must be a lowercase digest")
    return normalized
