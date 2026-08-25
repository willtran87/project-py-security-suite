from __future__ import annotations

import hashlib
import gzip
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .execution import sha256_file
from .path_safety import (
    resolve_regular_directory,
    resolve_regular_file,
    resolve_unlinked_path,
)


_SCHEMA_ID = "urn:project-py-security-suite:schema:reproducible-build:1.0"
_MAX_FILES = 100_000
_MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024


def compare_builds(
    first: Path,
    second: Path,
    *,
    first_label: str = "build-a",
    second_label: str = "build-b",
) -> dict[str, Any]:
    """Compare two closed artifact directories without executing their content."""
    labels = (_label(first_label), _label(second_label))
    first_root = resolve_regular_directory(first, "first build directory")
    second_root = resolve_regular_directory(second, "second build directory")
    if first_root == second_root:
        raise ValueError(
            "build directories must be distinct; comparing a directory with itself "
            "cannot demonstrate reproducibility"
        )
    first_records = _inventory(first_root)
    second_records = _inventory(second_root)
    first_paths = set(first_records)
    second_paths = set(second_records)
    missing = sorted(first_paths - second_paths)
    unexpected = sorted(second_paths - first_paths)
    changed = [
        {
            "path": path,
            "first_sha256": first_records[path]["sha256"],
            "second_sha256": second_records[path]["sha256"],
            "first_size_bytes": first_records[path]["size_bytes"],
            "second_size_bytes": second_records[path]["size_bytes"],
        }
        for path in sorted(first_paths & second_paths)
        if first_records[path] != second_records[path]
    ]
    reproducible = not missing and not unexpected and not changed
    summary = (
        "The two artifact sets are byte-for-byte identical."
        if reproducible
        else (
            f"Artifact sets differ: {len(missing)} missing, {len(unexpected)} "
            f"unexpected, and {len(changed)} changed."
        )
    )
    return {
        "schema_version": "1.0",
        "schema_id": _SCHEMA_ID,
        "authoritative": False,
        "kind": "reproducible-build",
        "scope": (
            "Byte-for-byte comparison of two separately supplied artifact directories; "
            "independent build-environment and source identity evidence remains required."
        ),
        "status": "match" if reproducible else "mismatch",
        "reproducible": reproducible,
        "summary": summary,
        "builds": [
            _build_identity(labels[0], first_records),
            _build_identity(labels[1], second_records),
        ],
        "differences": {
            "missing_from_second": missing,
            "unexpected_in_second": unexpected,
            "changed": changed,
        },
        "findings": (
            []
            if reproducible
            else [
                {
                    "rule_id": "REPRODUCIBLE-BUILD-MISMATCH",
                    "title": "Independent build artifacts are not reproducible",
                    "message": summary,
                    "severity": "high",
                    "classification": "SLSA-BUILD-REPRODUCIBILITY",
                    "domain": "supply-chain",
                    "area": "build-reproducibility",
                    "path": "<release-artifacts>",
                    "impact": (
                        "Artifact bytes cannot be reproduced from the compared build "
                        "lanes, weakening provenance and tamper-detection confidence."
                    ),
                    "remediation": (
                        "Normalize build inputs and timestamps, rebuild in clean "
                        "independent workspaces, and compare the exact artifact sets again."
                    ),
                    "citation": "https://reproducible-builds.org/docs/",
                    "evidence": {
                        "missing": len(missing),
                        "unexpected": len(unexpected),
                        "changed": len(changed),
                    },
                }
            ]
        ),
    }


def render_reproducibility_markdown(document: dict[str, Any]) -> str:
    """Render a concise human review of reproducibility evidence."""
    builds = document["builds"]
    differences = document["differences"]
    lines = [
        "# Reproducible build comparison",
        "",
        f"**Result:** `{str(document['status']).upper()}`",
        "",
        str(document["summary"]),
        "",
        "| Build | Files | Bytes | Aggregate SHA-256 |",
        "|---|---:|---:|---|",
    ]
    lines.extend(
        (
            f"| `{build['label']}` | {build['total_files']} | "
            f"{build['total_bytes']} | `{build['aggregate_sha256']}` |"
        )
        for build in builds
    )
    lines.extend(("", "## Differences", ""))
    lines.append(
        f"- Missing from second build: {len(differences['missing_from_second'])}"
    )
    lines.append(
        f"- Unexpected in second build: {len(differences['unexpected_in_second'])}"
    )
    lines.append(f"- Changed files: {len(differences['changed'])}")
    if differences["changed"]:
        lines.extend(
            (
                "",
                "| Changed artifact | First SHA-256 | Second SHA-256 |",
                "|---|---|---|",
            )
        )
        lines.extend(
            (
                f"| `{value['path']}` | `{value['first_sha256']}` | "
                f"`{value['second_sha256']}` |"
            )
            for value in differences["changed"]
        )
    lines.extend(
        (
            "",
            "> This comparison is non-authoritative. Preserve independent source, "
            "builder, environment, and custody evidence before release approval.",
        )
    )
    return "\n".join(lines) + "\n"


def normalize_sdist(
    source: Path,
    output: Path,
    *,
    epoch: int,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Rewrite a Python sdist with deterministic safe archive metadata."""
    if epoch < 0 or epoch > (1 << 63) - 1:
        raise ValueError("source-date epoch must be a non-negative signed integer")
    input_path = resolve_regular_file(source, "source distribution")
    if input_path.suffixes[-2:] != [".tar", ".gz"]:
        raise ValueError("source distribution must use the .tar.gz format")
    requested = output.expanduser().absolute()
    destination = resolve_unlinked_path(
        requested,
        "normalized source distribution",
        boundary=Path(requested.anchor),
    )
    if destination.exists() and destination != input_path and not overwrite:
        raise FileExistsError(
            "normalized source distribution already exists; use --overwrite"
        )
    if destination == input_path and not overwrite:
        raise FileExistsError("in-place normalization requires --overwrite")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    members = 0
    total_bytes = 0
    input_sha256 = sha256_file(input_path)
    try:
        with (
            tarfile.open(input_path, mode="r:gz") as archive,
            temporary.open("wb") as raw_output,
            gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_output,
                mtime=epoch,
            ) as compressed,
            tarfile.open(
                fileobj=compressed,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as normalized,
        ):
            archive_members = archive.getmembers()
            if len(archive_members) > _MAX_FILES:
                raise ValueError(f"source distribution exceeds {_MAX_FILES} members")
            names: set[str] = set()
            for member in sorted(archive_members, key=lambda value: value.name):
                _validate_member(member, names)
                members += 1
                total_bytes += member.size
                if total_bytes > _MAX_ARCHIVE_BYTES:
                    raise ValueError(
                        "source distribution exceeds the 4 GiB content limit"
                    )
                info = _normalized_member(member, epoch)
                extracted = archive.extractfile(member) if member.isfile() else None
                if member.isfile() and extracted is None:
                    raise ValueError(
                        f"source distribution member cannot be read: {member.name}"
                    )
                try:
                    normalized.addfile(info, extracted)
                finally:
                    if extracted is not None:
                        extracted.close()
        with temporary.open("rb+") as handle:
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)
            temporary.unlink()
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "schema_version": "1.0",
        "schema_id": "urn:project-py-security-suite:schema:sdist-normalization:1.0",
        "authoritative": False,
        "kind": "sdist-normalization",
        "source_date_epoch": epoch,
        "members": members,
        "uncompressed_file_bytes": total_bytes,
        "input_sha256": input_sha256,
        "output_sha256": sha256_file(destination),
        "output_size_bytes": destination.stat().st_size,
    }


def _inventory(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            if (current_path / directory).is_symlink():
                raise ValueError("build artifact directories must not contain links")
        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink() or not path.is_file():
                raise ValueError(
                    "build artifact directories must contain regular files"
                )
            relative = path.relative_to(root).as_posix()
            if len(result) >= _MAX_FILES:
                raise ValueError(f"build artifact directory exceeds {_MAX_FILES} files")
            result[relative] = _file_identity(path)
    return dict(sorted(result.items()))


def _validate_member(member: tarfile.TarInfo, names: set[str]) -> None:
    name = member.name
    pure = PurePosixPath(name)
    if (
        not name
        or name != pure.as_posix()
        or pure.is_absolute()
        or ".." in pure.parts
        or "\\" in name
        or name in names
    ):
        raise ValueError("source distribution contains an unsafe member path")
    if not member.isfile() and not member.isdir():
        raise ValueError("source distribution must contain only files and directories")
    if member.size < 0 or member.size > _MAX_FILE_BYTES:
        raise ValueError("source distribution member exceeds the 4 GiB file limit")
    names.add(name)


def _normalized_member(member: tarfile.TarInfo, epoch: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(member.name)
    info.type = tarfile.DIRTYPE if member.isdir() else tarfile.REGTYPE
    info.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    info.size = member.size if member.isfile() else 0
    info.pax_headers = {}
    return info


def _file_identity(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            if size > _MAX_FILE_BYTES:
                raise ValueError("build artifact exceeds the 4 GiB comparison limit")
            digest.update(chunk)
    return {"sha256": digest.hexdigest(), "size_bytes": size}


def _build_identity(label: str, records: dict[str, dict[str, Any]]) -> dict[str, Any]:
    aggregate = hashlib.sha256()
    total_bytes = 0
    artifacts = []
    for path, identity in records.items():
        encoded = path.encode("utf-8")
        size = int(identity["size_bytes"])
        aggregate.update(len(encoded).to_bytes(8, "big"))
        aggregate.update(encoded)
        aggregate.update(size.to_bytes(8, "big"))
        aggregate.update(bytes.fromhex(str(identity["sha256"])))
        total_bytes += size
        artifacts.append({"path": path, **identity})
    return {
        "label": label,
        "total_files": len(records),
        "total_bytes": total_bytes,
        "aggregate_sha256": aggregate.hexdigest(),
        "artifacts": artifacts,
    }


def _label(value: str) -> str:
    normalized = " ".join(value.split())
    if not normalized or len(normalized.encode("utf-8")) > 256:
        raise ValueError("build label must be a non-empty string of at most 256 bytes")
    return normalized
