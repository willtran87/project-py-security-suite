from __future__ import annotations

import hashlib
import stat
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import IO

from ..config import ToolConfig
from ..models import normalize_repo_path
from ..path_safety import is_link_like, resolve_unlinked_path

_MAX_ARCHIVE_MEMBERS = 100_000
_MAX_MEMBER_BYTES = 512 * 1024 * 1024
_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def configured_path(target: Path, value: Path | None, default: str) -> Path:
    configured = value or Path(default)
    if not configured.is_absolute():
        configured = target / configured
    return resolve_unlinked_path(
        configured,
        "artifact evidence path",
        boundary=target,
    )


def distribution_files(target: Path, config: ToolConfig) -> list[Path]:
    root = configured_path(target, config.artifacts_path, "dist")
    if not root.is_dir():
        return []
    distributions: list[Path] = []
    for path in root.iterdir():
        candidate = path.suffix.casefold() == ".whl" or path.name.casefold().endswith(
            (".tar.gz", ".zip")
        )
        if not candidate:
            continue
        if is_link_like(path):
            raise ValueError(f"distribution artifact cannot be a link: {path}")
        if path.is_file():
            distributions.append(path.resolve())
    return sorted(distributions, key=lambda item: item.name.casefold())


def wheel_files(target: Path, config: ToolConfig) -> list[Path]:
    return [
        path
        for path in distribution_files(target, config)
        if path.suffix.casefold() == ".whl"
    ]


def artifact_manifest(target: Path, config: ToolConfig) -> dict[str, object]:
    artifacts: list[dict[str, object]] = []
    for path in distribution_files(target, config):
        identity = artifact_identity_evidence(target, path)
        artifacts.append(
            {
                "path": identity["artifact_path"],
                "sha256": identity["artifact_sha256"],
                "size_bytes": identity["artifact_size_bytes"],
            }
        )
    return {
        "schema_version": "1.0",
        "algorithm": "sha256",
        "artifacts": artifacts,
    }


def artifact_identity_evidence(target: Path, path: Path) -> dict[str, object]:
    """Return the stable identity fields shared by artifact findings and manifests."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "artifact_path": normalize_repo_path(target, path),
        "artifact_sha256": digest.hexdigest(),
        "artifact_size_bytes": path.stat().st_size,
    }


@contextmanager
def extracted_distribution_tree(target: Path, config: ToolConfig) -> Iterator[Path]:
    """Safely expand distributions for scanners that treat archives as opaque.

    Archive entries are copied without executing target code. Paths escaping the
    temporary root, links, devices, excessive member counts, and oversized
    expanded content are rejected.
    """
    with tempfile.TemporaryDirectory(
        prefix="pysec-artifacts-", ignore_cleanup_errors=True
    ) as temporary:
        root = Path(temporary).resolve()
        for index, artifact in enumerate(distribution_files(target, config)):
            destination = root / f"{index:04d}-{artifact.name}"
            destination.mkdir()
            if artifact.suffix.casefold() in {".whl", ".zip"}:
                _extract_zip(artifact, destination)
            elif artifact.name.casefold().endswith(".tar.gz"):
                _extract_tar(artifact, destination)
        yield root


def _safe_destination(root: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/")
    if not normalized or normalized.startswith("/"):
        raise ValueError(f"unsafe archive member path: {member_name!r}")
    candidate = (root / normalized).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(
            f"archive member escapes extraction root: {member_name!r}"
        ) from exc
    return candidate


def _copy_limited(source: IO[bytes], destination: Path, size: int) -> int:
    if size < 0 or size > _MAX_MEMBER_BYTES:
        raise ValueError(f"archive member is too large: {size} bytes")
    destination.parent.mkdir(parents=True, exist_ok=True)
    copied = 0
    with destination.open("wb") as output:
        while True:
            chunk = source.read(min(1024 * 1024, _MAX_MEMBER_BYTES - copied + 1))
            if not chunk:
                break
            copied += len(chunk)
            if copied > _MAX_MEMBER_BYTES:
                raise ValueError("archive member exceeded expansion limit")
            output.write(chunk)
    if copied != size:
        raise ValueError(
            f"archive member size mismatch: expected {size}, expanded {copied}"
        )
    return copied


def _extract_zip(archive: Path, root: Path) -> None:
    total = 0
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        if len(members) > _MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive contains too many members")
        for member in members:
            destination = _safe_destination(root, member.filename)
            unix_mode = member.external_attr >> 16
            if unix_mode and stat.S_ISLNK(unix_mode):
                raise ValueError(f"archive links are not allowed: {member.filename}")
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            total += member.file_size
            if total > _MAX_TOTAL_BYTES:
                raise ValueError("archive exceeds the total expansion limit")
            with package.open(member) as source:
                _copy_limited(source, destination, member.file_size)


def _extract_tar(archive: Path, root: Path) -> None:
    total = 0
    with tarfile.open(archive, mode="r:gz") as package:
        members = package.getmembers()
        if len(members) > _MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive contains too many members")
        for member in members:
            destination = _safe_destination(root, member.name)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError(
                    f"archive links and special files are not allowed: {member.name}"
                )
            total += member.size
            if total > _MAX_TOTAL_BYTES:
                raise ValueError("archive exceeds the total expansion limit")
            source = package.extractfile(member)
            if source is None:
                raise ValueError(f"could not read archive member: {member.name}")
            with source:
                _copy_limited(source, destination, member.size)
