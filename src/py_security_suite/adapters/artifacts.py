from __future__ import annotations

import hashlib
import stat
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import IO

from ..config import ToolConfig
from ..models import normalize_repo_path
from ..path_safety import (
    archive_member_key,
    contained_archive_destination,
    is_link_like,
    portable_archive_member,
    resolve_unlinked_path,
)

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
        # One expansion budget spans every distribution, so many archives
        # cannot each consume the full per-scan allowance.
        budget = _ExtractionBudget()
        for index, artifact in enumerate(distribution_files(target, config)):
            destination = root / f"{index:04d}-{artifact.name}"
            destination.mkdir()
            if artifact.suffix.casefold() in {".whl", ".zip"}:
                _extract_zip(artifact, destination, budget)
            elif artifact.name.casefold().endswith(".tar.gz"):
                _extract_tar(artifact, destination, budget)
        yield root


class _ExtractionBudget:
    """Global member and expanded-byte allowance across all archives."""

    def __init__(self) -> None:
        self.members = 0
        self.total_bytes = 0

    def admit(self, size: int) -> None:
        self.members += 1
        if self.members > _MAX_ARCHIVE_MEMBERS:
            raise ValueError("archives contain too many members in total")
        if size < 0:
            raise ValueError(f"archive member has an invalid size: {size}")
        self.total_bytes += size
        if self.total_bytes > _MAX_TOTAL_BYTES:
            raise ValueError("archives exceed the total expansion limit")


class _MemberLedger:
    """Reject duplicate, case-colliding, or NFC-colliding members per archive."""

    def __init__(self) -> None:
        self._kinds: dict[str, bool] = {}

    def claim(self, member: PurePosixPath, *, directory: bool) -> None:
        key = archive_member_key(member)
        existing = self._kinds.get(key)
        if existing is not None and not (existing and directory):
            raise ValueError(
                f"archive members collide on a case-insensitive or normalizing "
                f"filesystem: {member.as_posix()!r}"
            )
        self._kinds[key] = directory


def _member_path(member_name: str) -> PurePosixPath | None:
    normalized = member_name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in {"", ".", "./"}:
        return None
    return portable_archive_member(normalized)


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


def _extract_zip(
    archive: Path, root: Path, budget: _ExtractionBudget | None = None
) -> None:
    budget = budget or _ExtractionBudget()
    ledger = _MemberLedger()
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        if len(members) > _MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive contains too many members")
        for member in members:
            relative = _member_path(member.filename)
            if relative is None:
                raise ValueError(f"unsafe archive member path: {member.filename!r}")
            ledger.claim(relative, directory=member.is_dir())
            destination = contained_archive_destination(root, relative)
            unix_mode = member.external_attr >> 16
            if unix_mode and stat.S_ISLNK(unix_mode):
                raise ValueError(f"archive links are not allowed: {member.filename}")
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            budget.admit(member.file_size)
            with package.open(member) as source:
                _copy_limited(source, destination, member.file_size)


def _extract_tar(
    archive: Path, root: Path, budget: _ExtractionBudget | None = None
) -> None:
    budget = budget or _ExtractionBudget()
    ledger = _MemberLedger()
    with tarfile.open(archive, mode="r:gz") as package:
        members = package.getmembers()
        if len(members) > _MAX_ARCHIVE_MEMBERS:
            raise ValueError("archive contains too many members")
        for member in members:
            relative = _member_path(member.name)
            if relative is None:
                if member.isdir():
                    continue
                raise ValueError(f"unsafe archive member path: {member.name!r}")
            ledger.claim(relative, directory=member.isdir())
            destination = contained_archive_destination(root, relative)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError(
                    f"archive links and special files are not allowed: {member.name}"
                )
            budget.admit(member.size)
            source = package.extractfile(member)
            if source is None:
                raise ValueError(f"could not read archive member: {member.name}")
            with source:
                _copy_limited(source, destination, member.size)
