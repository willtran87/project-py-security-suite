from __future__ import annotations

import argparse
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath


_MAX_MEMBERS = 100_000
_MAX_MEMBER_BYTES = 512 * 1024 * 1024
_MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 1_000


def _validated_name(name: str, seen: set[str]) -> PurePosixPath:
    pure = PurePosixPath(name)
    normalized = pure.as_posix()
    portable = normalized.casefold()
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or pure.is_absolute()
        or normalized != name.rstrip("/")
        or ".." in pure.parts
        or any(
            not part
            or ":" in part
            or part.endswith((" ", "."))
            or any(ord(character) < 32 for character in part)
            for part in pure.parts
        )
        or portable in seen
    ):
        raise ValueError(f"unsafe or duplicate artifact member: {name!r}")
    seen.add(portable)
    return pure


def extract_github_artifact(archive_path: Path, destination: Path) -> None:
    """Extract a bounded GitHub artifact without following links or paths."""

    archive_path = archive_path.resolve(strict=True)
    if destination.exists() or destination.is_symlink():
        raise ValueError("artifact destination must not already exist")
    destination = destination.resolve()
    seen: set[str] = set()
    total = 0
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        if not 1 <= len(members) <= _MAX_MEMBERS:
            raise ValueError("artifact member count is invalid")
        validated: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
        for member in members:
            pure = _validated_name(member.filename, seen)
            mode = stat.S_IFMT(member.external_attr >> 16)
            if member.flag_bits & 0x1:
                raise ValueError("encrypted artifact members are not allowed")
            if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ValueError("artifact links and special files are not allowed")
            if member.file_size > _MAX_MEMBER_BYTES:
                raise ValueError("artifact member size limit exceeded")
            total += member.file_size
            if total > _MAX_TOTAL_BYTES:
                raise ValueError("artifact expanded size limit exceeded")
            if (
                member.file_size
                and member.file_size
                > max(1, member.compress_size) * _MAX_COMPRESSION_RATIO
            ):
                raise ValueError("artifact compression ratio limit exceeded")
            validated.append((member, pure))

        destination.mkdir(parents=True, exist_ok=False, mode=0o700)
        for member, pure in validated:
            target = destination.joinpath(*pure.parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            descriptor = os.open(target, flags, 0o600)
            try:
                with (
                    archive.open(member) as source,
                    os.fdopen(descriptor, "wb") as output,
                ):
                    descriptor = -1
                    remaining = member.file_size
                    while remaining:
                        block = source.read(min(1024 * 1024, remaining))
                        if not block:
                            raise ValueError(
                                "artifact member ended before its declared size"
                            )
                        output.write(block)
                        remaining -= len(block)
                    if source.read(1):
                        raise ValueError("artifact member exceeded its declared size")
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                if descriptor >= 0:
                    os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely extract one digest-verified GitHub artifact archive."
    )
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    extract_github_artifact(arguments.archive, arguments.destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
