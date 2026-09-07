"""Digest and seal scanner assets with cooperative deadline checkpoints."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from contextlib import contextmanager
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path

from .path_safety import read_regular_file
from .strict_json import canonical_bytes


def sha256_file(path: Path, *, check: Callable[[], object] | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if check:
                check()
            digest.update(chunk)
    return digest.hexdigest()


def governed_asset_sha256(
    path: Path, *, check: Callable[[], object] | None = None
) -> str:
    """Digest one regular file or an exact, symlink-free asset directory tree."""
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("governed scanner asset is a symbolic link")
    resolved = expanded.resolve()
    if resolved.is_file():
        if resolved.stat().st_size > 16 * 1024**3:
            raise ValueError("governed scanner asset file exceeds 16 GiB")
        return sha256_file(resolved, check=check)
    if not resolved.is_dir():
        raise ValueError("governed scanner asset is not a regular file or directory")
    records: list[dict[str, object]] = []
    total_bytes = 0
    for root, directories, names in os.walk(resolved, followlinks=False):
        if check:
            check()
        root_path = Path(root)
        directories.sort()
        for directory in directories:
            if (root_path / directory).is_symlink():
                raise ValueError("governed scanner asset contains a symbolic link")
        for name in sorted(names):
            if check:
                check()
            candidate = root_path / name
            if candidate.is_symlink():
                raise ValueError("governed scanner asset contains a symbolic link")
            _, payload = read_regular_file(
                candidate,
                "governed scanner asset",
                maximum_bytes=2 * 1024**3,
                boundary=resolved,
            )
            total_bytes += len(payload)
            if len(records) >= 1_000_000 or total_bytes > 16 * 1024**3:
                raise ValueError("governed scanner asset tree exceeds its limits")
            records.append(
                {
                    "path": candidate.relative_to(resolved).as_posix(),
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
    records.sort(key=lambda item: str(item["path"]))
    return hashlib.sha256(canonical_bytes(records)).hexdigest()


@contextmanager
def sealed_governed_assets(
    assets: Mapping[str, Path],
    expected_digests: Mapping[str, str],
    *,
    check: Callable[[], object] | None = None,
) -> Iterator[dict[str, Path]]:
    """Copy governed scanner assets into an immutable, per-run private root.

    The scanner receives only the returned paths. The copy is made from
    race-resistant regular-file reads, is verified against the digest observed
    during preflight, and is re-verified before and after scanner execution.
    """
    if not assets:
        yield {}
        return
    temporary_root = Path(tempfile.mkdtemp(prefix="pysec-governed-assets-"))
    copies: dict[str, Path] = {}
    try:
        for label, source in sorted(assets.items()):
            expected = expected_digests.get(label, "")
            if not expected:
                raise ValueError(f"governed {label} asset has no preflight digest")
            resolved = source.expanduser().resolve()
            destination = temporary_root / label
            if resolved.is_file():
                _, payload = read_regular_file(
                    resolved,
                    f"governed {label} asset snapshot",
                    maximum_bytes=2 * 1024**3,
                )
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(destination, 0o400)
            elif resolved.is_dir():
                destination.mkdir(mode=0o700)
                files = 0
                total_bytes = 0
                for root, directories, names in os.walk(resolved, followlinks=False):
                    root_path = Path(root)
                    relative_root = root_path.relative_to(resolved)
                    for directory in sorted(directories):
                        candidate = root_path / directory
                        if candidate.is_symlink():
                            raise ValueError(
                                f"governed {label} asset contains a symbolic link"
                            )
                        (destination / relative_root / directory).mkdir(mode=0o700)
                    for name in sorted(names):
                        if check:
                            check()
                        candidate = root_path / name
                        if candidate.is_symlink():
                            raise ValueError(
                                f"governed {label} asset contains a symbolic link"
                            )
                        _, payload = read_regular_file(
                            candidate,
                            f"governed {label} asset snapshot member",
                            maximum_bytes=2 * 1024**3,
                            boundary=resolved,
                        )
                        files += 1
                        total_bytes += len(payload)
                        if files > 1_000_000 or total_bytes > 16 * 1024**3:
                            raise ValueError(
                                f"governed {label} asset exceeds snapshot limits"
                            )
                        output = destination / relative_root / name
                        with output.open("xb") as handle:
                            handle.write(payload)
                            handle.flush()
                            os.fsync(handle.fileno())
                        os.chmod(output, 0o400)
                for snapshot_directory in sorted(
                    (item for item in destination.rglob("*") if item.is_dir()),
                    reverse=True,
                ):
                    os.chmod(snapshot_directory, 0o500)
                os.chmod(destination, 0o500)
            else:
                raise ValueError(
                    f"governed {label} asset is not a regular file or directory"
                )
            if governed_asset_sha256(destination, check=check) != expected:
                raise ValueError(f"governed {label} asset changed while it was sealed")
            copies[label] = destination
        os.chmod(temporary_root, 0o500)
        yield copies
        for label, snapshot in copies.items():
            if governed_asset_sha256(snapshot, check=check) != expected_digests[label]:
                raise ValueError(
                    f"governed {label} asset snapshot changed during scanner execution"
                )
    finally:
        if temporary_root.exists():
            for item in [temporary_root, *temporary_root.rglob("*")]:
                try:
                    os.chmod(item, 0o700 if item.is_dir() else 0o600)
                except OSError:
                    pass
            shutil.rmtree(temporary_root, ignore_errors=False)
