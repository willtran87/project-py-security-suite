"""Finalize source identity without making cancellation wait for a full rehash."""

from pathlib import Path

from .inventory import source_snapshot
from .models import Inventory
from .scan_control import ScanInterrupted, analysis_checkpoint


def verify_final_source(
    inventory: Inventory,
    target: Path,
    scan_target: Path,
    source_exclusions: tuple[Path, ...],
) -> list[str]:
    errors = []
    inventory.source_integrity_verified = False
    inventory.source_sha256_after = ""
    inventory.hashed_files_after = inventory.hashed_bytes_after = 0
    try:
        analysis_checkpoint()
        (
            inventory.source_sha256_after,
            inventory.hashed_files_after,
            inventory.hashed_bytes_after,
        ) = source_snapshot(target, excluded_paths=source_exclusions)
        snapshot_after = source_snapshot(scan_target)
        expected = (
            inventory.source_sha256,
            inventory.hashed_files,
            inventory.hashed_bytes,
        )
        if snapshot_after != expected:
            errors.append("sealed scan snapshot changed during scanner execution")
        inventory.source_integrity_verified = (
            expected
            == (
                inventory.source_sha256_after,
                inventory.hashed_files_after,
                inventory.hashed_bytes_after,
            )
            == snapshot_after
            and inventory.skipped_symlinks == 0
        )
    except ScanInterrupted:
        errors.append(
            "source integrity verification interrupted; post-scan source identity is unverified"
        )
    if inventory.skipped_symlinks:
        errors.append(
            f"source inventory rejected {inventory.skipped_symlinks} symbolic link(s)"
        )
    return errors
