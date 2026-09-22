from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.inventory import source_snapshot
from py_security_suite.models import Inventory
from py_security_suite.scan_control import ScanControl, controlled_scan
from py_security_suite.scan_finalization import verify_final_source


def inventory_for(root: Path) -> Inventory:
    digest, count, size = source_snapshot(root)
    return Inventory(
        python_files=1,
        dependency_files=[],
        total_files=1,
        skipped_symlinks=0,
        source_sha256=digest,
        hashed_files=count,
        hashed_bytes=size,
    )


@pytest.mark.parametrize("change", ["none", "original", "snapshot", "symlink"])
def test_completed_finalization_still_requires_both_unchanged_sources(tmp_path, change):
    original, snapshot = tmp_path / "original", tmp_path / "snapshot"
    for root in (original, snapshot):
        root.mkdir()
        (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    inventory = inventory_for(original)
    if change in {"original", "snapshot"}:
        ((original if change == "original" else snapshot) / "app.py").write_text(
            "value = 2\n", encoding="utf-8"
        )
    if change == "symlink":
        inventory.skipped_symlinks = 1
    verify_final_source(inventory, original, snapshot, ())
    assert inventory.source_integrity_verified is (change == "none")


@pytest.mark.parametrize("stage", ["before", "between"])
def test_interrupted_finalization_cannot_retain_verified_source_claim(tmp_path, stage):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    inventory = inventory_for(tmp_path)
    inventory.source_integrity_verified = True
    control = ScanControl()
    calls = []

    def observe(*args, **kwargs):
        calls.append(True)
        value = source_snapshot(*args, **kwargs)
        control.cancel()
        return value

    if stage == "before":
        control.cancel()
    with (
        controlled_scan(control),
        patch(
            "py_security_suite.scan_finalization.source_snapshot", side_effect=observe
        ),
    ):
        errors = verify_final_source(inventory, tmp_path, tmp_path, ())
    assert not inventory.source_integrity_verified
    assert any("unverified" in error for error in errors)
    assert len(calls) == (0 if stage == "before" else 2)
