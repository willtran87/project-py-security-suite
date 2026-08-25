from __future__ import annotations

import hashlib
import json
import runpy
import tempfile
import unittest
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast


class OsvSnapshotValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(
            self.enterContext(tempfile.TemporaryDirectory())  # pylint: disable=R1732
        )
        namespace = runpy.run_path(
            str(Path(__file__).parents[1] / "scripts" / "validate-osv-snapshot.py")
        )
        self.validate = cast(
            Callable[[Path, str], dict[str, Any]], namespace["validate_snapshot"]
        )

    def test_valid_snapshot_returns_bounded_receipt(self) -> None:
        archive = self._archive(
            [
                ("PYSEC-1.json", self._record("PYSEC-1", "2026-08-08T00:00:00Z")),
                (
                    "GHSA-1.json",
                    self._record("GHSA-1", "2026-08-09T00:00:00.123Z"),
                ),
            ]
        )
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()

        receipt = self.validate(archive, digest)

        self.assertTrue(receipt["structurally_validated"])
        self.assertEqual(receipt["records"], 2)
        self.assertEqual(receipt["newest_modified"], "2026-08-09T00:00:00.123Z")

    def test_digest_paths_and_record_contract_fail_closed(self) -> None:
        valid = self._archive(
            [("PYSEC-1.json", self._record("PYSEC-1", "2026-08-09T00:00:00Z"))]
        )
        with self.assertRaisesRegex(ValueError, "approved digest"):
            self.validate(valid, "0" * 64)

        unsafe = self._archive(
            [("../escape.json", self._record("PYSEC-1", "2026-08-09T00:00:00Z"))]
        )
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.validate(unsafe, hashlib.sha256(unsafe.read_bytes()).hexdigest())

        duplicate = self._archive(
            [
                ("one.json", self._record("PYSEC-1", "2026-08-09T00:00:00Z")),
                ("two.json", self._record("PYSEC-1", "2026-08-09T00:00:01Z")),
            ]
        )
        with self.assertRaisesRegex(ValueError, "duplicate OSV ID"):
            self.validate(duplicate, hashlib.sha256(duplicate.read_bytes()).hexdigest())

    def _archive(self, records: list[tuple[str, dict[str, object]]]) -> Path:
        archive = self.root / f"snapshot-{len(list(self.root.glob('*.zip')))}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name, record in records:
                bundle.writestr(name, json.dumps(record))
        return archive

    @staticmethod
    def _record(identifier: str, modified: str) -> dict[str, object]:
        return {"id": identifier, "modified": modified, "affected": []}
