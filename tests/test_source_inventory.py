from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest.mock import patch

from py_security_suite.source_inventory import (
    load_source_inventory,
    verify_source_inventory,
    verify_source_inventory_file,
)


def _document() -> tuple[dict[str, object], dict[str, object]]:
    records = [
        {"path": "README.md", "size_bytes": 3, "sha256": "1" * 64},
        {"path": "src/example.py", "size_bytes": 7, "sha256": "2" * 64},
    ]
    aggregate = hashlib.sha256()
    for record in records:
        relative = str(record["path"]).encode()
        size = cast(int, record["size_bytes"])
        aggregate.update(len(relative).to_bytes(8, "big"))
        aggregate.update(relative)
        aggregate.update(size.to_bytes(8, "big"))
        aggregate.update(bytes.fromhex(str(record["sha256"])))
    digest = aggregate.hexdigest()
    document: dict[str, object] = {
        "schema_version": "1.0",
        "scope": "Exact source identities.",
        "source_sha256": digest,
        "total_files": 2,
        "total_bytes": 10,
        "files": records,
    }
    manifest = {
        "source_sha256": digest,
        "hashed_files": 2,
        "hashed_bytes": 10,
        "source_integrity_verified": True,
    }
    return document, manifest


class SourceInventoryTests(unittest.TestCase):
    def test_verifies_canonical_inventory_and_manifest_binding(self) -> None:
        document, manifest = _document()
        identity = verify_source_inventory(document, manifest, require_unchanged=True)
        self.assertEqual(identity.total_files, 2)
        self.assertEqual(identity.total_bytes, 10)
        self.assertEqual(identity.paths, frozenset({"README.md", "src/example.py"}))

    def test_rejects_unsafe_noncanonical_duplicate_and_unsorted_paths(self) -> None:
        for values in (
            ["../outside.py"],
            ["/absolute.py"],
            ["src\\windows.py"],
            ["C:/windows.py"],
            ["C:drive-relative.py"],
            ["src//duplicate.py"],
            ["z.py", "a.py"],
            ["a.py", "a.py"],
        ):
            with self.subTest(values=values):
                document, manifest = _document()
                records = [
                    {"path": value, "size_bytes": 0, "sha256": "0" * 64}
                    for value in values
                ]
                document["files"] = records
                document["total_files"] = len(records)
                document["total_bytes"] = 0
                with self.assertRaisesRegex(ValueError, "path|sorted"):
                    verify_source_inventory(document, manifest)

    def test_rejects_extra_fields_and_invalid_file_identity(self) -> None:
        document, manifest = _document()
        document["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "fields"):
            verify_source_inventory(document, manifest)

        document, manifest = _document()
        records = cast(list[dict[str, object]], copy.deepcopy(document["files"]))
        records[0]["size_bytes"] = True
        document["files"] = records
        with self.assertRaisesRegex(ValueError, "file identity"):
            verify_source_inventory(document, manifest)

    def test_rejects_aggregate_and_manifest_mismatches(self) -> None:
        document, manifest = _document()
        document["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "aggregate"):
            verify_source_inventory(document, manifest)

        document, manifest = _document()
        manifest["hashed_files"] = 3
        with self.assertRaisesRegex(ValueError, "scan manifest"):
            verify_source_inventory(document, manifest)

    def test_clean_evidence_requires_unchanged_snapshot(self) -> None:
        document, manifest = _document()
        manifest["source_integrity_verified"] = False
        with self.assertRaisesRegex(ValueError, "unchanged"):
            verify_source_inventory(document, manifest, require_unchanged=True)

    def test_file_count_and_total_bytes_are_bounded(self) -> None:
        document, manifest = _document()
        with (
            patch("py_security_suite.source_inventory._MAX_FILES", 1),
            self.assertRaisesRegex(ValueError, "exceeds 1 files"),
        ):
            verify_source_inventory(document, manifest)

        document, manifest = _document()
        records = cast(list[dict[str, object]], copy.deepcopy(document["files"]))
        records[0]["size_bytes"] = (1 << 64) - 1
        records[1]["size_bytes"] = 1
        document["files"] = records
        with self.assertRaisesRegex(ValueError, "total byte count"):
            verify_source_inventory(document, manifest)

        document, manifest = _document()
        document["scope"] = "x" * 5
        with (
            patch("py_security_suite.source_inventory._MAX_SCOPE_BYTES", 4),
            self.assertRaisesRegex(ValueError, "bounded string"),
        ):
            verify_source_inventory(document, manifest)

    def test_file_loader_is_bounded_to_regular_json_objects(self) -> None:
        document, manifest = _document()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source-inventory.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(
                verify_source_inventory_file(path, manifest).total_files, 2
            )
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(TypeError, "root"):
                load_source_inventory(path)
            path.write_bytes(b"\xff\xfe")
            with self.assertRaisesRegex(ValueError, "JSON is invalid"):
                load_source_inventory(path)
            path.write_bytes(b"{}")
            with (
                patch("py_security_suite.source_inventory._MAX_DOCUMENT_BYTES", 1),
                self.assertRaisesRegex(ValueError, "maximum document size"),
            ):
                load_source_inventory(path)


if __name__ == "__main__":
    unittest.main()
