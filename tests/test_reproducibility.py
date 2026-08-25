from __future__ import annotations

import json
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.cli import main
from py_security_suite.report_inspection import read_bundled_schema
from py_security_suite.reproducibility import (
    compare_builds,
    normalize_sdist,
    render_reproducibility_markdown,
)


class ReproducibilityTests(unittest.TestCase):
    def test_identical_closed_directories_produce_consumable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            first.mkdir()
            second.mkdir()
            (first / "project.whl").write_bytes(b"wheel")
            (second / "project.whl").write_bytes(b"wheel")
            result = compare_builds(first, second)

        self.assertTrue(result["reproducible"])
        self.assertEqual(result["status"], "match")
        self.assertEqual(result["findings"], [])
        self.assertEqual(
            result["builds"][0]["aggregate_sha256"],
            result["builds"][1]["aggregate_sha256"],
        )
        schema = json.loads(read_bundled_schema("reproducible-build-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result)
        self.assertIn("`MATCH`", render_reproducibility_markdown(result))

    def test_changed_missing_and_unexpected_artifacts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            first.mkdir()
            second.mkdir()
            (first / "changed.whl").write_bytes(b"one")
            (second / "changed.whl").write_bytes(b"two")
            (first / "missing.tar.gz").write_bytes(b"missing")
            (second / "unexpected.txt").write_bytes(b"unexpected")
            result = compare_builds(first, second)

        self.assertFalse(result["reproducible"])
        self.assertEqual(result["status"], "mismatch")
        self.assertEqual(
            result["differences"]["missing_from_second"], ["missing.tar.gz"]
        )
        self.assertEqual(
            result["differences"]["unexpected_in_second"], ["unexpected.txt"]
        )
        self.assertEqual(len(result["differences"]["changed"]), 1)
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_cli_publishes_json_outside_compared_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            first.mkdir()
            second.mkdir()
            (first / "artifact").write_bytes(b"same")
            (second / "artifact").write_bytes(b"same")
            output = root / "reproducible-build.json"
            with patch("builtins.print"):
                self.assertEqual(
                    main(
                        [
                            "compare-builds",
                            str(first),
                            str(second),
                            "--format",
                            "json",
                            "--output",
                            str(output),
                        ]
                    ),
                    0,
                )
            self.assertTrue(json.loads(output.read_text("utf-8"))["reproducible"])

            with patch("builtins.print"):
                self.assertEqual(
                    main(
                        [
                            "compare-builds",
                            str(first),
                            str(second),
                            "--output",
                            str(second / "forbidden.json"),
                        ]
                    ),
                    3,
                )

    def test_labels_and_file_count_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            first.mkdir()
            second.mkdir()
            with self.assertRaisesRegex(ValueError, "build label"):
                compare_builds(first, second, first_label=" ")
            (first / "one").write_bytes(b"1")
            with (
                patch("py_security_suite.reproducibility._MAX_FILES", 0),
                self.assertRaisesRegex(ValueError, "exceeds 0 files"),
            ):
                compare_builds(first, second)

    def test_same_directory_cannot_be_presented_as_reproducibility_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "must be distinct"):
                compare_builds(root, root)

    def test_sdist_normalization_removes_archive_metadata_variance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first.tar.gz", root / "second.tar.gz"
            _sdist(first, mtime=100)
            _sdist(second, mtime=200)
            first_output = root / "normalized-a.tar.gz"
            second_output = root / "normalized-b.tar.gz"
            first_receipt = normalize_sdist(
                first, first_output, epoch=42, overwrite=False
            )
            second_receipt = normalize_sdist(
                second, second_output, epoch=42, overwrite=False
            )

            self.assertEqual(first_output.read_bytes(), second_output.read_bytes())
            self.assertNotEqual(
                first_receipt["input_sha256"], second_receipt["input_sha256"]
            )
            self.assertEqual(
                first_receipt["output_sha256"], second_receipt["output_sha256"]
            )
            schema = json.loads(read_bundled_schema("sdist-normalization-1.0"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(first_receipt)

    def test_sdist_normalization_rejects_link_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "linked.tar.gz"
            with tarfile.open(source, mode="w:gz") as archive:
                link = tarfile.TarInfo("project/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "../outside"
                archive.addfile(link)
            with self.assertRaisesRegex(ValueError, "only files and directories"):
                normalize_sdist(source, root / "output.tar.gz", epoch=42)


def _sdist(path: Path, *, mtime: int) -> None:
    with tarfile.open(path, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        root = tarfile.TarInfo("project-1.0")
        root.type = tarfile.DIRTYPE
        root.mode = 0o777
        root.mtime = mtime
        archive.addfile(root)
        content = b"value\n"
        member = tarfile.TarInfo("project-1.0/value.txt")
        member.size = len(content)
        member.mode = 0o666
        member.mtime = mtime
        member.uid = mtime
        member.gid = mtime
        archive.addfile(member, io.BytesIO(content))


if __name__ == "__main__":
    unittest.main()
