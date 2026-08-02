from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from py_security_suite.inventory import inventory_target, source_snapshot
from py_security_suite.models import normalize_repo_path


class InventoryTests(unittest.TestCase):
    def test_dotfile_path_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory)
            self.assertEqual(
                normalize_repo_path(target, target / ".pytest_cache" / "TAG"),
                ".pytest_cache/TAG",
            )

    def test_generated_artifacts_and_native_tools_are_not_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory)
            (target / "src").mkdir()
            (target / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
            (target / "pyproject.toml").write_text(
                '[project]\ndependencies = ["requests>=2"]\n',
                encoding="utf-8",
            )
            (target / "pylock.toml").write_text("", encoding="utf-8")
            (target / ".git").mkdir()
            (target / "dist").mkdir()
            (target / "dist" / "example-1.0-py3-none-any.whl").write_bytes(b"fixture")
            for excluded_directory in (".artifacts", ".pysec-tools"):
                excluded = target / excluded_directory
                excluded.mkdir()
                (excluded / "dependency.py").write_text("", encoding="utf-8")
                (excluded / "pyproject.toml").write_text(
                    "[project]\n", encoding="utf-8"
                )

            inventory = inventory_target(target)

        self.assertEqual(inventory.python_files, 1)
        self.assertEqual(inventory.total_files, 3)
        self.assertEqual(
            inventory.dependency_files,
            ["pylock.toml", "pyproject.toml"],
        )
        self.assertTrue(inventory.declared_dependencies)
        self.assertEqual(inventory.lock_files, ["pylock.toml"])
        self.assertTrue(inventory.vcs_history_available)
        self.assertEqual(
            inventory.distribution_files,
            ["dist/example-1.0-py3-none-any.whl"],
        )
        self.assertEqual(inventory.hashed_files, 4)
        self.assertGreater(inventory.hashed_bytes, 0)

    def test_integrity_snapshot_detects_source_and_distribution_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory)
            (target / "app.py").write_text("value = 1\n", encoding="utf-8")
            (target / "dist").mkdir()
            artifact = target / "dist" / "example.whl"
            artifact.write_bytes(b"first")
            initial = source_snapshot(target)
            artifact.write_bytes(b"second")
            changed_artifact = source_snapshot(target)
            (target / "app.py").write_text("value = 2\n", encoding="utf-8")
            changed_source = source_snapshot(target)

        self.assertNotEqual(initial[0], changed_artifact[0])
        self.assertNotEqual(changed_artifact[0], changed_source[0])

    def test_integrity_snapshot_ignores_explicit_report_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory)
            (target / "app.py").write_text("value = 1\n", encoding="utf-8")
            output = target / "custom-report"
            initial = source_snapshot(target, excluded_paths=(output,))
            output.mkdir()
            (output / "summary.md").write_text("report", encoding="utf-8")
            after = source_snapshot(target, excluded_paths=(output,))

        self.assertEqual(initial, after)


if __name__ == "__main__":
    unittest.main()
