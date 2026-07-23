from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from py_security_suite.inventory import inventory_target
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
            (target / "dist" / "example-1.0-py3-none-any.whl").write_bytes(
                b"fixture"
            )
            for excluded_directory in (".artifacts", ".pysec-tools"):
                excluded = target / excluded_directory
                excluded.mkdir()
                (excluded / "dependency.py").write_text("", encoding="utf-8")
                (excluded / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

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


if __name__ == "__main__":
    unittest.main()
