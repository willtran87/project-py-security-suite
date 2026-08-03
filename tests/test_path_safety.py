from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.path_safety import (
    is_link_like,
    resolve_regular_directory,
    resolve_regular_file,
    resolve_unlinked_path,
)


class PathSafetyTests(unittest.TestCase):
    def test_regular_paths_are_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            evidence.write_text("{}", encoding="utf-8")
            self.assertEqual(resolve_regular_directory(root, "root"), root.resolve())
            self.assertEqual(
                resolve_regular_file(evidence, "evidence"), evidence.resolve()
            )
            self.assertEqual(
                resolve_unlinked_path(root / "future", "future"),
                (root / "future").resolve(),
            )
            self.assertFalse(is_link_like(evidence))

    def test_links_and_junctions_are_rejected_before_resolution(self) -> None:
        path = Path("requested-trust-input")
        with patch.object(Path, "is_junction", return_value=True, create=True):
            self.assertTrue(is_link_like(path))
            for resolver in (
                resolve_unlinked_path,
                resolve_regular_file,
                resolve_regular_directory,
            ):
                with (
                    self.subTest(resolver=resolver.__name__),
                    self.assertRaisesRegex(ValueError, "symbolic link or junction"),
                ):
                    resolver(path, "trust input")

    def test_linked_components_inside_a_boundary_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).absolute()
            linked_parent = root / "linked-parent"
            evidence = linked_parent / "evidence.json"
            with patch(
                "py_security_suite.path_safety.is_link_like",
                side_effect=lambda path: path == linked_parent,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "cannot contain a symbolic link or junction",
                ):
                    resolve_unlinked_path(evidence, "evidence", boundary=root)

    def test_absolute_paths_outside_a_boundary_remain_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).absolute()
            external = root.parent / "approved-external-evidence.json"
            with patch(
                "py_security_suite.path_safety.is_link_like",
                side_effect=lambda path: path == root.parent,
            ):
                self.assertEqual(
                    resolve_unlinked_path(external, "evidence", boundary=root),
                    external.resolve(),
                )

    def test_relative_boundary_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).absolute()
            escaped = root / ".." / "outside.json"
            with self.assertRaisesRegex(ValueError, "cannot traverse outside"):
                resolve_unlinked_path(escaped, "evidence", boundary=root)


if __name__ == "__main__":
    unittest.main()
