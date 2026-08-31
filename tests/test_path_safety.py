from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.path_safety import (
    HeldParentDirectory,
    is_link_like,
    open_regular_file,
    read_regular_file,
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

    def test_bounded_read_uses_one_regular_file_handle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            evidence.write_bytes(b"trusted")

            resolved, payload = read_regular_file(evidence, "evidence", maximum_bytes=7)

            self.assertEqual(resolved, evidence.resolve())
            self.assertEqual(payload, b"trusted")

    def test_regular_file_open_rejects_invalid_limits_and_non_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "maximum_bytes must be positive"):
                with open_regular_file(root, "evidence", maximum_bytes=0):
                    pass
            with self.assertRaisesRegex(ValueError, "not a regular file|opened safely"):
                with open_regular_file(root, "evidence", maximum_bytes=10):
                    pass

    def test_open_file_detects_ancestor_identity_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            evidence.write_bytes(b"trusted")
            with (
                patch(
                    "py_security_suite.path_safety._component_identities",
                    side_effect=[(("before", 1, 1, 0),), (("after", 1, 2, 0),)],
                ),
                self.assertRaisesRegex(ValueError, "path components changed"),
            ):
                with open_regular_file(evidence, "evidence", maximum_bytes=10) as (
                    _,
                    handle,
                    _,
                ):
                    self.assertEqual(handle.read(), b"trusted")

    def test_bounded_read_rejects_oversized_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            evidence.write_bytes(b"too-large")
            with self.assertRaisesRegex(ValueError, "exceeds 3 bytes"):
                read_regular_file(evidence, "evidence", maximum_bytes=3)

    def test_held_parent_mutations_cannot_escape_pinned_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).absolute()
            held = HeldParentDirectory(root, None)
            with self.assertRaisesRegex(ValueError, "rename must remain"):
                held.rename(root / "source", root.parent / "destination")
            with self.assertRaisesRegex(ValueError, "replacement must remain"):
                held.replace(root / "source", root.parent / "destination")
            with self.assertRaisesRegex(ValueError, "deletion must remain"):
                held.remove_tree(root.parent / "outside")

    def test_held_parent_syncs_descriptor_on_posix(self) -> None:
        held = HeldParentDirectory(Path.cwd().absolute(), 7)
        with (
            patch("py_security_suite.path_safety.os.name", "posix"),
            patch("py_security_suite.path_safety.os.fsync") as fsync,
        ):
            held.sync()

        fsync.assert_called_once_with(7)

    def test_held_parent_uses_descriptor_relative_rename_on_posix(self) -> None:
        root = Path.cwd().absolute()
        held = HeldParentDirectory(root, 11)
        with (
            patch("py_security_suite.path_safety.os.name", "posix"),
            patch("py_security_suite.path_safety.os.rename") as rename,
            patch.object(HeldParentDirectory, "sync") as sync,
        ):
            held.rename(root / "source", root / "destination")

        rename.assert_called_once_with(
            "source", "destination", src_dir_fd=11, dst_dir_fd=11
        )
        sync.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
