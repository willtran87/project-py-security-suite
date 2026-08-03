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


if __name__ == "__main__":
    unittest.main()
