from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from py_security_suite.cli import _prepare_output


class CliSafetyTests(unittest.TestCase):
    def test_overwrite_rejects_unmarked_nonempty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            output = root / "important"
            output.mkdir()
            (output / "user-data.txt").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                _prepare_output(target=target, output=output, overwrite=True)
            self.assertTrue((output / "user-data.txt").exists())


if __name__ == "__main__":
    unittest.main()
