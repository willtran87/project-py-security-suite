from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.precommit_config import (
    build_precommit_config,
    render_precommit_receipt,
)
from py_security_suite.report_inspection import read_bundled_schema


class PreCommitConfigTests(unittest.TestCase):
    def test_hooks_are_local_non_executing_and_schema_governed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            output = target / ".pre-commit-config.yaml"
            rendered, receipt = build_precommit_config(
                target=target,
                output=output,
                profile="quick",
                config_path="security/pysec.toml",
            )

        self.assertIn("repo: local", rendered)
        self.assertIn("language: system", rendered)
        self.assertIn("pass_filenames: false", rendered)
        self.assertIn("py_security_suite adapter-check", rendered)
        self.assertIn("py_security_suite doctor", rendered)
        self.assertNotIn("py_security_suite scan", rendered)
        self.assertNotIn("pip install", rendered)
        self.assertFalse(receipt["authoritative"])
        self.assertIn("do not execute the scanner portfolio", receipt["scope"])
        self.assertIn("Mode: local diagnostics", render_precommit_receipt(receipt))
        schema = json.loads(read_bundled_schema("precommit-config-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(receipt)

    def test_unsafe_configuration_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            for value in ("../pysec.toml", "/outside/pysec.toml", "a.toml; echo bad"):
                with (
                    self.subTest(value=value),
                    self.assertRaisesRegex(ValueError, "repository-relative"),
                ):
                    build_precommit_config(
                        target=target,
                        output=target / ".pre-commit-config.yaml",
                        profile="quick",
                        config_path=value,
                    )

            with self.assertRaisesRegex(ValueError, "unsupported profile"):
                build_precommit_config(
                    target=target,
                    output=target / ".pre-commit-config.yaml",
                    profile="unknown",
                    config_path="pysec.toml",
                )


if __name__ == "__main__":
    unittest.main()
