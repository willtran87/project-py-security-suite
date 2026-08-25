from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.config_advisor import (
    _path_kind,
    advise_configuration,
    render_config_advice,
    render_config_advice_markdown,
)
from py_security_suite.report_inspection import read_bundled_schema


class ConfigAdvisorTests(unittest.TestCase):
    def test_path_kind_is_independent_of_the_runner_operating_system(self) -> None:
        for value in ("C:/approved/tool.exe", r"C:\approved\tool.exe", "/opt/tool"):
            with self.subTest(value=value):
                self.assertEqual(_path_kind(value), "absolute")
        self.assertEqual(_path_kind("tools/scanner"), "relative")
        self.assertEqual(_path_kind("@bundle/bin/scanner"), "bundle")

    def test_valid_configuration_reports_portability_and_authority_advice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "pysec.toml"
            config.write_text(
                'schema_version = "1"\n'
                'profile = "quick"\n'
                "[paths]\n"
                'bundle_root = ".pysec-tools"\n'
                "[tools.bandit]\n"
                'executable = "C:/approved/bandit.exe"\n'
                f'executable_sha256 = "{"a" * 64}"\n',
                encoding="utf-8",
            )
            document = advise_configuration(repository_config=config)

        self.assertEqual(document["decision"], "valid_with_advice")
        self.assertEqual(document["effective"]["profile"], "quick")
        self.assertEqual(document["path_inventory"]["relative"], 1)
        self.assertEqual(document["path_inventory"]["absolute"], 1)
        self.assertTrue(
            any(item["category"] == "authority" for item in document["recommendations"])
        )
        self.assertNotIn("C:/approved", json.dumps(document))
        self.assertIn("VALID WITH ADVICE", render_config_advice(document))
        self.assertIn(
            "# Configuration assessment", render_config_advice_markdown(document)
        )
        schema = json.loads(read_bundled_schema("config-advice-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

    def test_unsupported_schema_returns_actionable_invalid_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "legacy.toml"
            config.write_text(
                'schema_version = "0"\nprofile = "quick"\n', encoding="utf-8"
            )
            document = advise_configuration(repository_config=config)

        self.assertEqual(document["decision"], "invalid")
        self.assertTrue(document["compatibility"]["migration_required"])
        self.assertFalse(document["compatibility"]["automatic_migration_performed"])
        self.assertIsNone(document["effective"])
        self.assertIn("schema_version '1'", document["validation_errors"][0])
        self.assertIn("pysec init", document["compatibility"]["actions"][0])

    def test_invalid_toml_is_reported_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "broken.toml"
            config.write_text("profile = [", encoding="utf-8")
            before = config.read_bytes()
            document = advise_configuration(repository_config=config)
            after = config.read_bytes()

        self.assertEqual(document["decision"], "invalid")
        self.assertTrue(document["validation_errors"])
        self.assertEqual(before, after)
        self.assertIn("Validation errors:", render_config_advice(document))
        self.assertIn("## Validation errors", render_config_advice_markdown(document))

    def test_current_minimal_configuration_needs_no_migration_or_advice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "minimal.toml"
            policy = root / "policy.toml"
            config.write_text(
                'schema_version = "1"\nprofile = "quick"\n', encoding="utf-8"
            )
            policy.write_text('schema_version = "1"\n', encoding="utf-8")
            document = advise_configuration(
                repository_config=config, organization_policy=policy
            )

        self.assertEqual(document["decision"], "valid")
        self.assertEqual(document["recommendations"], [])
        self.assertIn(
            "No configuration improvements", render_config_advice_markdown(document)
        )

    def test_missing_configuration_returns_bounded_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "absent.toml"
            document = advise_configuration(repository_config=missing)

        self.assertEqual(document["decision"], "invalid")
        self.assertEqual(document["sources"]["repository"]["name"], "absent.toml")
        self.assertIsNone(document["sources"]["repository"]["sha256"])
        self.assertNotIn(str(missing.parent), json.dumps(document))


if __name__ == "__main__":
    unittest.main()
