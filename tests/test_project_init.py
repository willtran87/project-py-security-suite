from __future__ import annotations

import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.cli import main
from py_security_suite.config import load_config
from py_security_suite.project_init import (
    PROJECT_TEMPLATES,
    project_profile,
    render_project_config,
)


class ProjectInitializationTests(unittest.TestCase):
    def test_unknown_templates_and_profiles_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown project template"):
            render_project_config("unknown")
        with self.assertRaisesRegex(ValueError, "unknown project template"):
            project_profile("unknown")
        with self.assertRaisesRegex(ValueError, "unknown scan profile"):
            project_profile("library", "unknown")

    def test_every_template_is_valid_and_uses_a_supported_profile(self) -> None:
        for template in PROJECT_TEMPLATES:
            with self.subTest(template=template), tempfile.TemporaryDirectory() as root:
                config_path = Path(root) / "pysec.toml"
                config_path.write_text(
                    render_project_config(template), encoding="utf-8"
                )
                config = load_config(repository_config=config_path)
                self.assertTrue(config.selected_tools)
                self.assertEqual(config.isolation.network, "deny")
                self.assertFalse(config.isolation.execute_target_code)

    def test_init_publishes_config_and_versioned_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            target = Path(root)
            with patch("builtins.print") as output:
                self.assertEqual(
                    main(
                        [
                            "init",
                            str(target),
                            "--template",
                            "api",
                            "--format",
                            "json",
                        ]
                    ),
                    0,
                )
            receipt = json.loads(output.call_args.args[0])
            config = load_config(repository_config=target / "pysec.toml")

        self.assertEqual(receipt["template"], "api")
        self.assertEqual(receipt["profile"], "comprehensive")
        self.assertEqual(receipt["selected_tools"], len(config.selected_tools))
        self.assertFalse(receipt["authoritative"])
        self.assertEqual(receipt["configuration"], "pysec.toml")
        self.assertEqual(receipt["next_steps"][0]["argv"][1], "doctor")
        schema = json.loads(
            files("py_security_suite")
            .joinpath("schemas", "project-init.schema.json")
            .read_text("utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(receipt)

    def test_init_is_atomic_bounded_and_requires_explicit_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "project"
            target.mkdir()
            outside = Path(root) / "outside.toml"
            self.assertEqual(main(["init", str(target)]), 0)
            original = (target / "pysec.toml").read_text(encoding="utf-8")
            with patch("builtins.print") as error:
                self.assertEqual(main(["init", str(target)]), 3)
            self.assertIn("already exists", error.call_args.args[0])
            self.assertEqual(
                (target / "pysec.toml").read_text(encoding="utf-8"), original
            )
            with patch("builtins.print") as error:
                self.assertEqual(
                    main(["init", str(target), "--output", str(outside)]), 3
                )
            self.assertIn("must be inside", error.call_args.args[0])
            self.assertFalse(outside.exists())
            self.assertEqual(
                main(
                    [
                        "init",
                        str(target),
                        "--template",
                        "cli",
                        "--profile",
                        "quick",
                        "--overwrite",
                    ]
                ),
                0,
            )
            updated = (target / "pysec.toml").read_text(encoding="utf-8")
            self.assertIn('profile = "quick"', updated)
            self.assertEqual(list(target.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
