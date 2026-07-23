from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from py_security_suite.config import ConfigurationError, load_config


class ConfigTests(unittest.TestCase):
    def test_defaults_select_standard_offline_profile(self) -> None:
        config = load_config()
        self.assertEqual(config.profile, "standard")
        self.assertEqual(config.isolation.network, "deny")
        self.assertFalse(config.isolation.execute_target_code)
        self.assertEqual(
            config.required_tools,
            ("bandit", "semgrep", "detect-secrets", "osv-scanner"),
        )

    def test_quick_profile_override_changes_derived_required_tools(self) -> None:
        config = load_config(profile_override="quick")
        self.assertEqual(config.required_tools, ("bandit", "detect-secrets"))

    def test_comprehensive_profile_selects_every_implemented_tool(self) -> None:
        config = load_config(profile_override="comprehensive")
        self.assertEqual(len(config.selected_tools), 19)
        self.assertEqual(config.required_tools, config.selected_tools)
        self.assertIn("cyclonedx-py", config.selected_tools)
        self.assertIn("codeql", config.selected_tools)
        self.assertIn("syft", config.selected_tools)
        self.assertIn("pypi-attestations", config.selected_tools)

    def test_production_profile_blocks_medium_and_selects_full_suite(self) -> None:
        config = load_config(profile_override="production")
        self.assertEqual(config.required_tools, config.selected_tools)
        self.assertEqual(len(config.selected_tools), 14)
        self.assertIn("medium", {severity.value for severity in config.policy.block_severities})

    def test_release_profile_adds_artifact_assurance(self) -> None:
        config = load_config(profile_override="release")
        self.assertEqual(len(config.selected_tools), 19)
        self.assertIn("grype", config.required_tools)
        self.assertIn("check-wheel-contents", config.required_tools)

    def test_repository_cannot_weaken_default_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "pysec.toml"
            config_path.write_text(
                '[isolation]\nrequire_attestation = false\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError, "cannot disable isolation attestation"
            ):
                load_config(repository_config=config_path)

    def test_unknown_configuration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "pysec.toml"
            config_path.write_text("mystery = true\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ConfigurationError, "unknown top-level settings"
            ):
                load_config(repository_config=config_path)


if __name__ == "__main__":
    unittest.main()
