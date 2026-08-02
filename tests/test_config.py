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
        self.assertEqual(len(config.selected_tools), 62)
        self.assertEqual(config.required_tools, config.selected_tools)
        self.assertIn("cyclonedx-py", config.selected_tools)
        self.assertIn("codeql", config.selected_tools)
        self.assertIn("syft", config.selected_tools)
        self.assertIn("pypi-attestations", config.selected_tools)
        self.assertIn("mypy", config.selected_tools)
        self.assertIn("devskim", config.selected_tools)
        self.assertIn("pylint", config.selected_tools)
        self.assertIn("coverage", config.selected_tools)
        self.assertIn("reuse", config.selected_tools)
        self.assertIn("psscriptanalyzer", config.selected_tools)
        self.assertIn("shellcheck", config.selected_tools)
        self.assertIn("deptry", config.selected_tools)
        self.assertIn("diff-cover", config.selected_tools)
        self.assertIn("checkov", config.selected_tools)
        self.assertIn("cosign", config.selected_tools)
        self.assertIn("pyright", config.selected_tools)
        self.assertIn("scorecard", config.selected_tools)
        self.assertIn("conftest", config.selected_tools)
        self.assertIn("git-sizer", config.selected_tools)
        self.assertIn("crosshair", config.selected_tools)
        self.assertIn("github-attestation", config.selected_tools)
        self.assertIn("hypothesis", config.selected_tools)
        self.assertIn("schemathesis", config.selected_tools)
        self.assertIn("zap", config.selected_tools)
        self.assertIn("pytm", config.selected_tools)
        self.assertIn("in-toto", config.selected_tools)
        self.assertIn("reproducible-build", config.selected_tools)
        self.assertIn("yara", config.selected_tools)

    def test_production_profile_blocks_medium_and_selects_full_suite(self) -> None:
        config = load_config(profile_override="production")
        self.assertEqual(config.required_tools, config.selected_tools)
        self.assertEqual(len(config.selected_tools), 49)
        self.assertIn(
            "medium", {severity.value for severity in config.policy.block_severities}
        )
        self.assertIn("hadolint", config.selected_tools)
        self.assertIn("devskim", config.selected_tools)

    def test_release_profile_adds_artifact_assurance(self) -> None:
        config = load_config(profile_override="release")
        self.assertEqual(len(config.selected_tools), 62)
        self.assertIn("grype", config.required_tools)
        self.assertIn("check-wheel-contents", config.required_tools)
        self.assertIn("cosign", config.required_tools)

    def test_quality_and_repo_profiles_expose_distinct_coverage(self) -> None:
        quality = load_config(profile_override="quality")
        repo = load_config(profile_override="repo")
        self.assertEqual(len(quality.selected_tools), 24)
        self.assertEqual(len(repo.selected_tools), 52)
        self.assertIn("ruff-quality", quality.selected_tools)
        self.assertIn("mypy", repo.selected_tools)
        self.assertIn("tach", quality.selected_tools)
        self.assertIn("ruff-format", quality.selected_tools)
        self.assertIn("junit", quality.selected_tools)
        self.assertIn("diff-cover", quality.selected_tools)
        self.assertIn("psscriptanalyzer", quality.selected_tools)
        self.assertNotIn("syft", repo.selected_tools)

    def test_repository_cannot_weaken_default_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "pysec.toml"
            config_path.write_text(
                "[isolation]\nrequire_attestation = false\n",
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

    def test_intelligence_and_baseline_require_digest_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "pysec.toml"
            config_path.write_text(
                '[intelligence]\nkev_path = "security/kev.json"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "configured together"):
                load_config(repository_config=config_path)
            config_path.write_text(
                '[reports]\nbaseline_path = "previous/findings.json"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "configured together"):
                load_config(repository_config=config_path)

    def test_repository_cannot_replace_approved_intelligence_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.toml"
            config_path = root / "pysec.toml"
            policy_path.write_text(
                f'[intelligence]\nkev_path = "kev.json"\nkev_sha256 = "{"a" * 64}"\n',
                encoding="utf-8",
            )
            config_path.write_text(
                f'[intelligence]\nkev_path = "kev.json"\nkev_sha256 = "{"b" * 64}"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError, "cannot change.*intelligence.kev_sha256"
            ):
                load_config(
                    organization_policy=policy_path,
                    repository_config=config_path,
                )

    def test_executable_digest_must_be_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "pysec.toml"
            config_path.write_text(
                '[tools.bandit]\nexecutable_sha256 = "not-a-digest"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError, "must be exactly 64 hexadecimal"
            ):
                load_config(repository_config=config_path)

    def test_repository_cannot_replace_organization_approved_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.toml"
            config_path = root / "pysec.toml"
            policy_path.write_text(
                f'[tools.bandit]\nexecutable_sha256 = "{"a" * 64}"\n',
                encoding="utf-8",
            )
            config_path.write_text(
                f'[tools.bandit]\nexecutable_sha256 = "{"b" * 64}"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError,
                "cannot change the approved bandit executable_sha256",
            ):
                load_config(
                    organization_policy=policy_path,
                    repository_config=config_path,
                )

    def test_coverage_threshold_is_validated_and_cannot_be_weakened(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.toml"
            config_path = root / "pysec.toml"
            policy_path.write_text(
                "[tools.coverage]\nminimum_coverage_percent = 85\n",
                encoding="utf-8",
            )
            config_path.write_text(
                "[tools.coverage]\nminimum_coverage_percent = 80\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError, "cannot lower.*minimum coverage"
            ):
                load_config(
                    organization_policy=policy_path,
                    repository_config=config_path,
                )

            config_path.write_text(
                '[tools.coverage]\nminimum_coverage_percent = "high"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError, "minimum_coverage_percent must be numeric"
            ):
                load_config(
                    organization_policy=policy_path,
                    repository_config=config_path,
                )


if __name__ == "__main__":
    unittest.main()
