from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.config import ConfigurationError, load_config


class ConfigTests(unittest.TestCase):
    def test_missing_or_linked_configuration_is_rejected_as_non_regular(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.toml"
            with self.assertRaisesRegex(ConfigurationError, "not a regular file"):
                load_config(repository_config=missing)

    def test_defaults_select_standard_offline_profile(self) -> None:
        config = load_config()
        self.assertEqual(config.profile, "standard")
        self.assertEqual(config.isolation.network, "deny")
        self.assertFalse(config.isolation.execute_target_code)
        self.assertEqual(
            config.required_tools,
            ("bandit", "semgrep", "detect-secrets", "osv-scanner"),
        )

    def test_production_organization_policy_requires_deployment_digest_pin(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "organization.toml"
            payload = b'profile = "production"\n'
            policy.write_bytes(payload)
            with self.assertRaisesRegex(
                ConfigurationError, "PYSEC_ORGANIZATION_POLICY_SHA256"
            ):
                load_config(organization_policy=policy)
            with patch.dict(
                os.environ,
                {
                    "PYSEC_ORGANIZATION_POLICY_SHA256": hashlib.sha256(
                        payload
                    ).hexdigest()
                },
            ):
                config = load_config(organization_policy=policy)
        self.assertEqual(config.profile, "production")

    def test_quick_profile_override_changes_derived_required_tools(self) -> None:
        config = load_config(profile_override="quick")
        self.assertEqual(config.required_tools, ("bandit", "detect-secrets"))

    def test_comprehensive_profile_selects_every_implemented_tool(self) -> None:
        config = load_config(profile_override="comprehensive")
        self.assertEqual(len(config.selected_tools), 88)
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
        self.assertIn("clusterfuzzlite", config.selected_tools)
        self.assertIn("github-attestation", config.selected_tools)
        self.assertIn("hypothesis", config.selected_tools)
        self.assertIn("schemathesis", config.selected_tools)
        self.assertIn("zap", config.selected_tools)
        self.assertIn("browser-security", config.selected_tools)
        self.assertIn("iast", config.selected_tools)
        self.assertIn("falco", config.selected_tools)
        self.assertIn("kubescape", config.selected_tools)
        self.assertIn("pytm", config.selected_tools)
        self.assertIn("in-toto", config.selected_tools)
        self.assertIn("reproducible-build", config.selected_tools)
        self.assertIn("yara", config.selected_tools)
        self.assertIn("reachability", config.selected_tools)
        self.assertIn("graphify", config.selected_tools)

    def test_production_profile_blocks_medium_and_selects_full_suite(self) -> None:
        config = load_config(profile_override="production")
        self.assertEqual(config.required_tools, config.selected_tools)
        self.assertEqual(len(config.selected_tools), 75)
        self.assertIn(
            "medium", {severity.value for severity in config.policy.block_severities}
        )
        self.assertIn("hadolint", config.selected_tools)
        self.assertIn("devskim", config.selected_tools)
        self.assertTrue(config.isolation.require_evidence)
        self.assertTrue(config.intelligence.require_approval)

    def test_release_profile_adds_artifact_assurance(self) -> None:
        config = load_config(profile_override="release")
        self.assertEqual(len(config.selected_tools), 88)
        self.assertIn("grype", config.required_tools)
        self.assertIn("check-wheel-contents", config.required_tools)
        self.assertIn("cosign", config.required_tools)

    def test_quality_and_repo_profiles_expose_distinct_coverage(self) -> None:
        quality = load_config(profile_override="quality")
        repo = load_config(profile_override="repo")
        self.assertEqual(len(quality.selected_tools), 26)
        self.assertEqual(len(repo.selected_tools), 78)
        self.assertIn("ruff-quality", quality.selected_tools)
        self.assertIn("mypy", repo.selected_tools)
        self.assertIn("tach", quality.selected_tools)
        self.assertIn("ruff-format", quality.selected_tools)
        self.assertIn("junit", quality.selected_tools)
        self.assertIn("diff-cover", quality.selected_tools)
        self.assertIn("reachability", quality.selected_tools)
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
                '[isolation]\nevidence_path = "security/isolation.json"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "configured together"):
                load_config(repository_config=config_path)

            config_path.write_text(
                '[intelligence]\napproval_path = "security/approval.json"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "configured together"):
                load_config(repository_config=config_path)

    def test_trust_catalog_requires_digest_and_cannot_be_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.toml"
            config_path = root / "pysec.toml"
            policy_path.write_text(
                f'[trust]\ncatalog_path = "trust.json"\ncatalog_sha256 = "{"a" * 64}"\n',
                encoding="utf-8",
            )
            config_path.write_text(
                f'[trust]\ncatalog_path = "trust.json"\ncatalog_sha256 = "{"b" * 64}"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError, "cannot change.*trust.catalog_sha256"
            ):
                load_config(
                    organization_policy=policy_path,
                    repository_config=config_path,
                )

            config_path.write_text(
                '[trust]\ncatalog_path = "trust.json"\n', encoding="utf-8"
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

    def test_governance_authority_requires_organization_policy_origin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository.toml"
            organization = root / "organization.toml"
            settings = (
                f'[isolation]\nevidence_path = "isolation.json"\n'
                f'evidence_sha256 = "{"a" * 64}"\n'
                f'evidence_public_key_path = "governance.pem"\n'
                f'evidence_public_key_sha256 = "{"c" * 64}"\n'
                f'evidence_signature_path = "isolation.sig"\n'
                f'[intelligence]\napproval_path = "approval.json"\n'
                f'approval_sha256 = "{"b" * 64}"\n'
                f'approval_public_key_path = "governance.pem"\n'
                f'approval_public_key_sha256 = "{"c" * 64}"\n'
                f'approval_signature_path = "approval.sig"\n'
            )
            repository.write_text(settings, encoding="utf-8")
            organization.write_text(settings, encoding="utf-8")

            repository_only = load_config(repository_config=repository)
            governed = load_config(organization_policy=organization)

        self.assertFalse(repository_only.isolation.evidence_organization_approved)
        self.assertFalse(repository_only.intelligence.approval_organization_approved)
        self.assertTrue(governed.isolation.evidence_organization_approved)
        self.assertTrue(governed.intelligence.approval_organization_approved)

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

    def test_companion_evidence_trust_defaults_and_policy_cannot_be_weakened(
        self,
    ) -> None:
        runtime = load_config(profile_override="runtime")
        for name in (
            "zap",
            "nuclei",
            "iast",
            "prowler",
            "native-sanitizers",
            "mobsf",
            "tls-scan",
            "polyglot",
            "oast",
            "restler",
            "protocol-security",
            "fuzz-introspector",
            "cloud-attack-path",
            "secret-verification",
        ):
            with self.subTest(tool=name):
                self.assertTrue(runtime.tools[name].require_evidence_contract_v2)
                self.assertTrue(runtime.tools[name].require_signed_evidence)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.toml"
            config_path = root / "pysec.toml"
            policy_path.write_text(
                "[tools.nuclei]\n"
                "maximum_evidence_age_days = 2\n"
                "require_evidence_contract_v2 = true\n"
                "require_signed_evidence = true\n"
                'public_key_path = "trusted.pub"\n'
                f'public_key_sha256 = "{"a" * 64}"\n'
                'expected_run_id = "orchestrator-42"\n'
                f'expected_environment_sha256 = "{"c" * 64}"\n'
                'replay_ledger_path = "security-data/replay.sqlite3"\n',
                encoding="utf-8",
            )
            cases = (
                ("maximum_evidence_age_days = 3\n", "maximum evidence age"),
                ("require_evidence_contract_v2 = false\n", "cannot disable"),
                ("require_signed_evidence = false\n", "cannot disable"),
                (f'public_key_sha256 = "{"b" * 64}"\n', "public_key_sha256"),
                ('expected_run_id = "other-run"\n', "expected_run_id"),
                (
                    f'expected_environment_sha256 = "{"d" * 64}"\n',
                    "expected_environment_sha256",
                ),
                (
                    'replay_ledger_path = "elsewhere/replay.sqlite3"\n',
                    "replay_ledger_path",
                ),
            )
            for settings, message in cases:
                with self.subTest(message=message):
                    config_path.write_text(
                        "[tools.nuclei]\n" + settings,
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ConfigurationError, message):
                        load_config(
                            organization_policy=policy_path,
                            repository_config=config_path,
                        )

    def test_reachability_scope_and_threshold_are_governed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.toml"
            config_path = root / "pysec.toml"
            policy_path.write_text(
                "[tools.reachability]\n"
                "minimum_island_loc = 100\n"
                'entry_points = ["acme.plugins:load"]\n'
                'source_roots = ["src"]\n'
                'coverage_path = ".artifacts/coverage.json"\n'
                "discover_framework_roots = true\n",
                encoding="utf-8",
            )
            config_path.write_text(
                "[tools.reachability]\n"
                "minimum_island_loc = 200\n"
                "entry_points = []\n"
                "source_roots = []\n"
                "discover_framework_roots = false\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError, "cannot raise.*minimum_island_loc"
            ):
                load_config(
                    organization_policy=policy_path,
                    repository_config=config_path,
                )

            config_path.write_text(
                "[tools.reachability]\n"
                "minimum_island_loc = 50\n"
                'entry_points = ["acme.plugins:load", "acme.cli:main"]\n'
                'source_roots = ["src"]\n'
                "discover_framework_roots = true\n",
                encoding="utf-8",
            )
            config = load_config(
                organization_policy=policy_path,
                repository_config=config_path,
            )
            reachability = config.tools["reachability"]
            self.assertEqual(reachability.minimum_island_loc, 50)
            self.assertEqual(
                reachability.entry_points,
                ("acme.plugins:load", "acme.cli:main"),
            )
            self.assertEqual(reachability.source_roots, ("src",))
            self.assertEqual(
                reachability.coverage_path, Path(".artifacts/coverage.json")
            )

    def test_reachability_rejects_weaker_scope_and_invalid_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.toml"
            config_path = root / "pysec.toml"
            policy_path.write_text(
                "[tools.reachability]\n"
                "minimum_island_loc = 100\n"
                'entry_points = ["acme.plugins:load"]\n'
                'source_roots = ["src"]\n'
                'coverage_path = "approved-coverage.json"\n'
                "discover_framework_roots = true\n",
                encoding="utf-8",
            )
            cases = (
                (
                    "minimum_island_loc = 'large'\n",
                    "minimum_island_loc must be an integer",
                ),
                (
                    "minimum_island_loc = 50\nentry_points = []\n",
                    "must include every organization-required root",
                ),
                (
                    "minimum_island_loc = 50\n"
                    'entry_points = ["acme.plugins:load"]\n'
                    "source_roots = []\n",
                    "must include every organization-required source root",
                ),
                (
                    "minimum_island_loc = 50\n"
                    'entry_points = ["acme.plugins:load"]\n'
                    'source_roots = ["src"]\n'
                    "discover_framework_roots = false\n",
                    "cannot disable framework root discovery",
                ),
                (
                    "minimum_island_loc = 50\n"
                    'entry_points = ["acme.plugins:load"]\n'
                    'source_roots = ["src"]\n'
                    'coverage_path = "replacement.json"\n'
                    "discover_framework_roots = true\n",
                    "cannot replace.*coverage_path",
                ),
            )
            for settings, message in cases:
                with self.subTest(message=message):
                    config_path.write_text(
                        "[tools.reachability]\n" + settings,
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ConfigurationError, message):
                        load_config(
                            organization_policy=policy_path,
                            repository_config=config_path,
                        )

            invalid_repository_values = (
                ("entry_points = 'not-an-array'\n", "must be arrays"),
                ("discover_framework_roots = 'yes'\n", "must be true or false"),
                ("minimum_island_loc = 0\n", "must be between"),
                ('entry_points = [""]\n', "contains invalid values"),
            )
            for settings, message in invalid_repository_values:
                with self.subTest(message=message):
                    config_path.write_text(
                        "[tools.reachability]\n" + settings,
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ConfigurationError, message):
                        load_config(organization_policy=config_path)

    def test_executable_authority_origin_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            organization = root / "organization.toml"
            repository = root / "pysec.toml"
            organization.write_text(
                "[tools.bandit]\nexecutable_sha256 = '" + "a" * 64 + "'\n",
                encoding="utf-8",
            )
            repository.write_text(
                "[tools.semgrep]\nexecutable_sha256 = '" + "b" * 64 + "'\n",
                encoding="utf-8",
            )

            config = load_config(
                organization_policy=organization,
                repository_config=repository,
                profile_override="quick",
            )

        self.assertTrue(config.tools["bandit"].executable_organization_approved)
        self.assertFalse(config.tools["semgrep"].executable_organization_approved)

    def test_portable_bundle_root_is_configurable_and_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "pysec.toml"
            config_path.write_text(
                '[paths]\nbundle_root = "vendor/security-tools"\n'
                '[tools.bandit]\nexecutable = "@bundle/bin/bandit"\n',
                encoding="utf-8",
            )
            config = load_config(
                repository_config=config_path,
                profile_override="quick",
            )
            self.assertEqual(config.paths.bundle_root, Path("vendor/security-tools"))
            self.assertEqual(config.tools["bandit"].executable, "@bundle/bin/bandit")

            config_path.write_text('[paths]\nbundle_root = ""\n', encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "cannot be empty"):
                load_config(repository_config=config_path)

            config_path.write_text(
                '[paths]\nbundle_root = "@bundle/nested"\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(ConfigurationError, "cannot reference"):
                load_config(repository_config=config_path)


if __name__ == "__main__":
    unittest.main()
