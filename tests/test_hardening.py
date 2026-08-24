from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.adapters.base import ScannerAdapter
from py_security_suite.config import ToolConfig, load_config
from py_security_suite.execution import RawExecution, governed_asset_sha256
from py_security_suite.models import Finding, ToolStatus


class IntegrityAdapter(ScannerAdapter):
    name = "integrity-test"

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [executable, "scan"]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        return []


def execution(command: list[str]) -> RawExecution:
    return RawExecution(
        command=command,
        exit_code=0,
        stdout="scanner 1.0",
        stderr="",
        duration_seconds=0.01,
    )


class ExecutableIntegrityTests(unittest.TestCase):
    def test_governed_asset_tree_is_exact_and_symlink_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rules = root / "rules"
            rules.mkdir()
            rule = rules / "command.yml"
            rule.write_text("id: command\n", encoding="utf-8")
            first = governed_asset_sha256(rules)
            rule.write_text("id: command-v2\n", encoding="utf-8")
            self.assertNotEqual(first, governed_asset_sha256(rules))
            try:
                (rules / "alias.yml").symlink_to(rule)
            except OSError:
                self.skipTest("symbolic-link creation is unavailable")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                governed_asset_sha256(rules)

    def test_production_asset_digest_and_authority_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rules = root / "rules.yml"
            rules.write_text("rules: []\n", encoding="utf-8")
            adapter = IntegrityAdapter(
                ToolConfig(
                    rules_path=rules,
                    require_asset_digests=True,
                    rules_sha256=governed_asset_sha256(rules),
                ),
                1024,
            )
            self.assertIn(
                "organization approval",
                adapter._prepare_assets() or "",  # noqa: SLF001
            )

    def test_deployment_trust_environment_is_frozen_and_forwarded(self) -> None:
        with patch.dict(
            os.environ,
            {"PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": "a" * 64},
            clear=False,
        ):
            config = load_config(profile_override="quick")
        adapter = IntegrityAdapter(config.tools["bandit"], 1024)
        environment = adapter.execution_environment()
        self.assertEqual(
            environment.extra["PYSEC_TRUSTED_AUTHORITY_KEY_SHA256"], "a" * 64
        )
        self.assertEqual(
            environment.extra["PYSEC_TRUST_POLICY_SHA256"],
            config.trust_policy_sha256,
        )

    def test_approved_digest_mismatch_prevents_execution(self) -> None:
        config = ToolConfig(
            executable="scanner",
            executable_sha256="a" * 64,
        )
        adapter = IntegrityAdapter(config, 1024)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "py_security_suite.adapters.base.resolve_executable",
                return_value=str(Path(directory) / "scanner"),
            ),
            patch(
                "py_security_suite.adapters.base.sha256_file",
                return_value="b" * 64,
            ),
            patch("py_security_suite.adapters.base.run_command") as mocked_run,
        ):
            result = adapter.run(Path(directory))

        self.assertEqual(result.tool_run.status, ToolStatus.UNAVAILABLE)
        self.assertIn("does not match", result.tool_run.error or "")
        self.assertEqual(result.tool_run.executable_sha256, "b" * 64)
        self.assertFalse(result.tool_run.executable_integrity_verified)
        mocked_run.assert_not_called()

    def test_entry_point_change_during_scan_fails_closed(self) -> None:
        digest = "a" * 64
        config = ToolConfig(executable="scanner", executable_sha256=digest)
        adapter = IntegrityAdapter(config, 1024)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "py_security_suite.adapters.base.resolve_executable",
                return_value=str(Path(directory) / "scanner"),
            ),
            patch(
                "py_security_suite.adapters.base.sha256_file",
                side_effect=[digest, "b" * 64],
            ),
            patch(
                "py_security_suite.adapters.base.run_command",
                side_effect=lambda command, **_: execution(command),
            ),
        ):
            result = adapter.run(Path(directory))

        self.assertEqual(result.tool_run.status, ToolStatus.FAILED)
        self.assertIn("changed during execution", result.tool_run.error or "")
        self.assertTrue(result.tool_run.executable_integrity_verified)
        self.assertFalse(result.tool_run.executable_unchanged)

    def test_approved_entry_point_is_recorded_after_execution(self) -> None:
        digest = "a" * 64
        config = ToolConfig(executable="scanner", executable_sha256=digest)
        adapter = IntegrityAdapter(config, 1024)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "py_security_suite.adapters.base.resolve_executable",
                return_value=str(Path(directory) / "scanner"),
            ),
            patch(
                "py_security_suite.adapters.base.sha256_file",
                return_value=digest,
            ),
            patch(
                "py_security_suite.adapters.base.run_command",
                side_effect=lambda command, **_: execution(command),
            ),
        ):
            result = adapter.run(Path(directory))

        self.assertEqual(result.tool_run.status, ToolStatus.COMPLETED)
        self.assertTrue(result.tool_run.executable_integrity_verified)
        self.assertTrue(result.tool_run.executable_unchanged)
        self.assertEqual(result.diagnostic["executable_sha256"], digest)

    def test_python_runtime_closure_mismatch_prevents_execution(self) -> None:
        config = ToolConfig(
            executable="scanner",
            executable_sha256="a" * 64,
            runtime_closure_sha256="b" * 64,
        )
        adapter = IntegrityAdapter(config, 1024)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "py_security_suite.adapters.base.resolve_executable",
                return_value=str(Path(directory) / "scanner"),
            ),
            patch("py_security_suite.adapters.base.sha256_file", return_value="a" * 64),
            patch(
                "py_security_suite.adapters.base.python_runtime_closure_sha256",
                return_value="c" * 64,
            ),
            patch("py_security_suite.adapters.base.run_command") as mocked_run,
        ):
            result = adapter.run(Path(directory))

        self.assertEqual(result.tool_run.status, ToolStatus.UNAVAILABLE)
        self.assertIn("runtime closure", result.tool_run.error or "")
        mocked_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
