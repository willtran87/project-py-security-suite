from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.adapters.base import ScannerAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.execution import RawExecution
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


if __name__ == "__main__":
    unittest.main()
