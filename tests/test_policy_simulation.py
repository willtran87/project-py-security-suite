from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.policy_simulation import simulate_policy


class PolicySimulationTests(unittest.TestCase):
    @patch("py_security_suite.policy_simulation.verify_report")
    def test_simulation_reports_findings_confidence_and_tool_gaps(
        self, verify_mock
    ) -> None:
        verify_mock.return_value = {
            "scan_id": "scan-1",
            "checksums_sha256": "a" * 64,
            "outcome": "pass",
        }
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write(
                report / "findings.json",
                {
                    "findings": [
                        {
                            "finding_id": "F-1",
                            "status": "new",
                            "severity": "high",
                            "confidence": "low",
                        },
                        {
                            "finding_id": "F-2",
                            "status": "suppressed",
                            "severity": "critical",
                            "confidence": "high",
                        },
                    ]
                },
            )
            _write(
                report / "scan-manifest.json",
                {
                    "tools": [
                        {"tool": "bandit", "applicable": True, "status": "completed"},
                        {
                            "tool": "semgrep",
                            "applicable": True,
                            "status": "unavailable",
                        },
                    ]
                },
            )
            result = simulate_policy(
                report,
                block_severities=("critical", "high"),
                required_tools=("bandit", "semgrep"),
                minimum_confidence="medium",
            )
        self.assertEqual(result["result"]["disposition"], "block")
        self.assertTrue(result["result"]["differs_from_actual"])
        self.assertEqual(result["metrics"]["matching_blocking_findings"], 1)
        self.assertEqual(result["metrics"]["required_tool_gaps"], 1)

    @patch("py_security_suite.policy_simulation.verify_report")
    def test_simulation_can_allow(self, verify_mock) -> None:
        verify_mock.return_value = {
            "scan_id": "scan-1",
            "checksums_sha256": "b" * 64,
            "outcome": "pass",
        }
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write(report / "findings.json", {"findings": []})
            _write(
                report / "scan-manifest.json",
                {
                    "tools": [
                        {"tool": "bandit", "applicable": True, "status": "completed"}
                    ]
                },
            )
            result = simulate_policy(report, required_tools=("bandit",))
        self.assertEqual(result["result"]["disposition"], "allow")


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
