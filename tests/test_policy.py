from __future__ import annotations

import unittest

from py_security_suite.config import load_config
from py_security_suite.models import (
    Confidence,
    Finding,
    Inventory,
    Outcome,
    Severity,
    ToolRun,
    ToolStatus,
)
from py_security_suite.policy import evaluate_policy


def finding(severity: Severity) -> Finding:
    return Finding(
        finding_id="PYSEC-TEST",
        fingerprint="sha256:test",
        title="Test",
        description="Test",
        impact="Test",
        remediation="Test",
        severity=severity,
        confidence=Confidence.HIGH,
        area="test",
    )


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(profile_override="quick")
        self.completed = [
            ToolRun(
                tool=name,
                status=ToolStatus.COMPLETED,
                command=[name],
                duration_seconds=0.1,
            )
            for name in self.config.required_tools
        ]

    def test_missing_attestation_is_incomplete(self) -> None:
        decision = evaluate_policy(
            config=self.config,
            findings=[],
            tool_runs=self.completed,
            network_isolation_attested=False,
        )
        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)

    def test_required_tool_failure_is_incomplete_not_clean(self) -> None:
        self.completed[0].status = ToolStatus.PARSE_ERROR
        decision = evaluate_policy(
            config=self.config,
            findings=[],
            tool_runs=self.completed,
            network_isolation_attested=True,
        )
        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)

    def test_non_applicable_required_tool_does_not_make_scan_incomplete(self) -> None:
        config = load_config(profile_override="quick")
        runs = [
            ToolRun(
                tool="bandit",
                status=ToolStatus.COMPLETED,
                command=["bandit"],
                duration_seconds=0.1,
            ),
            ToolRun(
                tool="detect-secrets",
                status=ToolStatus.SKIPPED,
                command=["detect-secrets"],
                duration_seconds=0.0,
                applicable=False,
                error="no applicable files",
            ),
        ]
        decision = evaluate_policy(
            config=config,
            findings=[],
            tool_runs=runs,
            network_isolation_attested=True,
        )
        self.assertEqual(decision.outcome, Outcome.PASS)

    def test_high_finding_fails(self) -> None:
        item = finding(Severity.HIGH)
        decision = evaluate_policy(
            config=self.config,
            findings=[item],
            tool_runs=self.completed,
            network_isolation_attested=True,
        )
        self.assertEqual(decision.outcome, Outcome.FAIL)
        self.assertTrue(item.blocking)

    def test_medium_finding_warns(self) -> None:
        decision = evaluate_policy(
            config=self.config,
            findings=[finding(Severity.MEDIUM)],
            tool_runs=self.completed,
            network_isolation_attested=True,
        )
        self.assertEqual(decision.outcome, Outcome.WARN)

    def test_production_gate_requires_history_lock_and_deep_dataflow(self) -> None:
        config = load_config(profile_override="production")
        runs = [
            ToolRun(
                tool=name,
                status=ToolStatus.COMPLETED,
                command=[name],
                duration_seconds=0.1,
            )
            for name in config.required_tools
        ]
        pysa = next(run for run in runs if run.tool == "pysa")
        pysa.status = ToolStatus.SKIPPED
        pysa.applicable = False
        cyclonedx = next(run for run in runs if run.tool == "cyclonedx-py")
        cyclonedx.status = ToolStatus.SKIPPED
        cyclonedx.applicable = False
        guarddog = next(run for run in runs if run.tool == "guarddog")
        guarddog.status = ToolStatus.SKIPPED
        guarddog.applicable = False
        decision = evaluate_policy(
            config=config,
            findings=[],
            tool_runs=runs,
            network_isolation_attested=True,
            inventory=Inventory(
                python_files=1,
                dependency_files=["pyproject.toml"],
                total_files=2,
                skipped_symlinks=0,
                declared_dependencies=True,
                lock_files=[],
                vcs_history_available=False,
            ),
        )
        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)
        reasons = " ".join(decision.reasons)
        self.assertIn("full VCS checkout", reasons)
        self.assertIn("lock file", reasons)
        self.assertIn("Pysa was not applicable", reasons)
        self.assertIn("cyclonedx-py", reasons)
        self.assertIn("guarddog", reasons)

    def test_production_gate_blocks_medium_findings(self) -> None:
        config = load_config(profile_override="production")
        runs = [
            ToolRun(
                tool=name,
                status=ToolStatus.COMPLETED,
                command=[name],
                duration_seconds=0.1,
            )
            for name in config.required_tools
        ]
        decision = evaluate_policy(
            config=config,
            findings=[finding(Severity.MEDIUM)],
            tool_runs=runs,
            network_isolation_attested=True,
            inventory=Inventory(
                python_files=1,
                dependency_files=[],
                total_files=1,
                skipped_symlinks=0,
                vcs_history_available=True,
            ),
        )
        self.assertEqual(decision.outcome, Outcome.FAIL)


if __name__ == "__main__":
    unittest.main()
