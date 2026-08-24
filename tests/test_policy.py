from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from py_security_suite.config import SuiteConfig, load_config
from py_security_suite.models import (
    Confidence,
    Finding,
    FindingStatus,
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


def production_runs(suite: SuiteConfig) -> list[ToolRun]:
    runs: list[ToolRun] = []
    for name in suite.required_tools:
        suite.tools[name].executable_sha256 = "a" * 64
        suite.tools[name].executable_organization_approved = True
        if suite.tools[name].require_assurance_profile:
            suite.tools[name].assurance_profile_path = Path("profile-v2.json")
            suite.tools[name].assurance_profile_sha256 = "c" * 64
        runs.append(
            ToolRun(
                tool=name,
                status=ToolStatus.COMPLETED,
                command=[name],
                duration_seconds=0.1,
                version="1.0.0",
                executable_sha256="a" * 64,
                executable_integrity_verified=True,
                executable_organization_approved=True,
                executable_unchanged=True,
            )
        )
    suite.tools["codeql"].auxiliary_executable_sha256 = "b" * 64
    suite.tools["codeql"].auxiliary_executable_organization_approved = True
    codeql = next(run for run in runs if run.tool == "codeql")
    codeql.auxiliary_executable_sha256 = "b" * 64
    codeql.auxiliary_executable_integrity_verified = True
    codeql.auxiliary_executable_organization_approved = True
    codeql.auxiliary_executable_unchanged = True
    return runs


def _unknown_version_run(runs: list[ToolRun]) -> ToolRun:
    run = runs[0]
    run.version = "unknown"
    return run


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
        item = finding(Severity.HIGH)
        decision = evaluate_policy(
            config=self.config,
            findings=[item],
            tool_runs=self.completed,
            network_isolation_attested=False,
        )
        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)
        self.assertTrue(item.blocking)

    def test_production_gate_requires_known_scanner_versions(self) -> None:
        config = load_config(profile_override="production")
        runs = production_runs(config)
        unknown = _unknown_version_run(runs)
        decision = evaluate_policy(
            config=config,
            findings=[],
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
        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)
        self.assertTrue(
            any(
                unknown.tool in reason and "version" in reason
                for reason in decision.reasons
            )
        )

    def test_release_provenance_is_blocking_even_when_severity_policy_is_weak(
        self,
    ) -> None:
        item = finding(Severity.LOW)
        item.area = "artifact-provenance"
        self.config.profile = "release"
        self.config.policy.block_severities = (Severity.CRITICAL,)

        decision = evaluate_policy(
            config=self.config,
            findings=[item],
            tool_runs=self.completed,
            network_isolation_attested=False,
        )

        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)
        self.assertTrue(item.blocking)

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

    def test_known_exploited_finding_blocks_regardless_of_native_severity(self) -> None:
        item = finding(Severity.LOW)
        item.evidence["risk_intelligence"] = {
            "known_exploited": [{"cve": "CVE-2026-12345"}]
        }
        decision = evaluate_policy(
            config=self.config,
            findings=[item],
            tool_runs=self.completed,
            network_isolation_attested=True,
        )
        self.assertEqual(decision.outcome, Outcome.FAIL)
        self.assertTrue(item.blocking)
        self.assertIn("known-exploited findings 1", decision.reasons[0])
        self.assertTrue(item.blocking)

    def test_medium_finding_warns(self) -> None:
        decision = evaluate_policy(
            config=self.config,
            findings=[finding(Severity.MEDIUM)],
            tool_runs=self.completed,
            network_isolation_attested=True,
        )
        self.assertEqual(decision.outcome, Outcome.WARN)

    def test_governed_risk_acceptance_suppresses_exact_finding(self) -> None:
        item = finding(Severity.HIGH)
        item.fingerprint = "sha256:" + "a" * 64
        expires = (date.today() + timedelta(days=30)).isoformat()
        document = {
            "schema_version": "1.0",
            "acceptances": [
                {
                    "fingerprint": item.fingerprint,
                    "finding_id": item.finding_id,
                    "disposition": "accepted_risk",
                    "owner": "security@example.invalid",
                    "rationale": "Time-bounded fixture acceptance.",
                    "expires": expires,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "acceptances.json"
            data = json.dumps(document).encode("utf-8")
            ledger.write_bytes(data)
            self.config.policy.risk_acceptance_path = ledger
            self.config.policy.risk_acceptance_sha256 = hashlib.sha256(data).hexdigest()
            decision = evaluate_policy(
                config=self.config,
                findings=[item],
                tool_runs=self.completed,
                network_isolation_attested=True,
            )

        self.assertEqual(decision.outcome, Outcome.PASS)
        self.assertEqual(item.status, FindingStatus.SUPPRESSED)
        self.assertFalse(item.blocking)
        self.assertIn("governed acceptance", decision.reasons[0])

    def test_expired_or_stale_risk_acceptance_is_incomplete(self) -> None:
        item = finding(Severity.MEDIUM)
        item.fingerprint = "sha256:" + "b" * 64
        document = {
            "schema_version": "1.0",
            "acceptances": [
                {
                    "fingerprint": "sha256:" + "c" * 64,
                    "disposition": "false_positive",
                    "owner": "security@example.invalid",
                    "rationale": "Stale fixture acceptance.",
                    "expires": (date.today() + timedelta(days=30)).isoformat(),
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "acceptances.json"
            ledger.write_text(json.dumps(document), encoding="utf-8")
            self.config.policy.risk_acceptance_path = ledger
            decision = evaluate_policy(
                config=self.config,
                findings=[item],
                tool_runs=self.completed,
                network_isolation_attested=True,
            )

        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)
        self.assertIn("does not match a current finding", " ".join(decision.reasons))

    def test_production_gate_requires_history_lock_and_deep_dataflow(self) -> None:
        config = load_config(profile_override="production")
        runs = production_runs(config)
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

    def test_production_gate_rejects_repository_only_scanner_pin(self) -> None:
        config = load_config(profile_override="production")
        runs = production_runs(config)
        config.tools["bandit"].executable_organization_approved = False
        bandit = next(run for run in runs if run.tool == "bandit")
        bandit.executable_organization_approved = False

        decision = evaluate_policy(
            config=config,
            findings=[],
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

        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)
        self.assertIn(
            "organization-approved executable_sha256 for bandit",
            " ".join(decision.reasons),
        )

    def test_production_gate_requires_dynamic_and_governance_evidence(self) -> None:
        config = load_config(profile_override="production")
        runs = production_runs(config)
        for tool in ("crosshair", "atheris", "mutmut", "pytm", "scorecard"):
            run = next(item for item in runs if item.tool == tool)
            run.status = ToolStatus.SKIPPED
            run.applicable = False
        decision = evaluate_policy(
            config=config,
            findings=[],
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
        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)
        reasons = " ".join(decision.reasons)
        self.assertIn("crosshair evidence", reasons)
        self.assertIn("atheris evidence", reasons)
        self.assertIn("mutmut evidence", reasons)
        self.assertIn("pytm evidence", reasons)
        self.assertIn("scorecard evidence", reasons)

    def test_production_gate_blocks_medium_findings(self) -> None:
        config = load_config(profile_override="production")
        runs = production_runs(config)
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

    def test_production_gate_requires_only_applicable_runtime_evidence(self) -> None:
        config = load_config(profile_override="production")
        runs = production_runs(config)
        iast = next(run for run in runs if run.tool == "iast")
        iast.status = ToolStatus.FAILED
        falco = next(run for run in runs if run.tool == "falco")
        falco.status = ToolStatus.SKIPPED
        falco.applicable = False

        decision = evaluate_policy(
            config=config,
            findings=[],
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

        reasons = " ".join(decision.reasons)
        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)
        self.assertIn("iast evidence for this repository shape", reasons)
        self.assertNotIn("falco evidence", reasons)


if __name__ == "__main__":
    unittest.main()
