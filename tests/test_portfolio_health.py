from __future__ import annotations

import json
import unittest

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import (  # pylint: disable=import-error
    Draft202012Validator,
    ValidationError,
)

from py_security_suite.models import (
    Confidence,
    Finding,
    Outcome,
    Severity,
    Source,
    ToolRun,
    ToolStatus,
)
from py_security_suite.portfolio_health import (
    activation_recipe,
    portfolio_health_artifact,
)
from py_security_suite.report_inspection import read_bundled_schema


class PortfolioHealthTests(unittest.TestCase):
    def test_grades_applicable_completion_without_treating_na_as_failure(self) -> None:
        runs = [
            ToolRun("bandit", ToolStatus.COMPLETED, [], 0.1),
            ToolRun("semgrep", ToolStatus.UNAVAILABLE, [], 0.0),
            ToolRun(
                "flawfinder",
                ToolStatus.SKIPPED,
                [],
                0.0,
                applicable=False,
            ),
        ]

        artifact = portfolio_health_artifact([], runs)
        source = next(
            row
            for row in artifact["domains"]
            if row["domain"] == "python-source-security"
        )

        self.assertEqual(source["execution_grade"], "C")
        self.assertEqual(source["risk_grade"], "A")
        self.assertEqual(source["execution_gaps"], ["semgrep"])
        self.assertEqual(source["applicable_tools"], 2)
        self.assertEqual(source["selected_tools"], 3)

    def test_unselected_domains_are_explicit_and_not_graded(self) -> None:
        artifact = portfolio_health_artifact(
            [], [ToolRun("bandit", ToolStatus.COMPLETED, [], 0.1)]
        )
        dynamic = next(
            row
            for row in artifact["domains"]
            if row["domain"] == "dynamic-threat-modeling"
        )
        self.assertEqual(dynamic["status"], "not_selected")
        self.assertEqual(dynamic["execution_grade"], "N/A")
        schema = json.loads(read_bundled_schema("portfolio-health-1.1"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(artifact)
        artifact["overall"]["unexpected"] = True
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(artifact)

    def test_separates_execution_risk_evidence_and_release_decision(self) -> None:
        finding = Finding(
            finding_id="PYSEC-HIGH",
            fingerprint="sha256:high",
            title="Unsigned artifact",
            description="Fixture",
            impact="Publisher identity is absent.",
            remediation="Attach signature evidence.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            domain="supply-chain",
            area="artifact-provenance",
            sources=[Source(tool="cosign", rule_id="missing", message="missing")],
        )
        runs = [
            ToolRun(
                "cosign",
                ToolStatus.COMPLETED,
                [],
                0.1,
                executable_sha256="a" * 64,
                executable_unchanged=True,
            ),
            ToolRun(
                "guarddog",
                ToolStatus.SKIPPED,
                [],
                0.0,
                applicable=False,
                error="GuardDog does not support native Windows execution",
            ),
        ]
        artifact = portfolio_health_artifact(
            [finding],
            runs,
            outcome=Outcome.INCOMPLETE,
            policy_reasons=["network-isolation attestation was not provided"],
        )
        overall = artifact["overall"]
        self.assertEqual(overall["execution_grade"], "A")
        self.assertEqual(overall["risk_grade"], "D")
        self.assertEqual(overall["evidence_grade"], "F")
        self.assertEqual(overall["release_decision"], "blocked")
        self.assertEqual(
            artifact["activation_recipes"][0]["owner"], "platform-security"
        )
        self.assertNotIn("grade", overall)

    def test_evidence_gaps_are_unique_and_schema_bounded(self) -> None:
        artifact = portfolio_health_artifact(
            [],
            [],
            outcome=Outcome.INCOMPLETE,
            policy_reasons=["same gap"] * 300
            + [f"gap {index}" for index in range(300)],
        )

        gaps = artifact["overall"]["evidence_gaps"]
        self.assertEqual(len(gaps), 256)
        self.assertEqual(gaps[0], "same gap")
        self.assertEqual(len(gaps), len(set(gaps)))
        schema = json.loads(read_bundled_schema("portfolio-health-1.1"))
        Draft202012Validator(schema).validate(artifact)

    def test_activation_recipes_cover_each_operator_path(self) -> None:
        cases = {
            "A Trusted Publisher identity is not configured": (
                "release_configuration",
                "release-engineering",
            ),
            "No approved target Python environment is available": (
                "target_environment",
                "python-platform",
            ),
            "No OpenAPI schema or pre-generated Schemathesis evidence": (
                "companion_evidence",
                "application-security",
            ),
            "No pre-generated DAST result was supplied": (
                "companion_evidence",
                "application-security",
            ),
            "No approved local policy is configured": (
                "missing_configuration",
                "security-policy",
            ),
            "No repository Pysa/Pyre configuration was found": (
                "missing_configuration",
                "security-policy",
            ),
            "Run this profile on Linux": (
                "platform_constraint",
                "platform-security",
            ),
            "No supported files were found": (
                "content_absent",
                "repository-maintainers",
            ),
        }
        for reason, expected in cases.items():
            with self.subTest(reason=reason):
                recipe = activation_recipe(
                    ToolRun(
                        "fixture",
                        ToolStatus.SKIPPED,
                        [],
                        0.0,
                        applicable=False,
                        error=reason,
                    )
                )
                self.assertEqual((recipe["category"], recipe["owner"]), expected)
                self.assertTrue(recipe["required_action"])
                self.assertTrue(recipe["evidence_required"])

    def test_all_risk_bands_and_release_states_are_explicit(self) -> None:
        expectations = {
            Severity.CRITICAL: ("F", "critical"),
            Severity.HIGH: ("D", "high"),
            Severity.MEDIUM: ("C", "moderate"),
            Severity.UNKNOWN: ("C", "moderate"),
            Severity.LOW: ("B", "low"),
            Severity.INFORMATIONAL: ("A", "minimal"),
        }
        for severity, expected in expectations.items():
            with self.subTest(severity=severity.value):
                finding = Finding(
                    finding_id=f"PYSEC-{severity.value}",
                    fingerprint=f"sha256:{severity.value}",
                    title="Fixture",
                    description="Fixture",
                    impact="Fixture impact",
                    remediation="Fixture action",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    domain="security",
                    area="source",
                    sources=[Source(tool="bandit", rule_id="fixture", message="x")],
                )
                overall = portfolio_health_artifact(
                    [finding], [ToolRun("bandit", ToolStatus.COMPLETED, [], 0.0)]
                )["overall"]
                self.assertEqual(
                    (overall["risk_grade"], overall["risk_status"]), expected
                )

        completed = [ToolRun("bandit", ToolStatus.COMPLETED, [], 0.0)]
        self.assertEqual(
            portfolio_health_artifact([], completed, outcome=Outcome.WARN)["overall"][
                "release_decision"
            ],
            "review_required",
        )
        self.assertEqual(
            portfolio_health_artifact([], completed, outcome=Outcome.PASS)["overall"][
                "release_decision"
            ],
            "eligible_for_external_approval",
        )

    def test_changed_entry_point_is_an_incomplete_evidence_gap(self) -> None:
        run = ToolRun(
            "bandit",
            ToolStatus.COMPLETED,
            [],
            0.0,
            executable_sha256="a" * 64,
            executable_unchanged=False,
        )
        overall = portfolio_health_artifact([], [run], outcome=Outcome.PASS)["overall"]
        self.assertEqual(overall["evidence_grade"], "F")
        self.assertIn("scanner entry points changed: bandit", overall["evidence_gaps"])
