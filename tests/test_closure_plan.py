from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.closure_plan import (
    build_closure_plan,
    render_closure_plan_markdown,
)
from py_security_suite.report_inspection import read_bundled_schema


class ClosurePlanTests(unittest.TestCase):
    @patch("py_security_suite.closure_plan.verify_report")
    def test_builds_stable_owned_backlog_from_verified_evidence(
        self, verify_mock
    ) -> None:
        verify_mock.return_value = {
            "scan_id": "scan-1",
            "outcome": "incomplete",
            "checksums_sha256": "f" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_report(report)
            first = build_closure_plan(report, coverage_target=90.0)
            second = build_closure_plan(report, coverage_target=90.0)

        self.assertEqual(first, second)
        self.assertFalse(first["authoritative"])
        self.assertGreaterEqual(first["summary"]["open_items"], 6)
        categories = {item["category"] for item in first["items"]}
        self.assertTrue(
            {
                "finding",
                "governance",
                "conditional-control",
                "test-assurance",
                "architecture",
            }.issubset(categories)
        )
        finding = next(item for item in first["items"] if item["category"] == "finding")
        self.assertEqual(finding["authority"], "external")
        self.assertEqual(finding["status"], "external_required")
        self.assertEqual(finding["commands"][0][0:2], ["pysec", "prepare-signing"])
        self.assertIn("organization", first["summary"]["by_authority"])

        schema = json.loads(read_bundled_schema("closure-plan-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(first)

        markdown = render_closure_plan_markdown(first)
        self.assertIn("# Findings closure plan", markdown)
        self.assertIn("non-authoritative", markdown)
        self.assertIn("```text\npysec prepare-signing", markdown)

    @patch("py_security_suite.closure_plan.verify_report")
    def test_filters_coverage_and_bounds_operator_options(self, verify_mock) -> None:
        verify_mock.return_value = {
            "scan_id": "scan-1",
            "outcome": "pass",
            "checksums_sha256": "e" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_report(report)
            result = build_closure_plan(
                report,
                coverage_target=80.0,
                hotspot_limit=1,
            )
        self.assertFalse(
            any(item["category"] == "test-assurance" for item in result["items"])
        )

        with self.assertRaisesRegex(ValueError, "between 0 and 100"):
            build_closure_plan(Path("unused"), coverage_target=101.0)
        with self.assertRaisesRegex(ValueError, "between 0 and 100"):
            build_closure_plan(Path("unused"), hotspot_limit=101)


def _write_report(report: Path) -> None:
    _write(
        report / "scan-manifest.json",
        {
            "inventory": {"source_sha256": "a" * 64},
            "network_isolation_attested": False,
            "tools": [],
        },
    )
    _write(
        report / "findings.json",
        {
            "findings": [
                {
                    "finding_id": "PYSEC-1",
                    "status": "new",
                    "severity": "high",
                    "title": "Sigstore verification bundle is missing",
                    "impact": "Artifact signer identity cannot be verified.",
                    "remediation": "Sign in the controlled release lane.",
                    "sources": [
                        {
                            "tool": "cosign",
                            "rule_id": "COSIGN-BUNDLE-MISSING",
                        }
                    ],
                    "locations": [{"path": "dist/project.whl"}],
                    "evidence": {"owners": ["@release"]},
                }
            ]
        },
    )
    _write(
        report / "admission-decisions.json",
        {
            "axes": [
                {
                    "axis": "governance",
                    "integrity_gaps": [
                        "external network-isolation attestation is absent",
                        "2 scanner entry point(s) lack organization approval",
                    ],
                }
            ]
        },
    )
    _write(
        report / "portfolio-health.json",
        {
            "activation_recipes": [
                {
                    "tool": "guarddog",
                    "category": "platform_constraint",
                    "owner": "platform-security",
                    "reason": "supported companion platform is unavailable",
                    "required_action": "Run on an approved supported platform.",
                    "evidence_required": "Digest-bound companion evidence.",
                }
            ]
        },
    )
    _write(
        report / "coverage-summary.json",
        {
            "files": [
                {
                    "path": "src/py_security_suite/governance.py",
                    "summary": {"percent_covered": 80.0},
                }
            ]
        },
    )
    _write(
        report / "reachability.json",
        {
            "warnings": ["Dynamic loading was detected."],
            "summary": {"load_only_islands": 2, "reportable_islands": 0},
        },
    )


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
