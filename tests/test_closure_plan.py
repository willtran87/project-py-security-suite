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
        finding = next(
            item
            for item in first["items"]
            if item["category"] == "finding" and item["authority"] == "external"
        )
        self.assertEqual(finding["authority"], "external")
        self.assertEqual(finding["status"], "external_required")
        self.assertEqual(finding["commands"][0][0:2], ["pysec", "prepare-signing"])
        self.assertIn("organization", first["summary"]["by_authority"])
        advisory_items = [
            item
            for item in first["items"]
            if item["details"].get("advisory_cluster_id") == "ADV-ABC123"
        ]
        self.assertEqual(len(advisory_items), 1)
        advisory = advisory_items[0]
        self.assertEqual(advisory["priority"], "P0")
        self.assertEqual(advisory["owner"], "@dependency-team")
        self.assertEqual(
            advisory["related_findings"], ["GRYPE-1", "OSV-1"]
        )
        self.assertEqual(advisory["tools"], ["grype", "osv-scanner"])
        self.assertIn("tests/test_client.py", advisory["evidence_refs"])
        self.assertIn("Upgrade demo-lib", advisory["action"])
        self.assertEqual(first["summary"]["advisory_items"], 1)
        self.assertEqual(first["summary"]["advisory_observations"], 2)
        self.assertEqual(first["summary"]["alias_observations_consolidated"], 1)

        self.assertEqual(first["schema_version"], "1.1")
        schema = json.loads(read_bundled_schema("closure-plan-1.1"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(first)

        markdown = render_closure_plan_markdown(first)
        self.assertIn("# Findings closure plan", markdown)
        self.assertIn("Distinct advisory work:** 1 item(s) from 2", markdown)
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
                },
                _advisory_finding("OSV-1", "osv-scanner"),
                _advisory_finding("GRYPE-1", "grype"),
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


def _advisory_finding(finding_id: str, tool: str) -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "status": "new",
        "severity": "critical",
        "title": "CVE-2026-12345 affects demo-lib",
        "impact": "The affected package is present.",
        "remediation": "Upgrade the dependency.",
        "sources": [{"tool": tool, "rule_id": "CVE-2026-12345"}],
        "locations": [{"path": "uv.lock", "package": "demo-lib"}],
        "evidence": {
            "fusion": {
                "advisory_context": {
                    "cluster_id": "ADV-ABC123",
                    "primary_identifier": "CVE-2026-12345",
                    "identifiers": ["CVE-2026-12345", "GHSA-DEMO"],
                    "package": "demo-lib",
                    "versions": ["1.0"],
                    "finding_ids": ["GRYPE-1", "OSV-1"],
                    "tools": ["grype", "osv-scanner"],
                    "dependency_usage": {
                        "assessment": "executable-import",
                        "import_paths": ["src/client.py"],
                    },
                    "remediation_context": {
                        "priority": "P0",
                        "action_kind": "upgrade",
                        "owners": ["@dependency-team"],
                        "recommended_test_files": ["tests/test_client.py"],
                        "test_selection_confidence": "high",
                        "fixed_version_candidates": ["2.0"],
                        "recommended_action": "Upgrade demo-lib to an approved 2.0 release.",
                        "verification_steps": [
                            "Run tests/test_client.py.",
                            "Regenerate and verify the report.",
                        ],
                        "evidence_basis": ["OSV and Grype observations"],
                        "uncertainties": [
                            "Package use does not prove vulnerable API execution."
                        ],
                    },
                }
            }
        },
    }


if __name__ == "__main__":
    unittest.main()
