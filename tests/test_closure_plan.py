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
        self.assertGreaterEqual(first["summary"]["open_items"], 7)
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
        self.assertEqual(advisory["related_findings"], ["GRYPE-1", "OSV-1"])
        self.assertEqual(advisory["tools"], ["grype", "osv-scanner"])
        self.assertIn("tests/test_client.py", advisory["evidence_refs"])
        self.assertIn("Upgrade demo-lib", advisory["action"])
        self.assertEqual(first["summary"]["advisory_items"], 1)
        self.assertEqual(first["summary"]["advisory_observations"], 2)
        self.assertEqual(first["summary"]["alias_observations_consolidated"], 1)
        self.assertEqual(first["summary"]["validation_alignment_items"], 1)
        self.assertEqual(first["summary"]["codeowner_backed_validation_items"], 1)
        self.assertEqual(first["summary"]["validation_items_with_coverage_gaps"], 1)
        validation = next(
            item
            for item in first["items"]
            if item["details"].get("validation_alignment") == "coverage-gap"
        )
        self.assertEqual(validation["owner"], "@security-suite")
        self.assertEqual(validation["priority"], "P2")
        self.assertIn("tests/test_governance.py", validation["evidence_refs"])
        self.assertIn("junit-summary.json", validation["evidence_refs"])
        self.assertIn(
            "Every cited changed executable line is covered.",
            validation["acceptance_criteria"],
        )
        self.assertEqual(validation["details"]["uncovered_changed_lines"], [41, 44])
        self.assertEqual(validation["details"]["file_coverage_percent"], 80.0)
        self.assertTrue(validation["details"]["ownership_rule_matched"])
        self.assertIn("junit", validation["tools"])
        self.assertNotIn("junit-summary.json", validation["tools"])
        self.assertIn("COVERAGE-1", validation["related_findings"])
        self.assertEqual(
            validation["details"]["consolidated_coverage_findings"][0]["finding_ids"],
            ["COVERAGE-1"],
        )
        self.assertEqual(
            len(
                [
                    item
                    for item in first["items"]
                    if "src/py_security_suite/governance.py" in item["evidence_refs"]
                ]
            ),
            1,
        )
        advanced_items = [
            item for item in first["items"] if item["details"].get("advanced_analysis")
        ]
        self.assertEqual(len(advanced_items), 7)
        self.assertTrue(
            all(item["category"] == "architecture" for item in advanced_items)
        )
        self.assertTrue(
            all(
                "advanced-analysis.json" in item["evidence_refs"]
                for item in advanced_items
            )
        )
        self.assertEqual(
            next(
                item
                for item in advanced_items
                if item["details"].get("closure_status")
                == "threat-without-control-evidence"
            )["priority"],
            "P1",
        )
        self.assertEqual(
            next(
                item
                for item in advanced_items
                if item["details"].get("validation_signal")
                == "surviving-security-control-mutation"
            )["priority"],
            "P1",
        )

        self.assertEqual(first["schema_version"], "1.2")
        schema = json.loads(read_bundled_schema("closure-plan-1.2"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(first)

        markdown = render_closure_plan_markdown(first)
        self.assertIn("# Findings closure plan", markdown)
        self.assertIn("Distinct advisory work:** 1 item(s) from 2", markdown)
        self.assertIn("Changed-file validation work:** 1 item(s); 1 assigned", markdown)
        self.assertIn("## Validation work queues", markdown)
        self.assertIn(
            "| `@security-suite` | `coverage-gap` | 0 | 1 | 0 | 1 |", markdown
        )
        self.assertIn("| `P2` | test-assurance |", markdown)
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
        assurance = [
            item for item in result["items"] if item["category"] == "test-assurance"
        ]
        self.assertEqual(len(assurance), 1)
        self.assertEqual(
            assurance[0]["details"]["validation_alignment"], "coverage-gap"
        )
        self.assertNotIn(
            "The module reaches at least 80.00%",
            " ".join(assurance[0]["acceptance_criteria"]),
        )

        with self.assertRaisesRegex(ValueError, "between 0 and 100"):
            build_closure_plan(Path("unused"), coverage_target=101.0)
        with self.assertRaisesRegex(ValueError, "between 0 and 100"):
            build_closure_plan(Path("unused"), hotspot_limit=101)

    @patch("py_security_suite.closure_plan.verify_report")
    def test_turns_omitted_change_assessments_into_fail_closed_work(
        self, verify_mock
    ) -> None:
        verify_mock.return_value = {
            "scan_id": "scan-1",
            "outcome": "pass",
            "checksums_sha256": "e" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_report(report)
            structural_path = report / "structural-synthesis.json"
            structural = json.loads(structural_path.read_text(encoding="utf-8"))
            structural["truncation"] = {"change_impact_assessments_omitted": 3}
            _write(structural_path, structural)
            result = build_closure_plan(report)

        truncated = next(
            item
            for item in result["items"]
            if item["details"].get("validation_alignment") == "assessment-truncated"
        )
        self.assertEqual(truncated["priority"], "P1")
        self.assertEqual(truncated["owner"], "quality-engineering")
        self.assertEqual(truncated["details"]["omitted_change_impact_assessments"], 3)
        self.assertEqual(result["summary"]["validation_alignment_items"], 2)


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
                {
                    "finding_id": "COVERAGE-1",
                    "status": "new",
                    "severity": "medium",
                    "title": "Changed-line coverage below target",
                    "impact": "Changed behavior lacks observed execution.",
                    "remediation": "Cover the cited changed lines.",
                    "sources": [{"tool": "diff-cover", "rule_id": "DIFF-COVERAGE"}],
                    "locations": [{"path": "src/py_security_suite/governance.py"}],
                    "evidence": {"owners": ["@security-suite"]},
                },
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
    _write(
        report / "finding-delta.json",
        {
            "ownership_rule_details": [
                {
                    "pattern": "src/py_security_suite/*",
                    "owners": ["@security-suite"],
                }
            ]
        },
    )
    _write(
        report / "structural-synthesis.json",
        {
            "change_impact_assessments": [
                {
                    "path": "src/py_security_suite/governance.py",
                    "priority": "high",
                    "risk_score": 71,
                    "changed_lines": 5,
                    "uncovered_changed_lines": [41, 44],
                    "changed_line_coverage_percent": 60.0,
                    "file_coverage_percent": 80.0,
                    "direct_test_files": ["tests/test_governance.py"],
                    "transitive_test_files": [],
                    "associated_test_files": [],
                    "test_selection_confidence": "high",
                    "focused_test_validation_status": "passed",
                    "focused_test_execution": [
                        {
                            "test_file": "tests/test_governance.py",
                            "status": "passed",
                            "source": "junit.xml",
                        }
                    ],
                    "test_execution_sources": ["junit-summary.json"],
                    "test_coverage_alignment": "coverage-gap",
                    "validation_gap_reasons": [
                        "focused tests passed but changed executable lines remain uncovered"
                    ],
                    "validation_action": "Extend the passing focused tests and regenerate evidence.",
                    "finding_ids": ["PYSEC-1"],
                }
            ]
        },
    )
    _write(
        report / "advanced-analysis.json",
        {
            "schema_id": "urn:project-py-security-suite:advanced-analysis:1.0",
            "control_topology": [
                {
                    "control_point_id": "control-1",
                    "path": "src/security.py",
                    "topology_status": "bypass-capable",
                    "owners": ["@security"],
                    "recommended_action": "Protect the alternate route.",
                }
            ],
            "artifact_route_parity": [
                {
                    "artifact": "dist/demo.whl",
                    "published_entry_points": [
                        {
                            "group": "console_scripts",
                            "name": "demo",
                            "target": "demo.cli:main",
                            "parity_status": "unmodeled-entry-point",
                        }
                    ],
                    "record_gaps": [{"kind": "digest-mismatch", "path": "demo/cli.py"}],
                }
            ],
            "telemetry_privacy_topology": [
                {
                    "privacy_route_id": "privacy-1",
                    "path": "src/telemetry.py",
                    "line": 42,
                    "review_status": "protection-gap",
                    "protection_status": "unprotected",
                    "owners": ["@privacy"],
                }
            ],
            "dependency_trust_routes": [
                {
                    "dependency_trust_route_id": "dependency-1",
                    "package": "demo-lib",
                    "review_tier": "critical",
                    "risk_factors": ["known-exploited-vulnerability"],
                    "owners": ["@dependency-team"],
                }
            ],
            "threat_control_test_traceability": [
                {
                    "traceability_id": "trace-1",
                    "threat_finding_id": "PYTM-1",
                    "path": "src/auth.py",
                    "line": 20,
                    "closure_status": "threat-without-control-evidence",
                    "owners": ["@security"],
                }
            ],
            "security_mutation_leverage": [
                {
                    "mutation_leverage_id": "mutation-1",
                    "finding_id": "MUTMUT-1",
                    "path": "src/security.py",
                    "line": 51,
                    "validation_signal": "surviving-security-control-mutation",
                    "test_files": [],
                    "owners": ["@security"],
                }
            ],
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
