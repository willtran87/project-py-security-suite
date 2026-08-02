from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from py_security_suite.adapters.assurance_evidence import (
    CrossHairAdapter,
    InTotoAdapter,
    OciImageAdapter,
    PyTmAdapter,
    ReproducibleBuildAdapter,
    YaraAdapter,
    ZapAdapter,
)
from py_security_suite.adapters.test_evidence import (
    HypothesisAdapter,
    SchemathesisAdapter,
)
from py_security_suite.adapters.portfolio import (
    GitSizerAdapter,
    KicsAdapter,
    PipdeptreeAdapter,
    ValeAdapter,
    ValidatePyprojectAdapter,
)
from py_security_suite.config import ToolConfig
from py_security_suite.evidence_ingest import _assurance_document
from py_security_suite.reports import render_sonarqube_external_issues


class PortfolioAdapterTests(unittest.TestCase):
    def test_kics_normalizes_location_classification_and_tool_citation(self) -> None:
        payload = json.dumps(
            {
                "queries": [
                    {
                        "query_name": "Privileged container",
                        "query_id": "abc-123",
                        "severity": "HIGH",
                        "platform": "Kubernetes",
                        "cwe": "250",
                        "description": "Container grants excessive privilege",
                        "files": [
                            {
                                "file_name": "deploy/pod.yaml",
                                "line": 14,
                                "issue_type": "IncorrectValue",
                                "expected_value": "privileged=false",
                                "actual_value": "privileged=true",
                            }
                        ],
                    }
                ]
            }
        )
        finding = KicsAdapter(ToolConfig(), 4096).parse(payload, Path("."))[0]
        self.assertEqual(finding.sources[0].tool, "kics")
        self.assertEqual(finding.locations[0].start_line, 14)
        self.assertIn("CWE-250", finding.classifications)
        self.assertEqual(finding.severity.value, "high")

    def test_pipdeptree_health_summary_creates_actionable_findings(self) -> None:
        payload = json.dumps(
            {
                "missing_dependencies": 1,
                "cyclic_dependencies": 2,
                "conflicting_dependencies": {"packages": 1, "edges": 3},
            }
        )
        findings = PipdeptreeAdapter(ToolConfig(), 4096).parse(payload, Path("."))
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(item.domain == "supply-chain" for item in findings))

    def test_git_sizer_recurses_over_v2_concern_metrics(self) -> None:
        payload = json.dumps(
            {
                "maxBlobSize": {
                    "description": "largest blob",
                    "value": 50_000_000,
                    "levelOfConcern": 2,
                }
            }
        )
        finding = GitSizerAdapter(ToolConfig(), 4096).parse(payload, Path("."))[0]
        self.assertEqual(finding.area, "repository-health")
        self.assertEqual(finding.severity.value, "medium")

    def test_validate_pyproject_distinguishes_valid_json_from_invalid_text(
        self,
    ) -> None:
        adapter = ValidatePyprojectAdapter(ToolConfig(), 4096)
        self.assertEqual(adapter.parse('{"project":{"name":"demo"}}', Path(".")), [])
        finding = adapter.parse("Invalid file: pyproject.toml", Path("."))[0]
        self.assertEqual(finding.locations[0].path, "pyproject.toml")

    def test_vale_preserves_file_line_and_rule(self) -> None:
        payload = json.dumps(
            {
                "README.md": [
                    {
                        "Check": "Docs.Weasel",
                        "Line": 9,
                        "Severity": "warning",
                        "Message": "Avoid vague language",
                    }
                ]
            }
        )
        finding = ValeAdapter(ToolConfig(), 4096).parse(payload, Path("."))[0]
        self.assertEqual(finding.sources[0].rule_id, "Docs.Weasel")
        self.assertEqual(finding.locations[0].start_line, 9)

    def test_assurance_ingestion_is_bounded_and_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "crosshair.json"
            path.write_text(
                json.dumps(
                    {
                        "kind": "crosshair",
                        "producer": "crosshair 0.0",
                        "findings": [
                            {
                                "rule_id": "postcondition",
                                "title": "Postcondition can fail",
                                "message": "Counterexample: value=-1",
                                "path": "src/app.py",
                                "line": 12,
                                "severity": "high",
                                "evidence": {"counterexample": "value=-1"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            normalized = _assurance_document(path, "crosshair")
        finding = CrossHairAdapter(ToolConfig(), 4096).parse(
            json.dumps(normalized), Path(".")
        )[0]
        self.assertEqual(finding.sources[0].tool, "crosshair")
        self.assertEqual(finding.locations[0].start_line, 12)
        self.assertEqual(finding.evidence["counterexample"], "value=-1")

    def test_property_and_api_junit_preserve_producer_attribution(self) -> None:
        payload = json.dumps(
            {
                "kind": "junit",
                "failures": [
                    {
                        "result": "failure",
                        "name": "test_invariant",
                        "classname": "tests.test_properties",
                        "file": "tests/test_properties.py",
                        "line": 12,
                        "message": "minimal counterexample found",
                    }
                ],
            }
        )
        hypothesis = HypothesisAdapter(ToolConfig(), 4096).parse(payload, Path("."))[0]
        schemathesis = SchemathesisAdapter(ToolConfig(), 4096).parse(
            payload, Path(".")
        )[0]
        self.assertEqual(hypothesis.sources[0].tool, "hypothesis")
        self.assertEqual(hypothesis.area, "property-based-testing")
        self.assertEqual(schemathesis.sources[0].tool, "schemathesis")
        self.assertEqual(schemathesis.area, "api-schema-testing")

    def test_new_companion_evidence_has_distinct_domains_and_areas(self) -> None:
        adapters = [
            (ZapAdapter, "security", "dynamic-application-security-testing"),
            (PyTmAdapter, "security", "threat-modeling"),
            (InTotoAdapter, "supply-chain", "build-provenance"),
            (
                ReproducibleBuildAdapter,
                "supply-chain",
                "build-reproducibility",
            ),
            (OciImageAdapter, "supply-chain", "container-image-security"),
            (YaraAdapter, "security", "malware-scanning"),
        ]
        for adapter_type, domain, area in adapters:
            adapter = adapter_type(ToolConfig(), 4096)
            payload = json.dumps(
                {
                    "kind": adapter.evidence_kind,
                    "findings": [
                        {
                            "rule_id": "evidence-failure",
                            "title": "Evidence failed",
                            "message": "The companion control failed",
                        }
                    ],
                }
            )
            finding = adapter.parse(payload, Path("."))[0]
            self.assertEqual(finding.domain, domain)
            self.assertEqual(finding.area, area)
            self.assertEqual(finding.sources[0].tool, adapter.name)

    def test_sonarqube_export_has_engine_rule_location_and_action(self) -> None:
        finding = ValeAdapter(ToolConfig(), 4096).parse(
            json.dumps(
                {
                    "README.md": [
                        {
                            "Check": "Docs.Rule",
                            "Line": 3,
                            "Severity": "error",
                            "Message": "Rewrite this sentence",
                        }
                    ]
                }
            ),
            Path("."),
        )[0]
        issue = render_sonarqube_external_issues([finding])["issues"][0]
        self.assertEqual(issue["engineId"], "py-security-suite")
        self.assertEqual(issue["primaryLocation"]["filePath"], "README.md")
        self.assertIn("Recommended", issue["primaryLocation"]["message"])


if __name__ == "__main__":
    unittest.main()
