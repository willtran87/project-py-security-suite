from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from py_security_suite.adapters.pylint import PylintAdapter
from py_security_suite.adapters.radon import RadonAdapter
from py_security_suite.adapters.reuse import ReuseAdapter
from py_security_suite.adapters.ruff_format import RuffFormatAdapter
from py_security_suite.adapters.test_evidence import CoverageAdapter, JUnitAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.evidence_ingest import _coverage_document, _junit_document


class HealthAdapterTests(unittest.TestCase):
    def test_pylint_preserves_rule_attribution_and_precise_location(self) -> None:
        payload = json.dumps(
            {
                "messages": [
                    {
                        "type": "warning",
                        "symbol": "dangerous-default-value",
                        "message": "Dangerous default value [] as argument",
                        "messageId": "W0102",
                        "path": "src/example.py",
                        "line": 8,
                        "endLine": 8,
                    }
                ],
                "statistics": {"messageTypeCount": {"warning": 1}},
            }
        )
        finding = PylintAdapter(ToolConfig(), 1024).parse(payload, Path("."))[0]
        self.assertEqual(finding.sources[0].tool, "pylint")
        self.assertEqual(finding.sources[0].rule_id, "W0102")
        self.assertEqual(finding.classifications, ["PYLINT-W0102"])
        self.assertEqual(finding.locations[0].start_line, 8)

    def test_radon_reports_extreme_complexity_and_retains_c_rank_evidence(self) -> None:
        payload = json.dumps(
            {
                "src/example.py": [
                    {
                        "type": "function",
                        "name": "complex_path",
                        "lineno": 4,
                        "endline": 40,
                        "complexity": 33,
                        "rank": "E",
                        "closures": [],
                    },
                    {
                        "type": "function",
                        "name": "review_path",
                        "lineno": 44,
                        "endline": 60,
                        "complexity": 12,
                        "rank": "C",
                        "closures": [],
                    },
                ]
            }
        )
        adapter = RadonAdapter(ToolConfig(), 1024)
        findings = adapter.parse(payload, Path("."))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "high")
        artifact = adapter.derived_artifacts(payload, Path("."))
        self.assertEqual(
            artifact["radon-complexity.json"]["minimum_reported_rank"], "C"
        )

    def test_ruff_format_normalizes_changed_files(self) -> None:
        finding = RuffFormatAdapter(ToolConfig(), 1024).parse(
            "Would reformat: src/example.py\n1 file would be reformatted\n",
            Path("."),
        )[0]
        self.assertEqual(finding.domain, "quality")
        self.assertEqual(finding.area, "formatting")
        self.assertEqual(finding.sources[0].tool, "ruff-format")

    def test_reuse_normalizes_nested_non_compliance(self) -> None:
        payload = json.dumps(
            {
                "non_compliant": {
                    "missing_licensing_info": ["src/example.py"],
                    "missing_copyright_info": [],
                }
            }
        )
        finding = ReuseAdapter(ToolConfig(), 1024).parse(payload, Path("."))[0]
        self.assertEqual(finding.domain, "governance")
        self.assertEqual(finding.area, "license-compliance")
        self.assertEqual(finding.sources[0].tool, "reuse")
        self.assertEqual(finding.classifications, ["REUSE-MISSING-LICENSE-METADATA"])

    def test_coverage_adapter_reports_below_threshold_files(self) -> None:
        payload = json.dumps(
            {
                "kind": "coverage",
                "totals": {
                    "num_statements": 10,
                    "percent_covered": 70,
                    "missing_lines": 3,
                    "missing_branches": 2,
                },
                "files": [
                    {
                        "path": "src/example.py",
                        "summary": {
                            "num_statements": 10,
                            "percent_covered": 70,
                            "missing_branches": 2,
                        },
                        "missing_lines": [12, 13, 14],
                    }
                ],
            }
        )
        config = ToolConfig(minimum_coverage_percent=80.0)
        findings = CoverageAdapter(config, 1024).parse(payload, Path("."))
        self.assertEqual(len(findings), 2)
        finding = findings[1]
        self.assertEqual(finding.domain, "testing")
        self.assertEqual(finding.locations[0].start_line, 12)
        self.assertEqual(finding.evidence["minimum_percent"], 80.0)

    def test_junit_adapter_never_needs_failure_body(self) -> None:
        payload = json.dumps(
            {
                "kind": "junit",
                "failures": [
                    {
                        "name": "test_policy",
                        "classname": "tests.PolicyTests",
                        "file": "tests/test_policy.py",
                        "line": 17,
                        "result": "failure",
                        "message": "expected secure result",
                        "time": 0.1,
                    }
                ],
            }
        )
        finding = JUnitAdapter(ToolConfig(), 1024).parse(payload, Path("."))[0]
        self.assertEqual(finding.domain, "testing")
        self.assertEqual(finding.sources[0].tool, "junit")
        self.assertNotIn("body", finding.evidence)

    def test_evidence_ingestion_is_bounded_and_drops_junit_output_bodies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            coverage = root / "coverage.json"
            coverage.write_text(
                json.dumps(
                    {
                        "meta": {"format": 3, "branch_coverage": True},
                        "totals": {
                            "covered_lines": 1,
                            "num_statements": 2,
                            "percent_covered": 50,
                            "missing_lines": 1,
                            "num_branches": 2,
                            "covered_branches": 1,
                            "missing_branches": 1,
                            "num_partial_branches": 0,
                        },
                        "files": {
                            "src/example.py": {
                                "summary": {
                                    "covered_lines": 1,
                                    "num_statements": 2,
                                    "percent_covered": 50,
                                    "missing_lines": 1,
                                    "num_branches": 2,
                                    "covered_branches": 1,
                                    "missing_branches": 1,
                                    "num_partial_branches": 0,
                                },
                                "missing_lines": [2],
                                "missing_branches": [[1, 2]],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(_coverage_document(coverage)["kind"], "coverage")

            junit = root / "junit.xml"
            junit.write_text(
                '<testsuite><testcase name="bad" file="test_x.py" line="2">'
                '<failure message="no">sensitive process output</failure>'
                "<system-out>secret output</system-out></testcase></testsuite>",
                encoding="utf-8",
            )
            normalized = _junit_document(junit)
            self.assertEqual(normalized["totals"]["failures"], 1)
            self.assertNotIn("sensitive process output", json.dumps(normalized))
            self.assertNotIn("secret output", json.dumps(normalized))

            junit.write_text(
                '<!DOCTYPE testsuite [<!ENTITY xxe SYSTEM "file:///secret">]>'
                "<testsuite />",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "DTD and entity"):
                _junit_document(junit)


if __name__ == "__main__":
    unittest.main()
