from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from py_security_suite.adapters.pylint import PylintAdapter
from py_security_suite.adapters.radon import RadonAdapter
from py_security_suite.adapters.reuse import ReuseAdapter
from py_security_suite.adapters.ruff_format import RuffFormatAdapter
from py_security_suite.adapters.test_evidence import (
    CoverageAdapter,
    HypothesisAdapter,
    JUnitAdapter,
    SchemathesisAdapter,
    _integer,
    _number,
    _optional_integer,
)
from py_security_suite.config import ToolConfig
from py_security_suite.evidence_ingest import _coverage_document, _junit_document


class HealthAdapterTests(unittest.TestCase):
    def test_test_evidence_applicability_and_commands_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            coverage = CoverageAdapter(ToolConfig(), 1024)
            junit = JUnitAdapter(ToolConfig(), 1024)
            self.assertIn("coverage.json", coverage.not_applicable_reason(root) or "")
            self.assertIn("JUnit", junit.not_applicable_reason(root) or "")
            (root / "coverage.json").write_text("{}", encoding="utf-8")
            reports = root / "junit.xml"
            reports.mkdir()
            (reports / "one.xml").write_text("<testsuite/>", encoding="utf-8")
            self.assertIsNone(coverage.not_applicable_reason(root))
            self.assertIsNone(junit.not_applicable_reason(root))
            self.assertEqual(coverage.build_command("ingest", root)[1], "coverage")
            self.assertEqual(junit.build_command("ingest", root)[1], "junit")

    def test_specialized_test_evidence_fails_closed_only_when_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hypothesis = HypothesisAdapter(ToolConfig(), 1024)
            schemathesis = SchemathesisAdapter(ToolConfig(), 1024)
            self.assertIn(
                "no Python source", hypothesis.not_applicable_reason(root) or ""
            )
            self.assertIn("no OpenAPI", schemathesis.not_applicable_reason(root) or "")
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            (root / "openapi.yaml").write_text("openapi: 3.1.0\n", encoding="utf-8")
            self.assertIsNone(hypothesis.not_applicable_reason(root))
            self.assertIsNone(schemathesis.not_applicable_reason(root))

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

    def test_coverage_adapter_orders_hotspots_and_validates_evidence(self) -> None:
        adapter = CoverageAdapter(ToolConfig(minimum_coverage_percent=80), 1024)
        payload = json.dumps(
            {
                "kind": "coverage",
                "totals": {"num_statements": 20, "percent_covered": 90},
                "files": [
                    {
                        "path": "src/healthy.py",
                        "summary": {"num_statements": 10, "percent_covered": 100},
                        "missing_lines": [],
                    },
                    {
                        "path": "src/small.py",
                        "summary": {"num_statements": 5, "percent_covered": 50},
                        "missing_lines": [3],
                    },
                    {
                        "path": "src/large.py",
                        "summary": {"num_statements": 20, "percent_covered": 50},
                        "missing_lines": [8, "9"],
                    },
                ],
            }
        )
        findings = adapter.parse(payload, Path("."))
        self.assertEqual(
            [item.locations[0].path for item in findings],
            ["src/large.py", "src/small.py"],
        )
        artifact = adapter.derived_artifacts(payload, Path("."))
        self.assertEqual(artifact["coverage-summary.json"]["finding_hotspot_limit"], 10)
        invalid_payloads = (
            ({"kind": "coverage", "totals": [], "files": []}, "totals object"),
            ({"kind": "coverage", "totals": {}, "files": [1]}, "file result"),
            (
                {"kind": "coverage", "totals": {}, "files": [{"summary": []}]},
                "file summary",
            ),
            (
                {
                    "kind": "coverage",
                    "totals": {},
                    "files": [
                        {"summary": {"num_statements": 1}, "missing_lines": {"bad": 1}}
                    ],
                },
                "missing_lines",
            ),
        )
        for document, message in invalid_payloads:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(TypeError, message),
            ):
                adapter.parse(json.dumps(document), Path("."))

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

    def test_test_evidence_adapters_preserve_verified_source_binding(self) -> None:
        binding = {
            "schema_version": "1.0",
            "evidence_sha256": "b" * 64,
            "binding_file": "evidence.pysec-binding.json",
            "verified": True,
        }
        coverage_payload = json.dumps(
            {
                "kind": "coverage",
                "source_sha256": "a" * 64,
                "evidence_binding": binding,
                "totals": {},
                "files": [],
            }
        )
        junit_payload = json.dumps(
            {
                "kind": "junit",
                "source_sha256": "a" * 64,
                "evidence_binding": binding,
                "failures": [],
                "test_cases": [],
            }
        )

        coverage = CoverageAdapter(ToolConfig(), 1024).derived_artifacts(
            coverage_payload, Path(".")
        )["coverage-summary.json"]
        junit = JUnitAdapter(ToolConfig(), 1024).derived_artifacts(
            junit_payload, Path(".")
        )["junit-summary.json"]

        for artifact in (coverage, junit):
            self.assertEqual(artifact["source_sha256"], "a" * 64)
            self.assertEqual(artifact["evidence_binding"], binding)

    def test_junit_defaults_artifacts_and_type_guards(self) -> None:
        adapter = JUnitAdapter(ToolConfig(), 1024)
        payload = json.dumps(
            {
                "kind": "junit",
                "failures": [{"name": "unnamed", "result": "error"}],
                "test_cases": [
                    {
                        "name": "test_ok",
                        "file": "tests/test_ok.py",
                        "result": "passed",
                    },
                    {
                        "name": "test_module_mapping",
                        "classname": "tests.test_health_adapters.HealthAdapterTests",
                        "file": "",
                        "result": "passed",
                    },
                ],
                "test_case_inventory_complete": True,
            }
        )
        finding = adapter.parse(payload, Path("."))[0]
        self.assertEqual(finding.locations[0].path, "<test-suite>")
        self.assertIsNone(finding.locations[0].start_line)
        self.assertEqual(finding.sources[0].native_severity, "error")
        self.assertEqual(
            adapter.derived_artifacts(payload, Path("."))["junit-summary.json"]["kind"],
            "junit",
        )
        self.assertEqual(
            adapter.derived_artifacts(payload, Path("."))["junit-summary.json"][
                "test_cases"
            ][0]["file"],
            "tests/test_ok.py",
        )
        self.assertEqual(
            adapter.derived_artifacts(payload, Path("."))["junit-summary.json"][
                "test_cases"
            ][1]["file"],
            "tests/test_health_adapters.py",
        )
        self.assertEqual(
            adapter.derived_artifacts(payload, Path("."))["junit-summary.json"][
                "test_cases"
            ][1]["file_attribution"],
            "classname-module",
        )
        with self.assertRaisesRegex(TypeError, "failures list"):
            adapter.parse('{"kind":"junit","failures":{}}', Path("."))
        with self.assertRaisesRegex(TypeError, "failure must be an object"):
            adapter.parse('{"kind":"junit","failures":[1]}', Path("."))
        with self.assertRaisesRegex(TypeError, "validated junit"):
            adapter.parse('{"kind":"coverage"}', Path("."))

    def test_evidence_number_conversions_are_strict(self) -> None:
        self.assertEqual(_integer("2"), 2)
        self.assertEqual(_optional_integer(""), None)
        self.assertEqual(_optional_integer("3"), 3)
        self.assertEqual(_number("2.5"), 2.5)
        with self.assertRaisesRegex(TypeError, "expected integer"):
            _integer("bad")
        with self.assertRaisesRegex(TypeError, "expected numeric"):
            _number("bad")

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
