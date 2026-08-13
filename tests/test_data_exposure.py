from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from py_security_suite.data_exposure import (
    apply_data_exposure_fusion,
    build_data_exposure_synthesis,
)
from py_security_suite.evidence_fusion import build_evidence_fusion
from py_security_suite.models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
)
from py_security_suite.report_inspection import read_bundled_schema
from py_security_suite.reports import (
    _markdown_data_exposure_context,
    _render_data_exposure_summary,
    render_sarif,
    render_sonarqube_external_issues,
)


def _finding(
    *,
    path: str = "src/app.py",
    line: int = 6,
    classifications: list[str] | None = None,
    rule_id: str = "python.sensitive-data-to-telemetry",
) -> Finding:
    return Finding(
        finding_id="PYSEC-EXPOSURE",
        fingerprint="sha256:exposure",
        title="Sensitive data may reach telemetry",
        description="A credential-bearing source reaches a telemetry sink.",
        impact="The value can cross a trust boundary.",
        remediation="Minimize and redact the payload.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="data-exposure",
        classifications=classifications or ["CWE-201", "CWE-200"],
        locations=[Location(path=path, start_line=line, end_line=line)],
        sources=[
            Source(
                tool="semgrep",
                rule_id=rule_id,
                message="Sensitive flow",
                native_severity="ERROR",
            )
        ],
    )


class DataExposureSynthesisTests(unittest.TestCase):
    def test_inventories_sdk_sinks_without_claiming_a_leak(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "tests").mkdir()
            (root / "src" / "app.py").write_text(
                "import sentry_sdk\n"
                "import requests\n\n"
                "def report(user):\n"
                "    sentry_sdk.set_user(user)\n"
                "    requests.post('https://example.invalid', json=user)\n",
                encoding="utf-8",
            )
            (root / "tests" / "test_app.py").write_text(
                "import logging\nlogging.info('test')\n", encoding="utf-8"
            )
            (root / "pyproject.toml").write_text(
                '[project]\nname = "demo"\nversion = "1"\n'
                'dependencies = ["sentry-sdk>=2", "httpx>=0.28"]\n',
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(result["summary"]["exposure_findings"], 0)
        self.assertEqual(result["summary"]["production_sink_surfaces"], 2)
        self.assertEqual(result["summary"]["test_sink_surfaces"], 1)
        self.assertIn(
            "Sentry SDK", {item["sdk"] for item in result["sdk_observations"]}
        )
        self.assertIn("HTTPX", {item["sdk"] for item in result["sdk_observations"]})

    def test_accepts_utf8_bom_without_losing_sink_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "app.py"
            source.write_bytes(b"\xef\xbb\xbfimport logging\nlogging.error('review')\n")

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(result["summary"]["parse_errors"], 0)
        self.assertEqual(result["summary"]["production_sink_surfaces"], 1)

    def test_cross_references_egress_sdk_with_package_findings_and_lineage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "import os\nimport sentry_sdk\n\n"
                "token = os.getenv('AUTH_TOKEN')\n"
                "sentry_sdk.set_context('auth', {'token': token})\n",
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text(
                '[project]\nname = "demo"\nversion = "1"\n'
                'dependencies = ["sentry-sdk>=2"]\n',
                encoding="utf-8",
            )
            exposure = _finding(
                line=5,
                classifications=["CWE-201"],
                rule_id="python.sensitive-data-to-telemetry",
            )
            exposure.evidence["owners"] = ["@observability"]
            package = Finding(
                finding_id="PYSEC-SENTRY-ADVISORY",
                fingerprint="sha256:sentry-advisory",
                title="GHSA-DEMO affects sentry-sdk",
                description="The SDK version matches an advisory.",
                impact="The egress dependency may be vulnerable.",
                remediation="Upgrade to an approved fixed version.",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                area="dependencies",
                classifications=["GHSA-DEMO"],
                locations=[
                    Location(
                        path="uv.lock",
                        package="sentry-sdk",
                        version="2.0",
                        ecosystem="PyPI",
                    )
                ],
                sources=[
                    Source(
                        tool="osv-scanner",
                        rule_id="GHSA-DEMO",
                        message="Affected package",
                    )
                ],
                citations=[
                    Citation(
                        kind="advisory",
                        identifier="GHSA-DEMO",
                        title="Demonstration SDK advisory",
                        uri="https://example.invalid/GHSA-DEMO",
                    ),
                    Citation(
                        kind="supporting_evidence",
                        identifier="graphify-code-graph",
                        title="Graph context",
                        uri="https://example.invalid/graph",
                    ),
                ],
                evidence={
                    "fixed_versions": ["2.1"],
                    "risk_intelligence": {
                        "cves": ["CVE-2026-9000"],
                        "known_exploited": [{"cve": "CVE-2026-9000"}],
                    },
                },
            )
            result = build_data_exposure_synthesis(root, [exposure, package], {})
            fusion = build_evidence_fusion(
                [package, exposure],
                {
                    "sbom.cdx.json": {
                        "components": [
                            {
                                "bom-ref": "sentry-sdk@2.0",
                                "name": "sentry-sdk",
                                "version": "2.0",
                            }
                        ],
                        "dependencies": [{"ref": "sentry-sdk@2.0", "dependsOn": []}],
                    },
                    "artifact-sbom.cdx.json": {
                        "components": [{"name": "sentry-sdk", "version": "1.9"}]
                    },
                    "graphify.json": {
                        "nodes": [
                            {
                                "id": "app",
                                "kind": "code",
                                "label": "app.py",
                                "path": "src/app.py",
                            },
                            {
                                "id": "sentry_sdk",
                                "kind": "external",
                                "label": "sentry_sdk",
                                "path": ".",
                            },
                        ],
                        "edges": [
                            {
                                "source": "app",
                                "target": "sentry_sdk",
                                "relation": "imports",
                                "path": "src/app.py",
                                "line": 2,
                            }
                        ],
                        "topology": {
                            "file_edges": [
                                {
                                    "source": "tests/test_app.py",
                                    "target": "src/app.py",
                                    "relation": "imports",
                                    "count": 1,
                                }
                            ]
                        },
                    },
                    "finding-delta.json": {"ownership_rules": 1},
                    "coverage-summary.json": {
                        "files": [
                            {
                                "path": "src/app.py",
                                "summary": {"percent_covered": 72.0},
                            }
                        ]
                    },
                    "junit-summary.json": {
                        "test_case_inventory_complete": True,
                        "test_cases": [
                            {
                                "file": "tests/test_app.py",
                                "result": "passed",
                            }
                        ],
                    },
                    "reachability.json": {
                        "analysis": {"complete": True, "confidence": "high"},
                        "nodes": [
                            {
                                "id": "module:app",
                                "kind": "module",
                                "path": "src/app.py",
                                "state": "executable",
                                "runtime_observation": "not-observed",
                            }
                        ],
                    },
                },
                [],
            )

            apply_data_exposure_fusion(result, [exposure, package], fusion)

        assessment = result["finding_assessments"][0]
        dependency = assessment["sdk_dependency_context"]
        self.assertEqual(assessment["sdk"], "Sentry SDK")
        self.assertTrue(dependency["risk_present"])
        self.assertEqual(dependency["risk_tier"], "high")
        self.assertEqual(dependency["packages"], ["sentry-sdk"])
        self.assertEqual(dependency["package_finding_ids"], ["PYSEC-SENTRY-ADVISORY"])
        self.assertEqual(dependency["package_finding_tools"], ["osv-scanner"])
        self.assertEqual(dependency["package_classifications"], ["GHSA-DEMO"])
        self.assertEqual(dependency["distinct_advisory_count"], 1)
        self.assertEqual(dependency["advisory_observation_count"], 1)
        self.assertEqual(
            dependency["advisory_clusters"][0]["primary_identifier"], "GHSA-DEMO"
        )
        usage = dependency["advisory_clusters"][0]["dependency_usage"]
        self.assertEqual(usage["assessment"], "executable-import")
        self.assertEqual(usage["source_relationship"], "direct")
        self.assertEqual(usage["import_paths"], ["src/app.py"])
        self.assertEqual(dependency["advisories_with_import_evidence"], 1)
        self.assertEqual(dependency["advisories_in_executable_imports"], 1)
        self.assertEqual(dependency["known_exploited_advisories"], 1)
        self.assertEqual(dependency["advisories_with_fixed_versions"], 1)
        self.assertEqual(dependency["p0_advisories"], 1)
        self.assertEqual(dependency["advisories_with_focused_tests"], 1)
        self.assertEqual(dependency["advisories_with_import_path_owners"], 1)
        self.assertEqual(dependency["advisories_with_uncovered_import_paths"], 1)
        self.assertEqual(dependency["advisories_with_test_coverage_mismatch"], 1)
        cluster = dependency["advisory_clusters"][0]
        self.assertTrue(cluster["threat_context"]["known_exploited"])
        self.assertEqual(
            cluster["remediation_context"]["fixed_version_candidates"], ["2.1"]
        )
        self.assertEqual(cluster["remediation_context"]["owners"], ["@observability"])
        self.assertEqual(
            cluster["remediation_context"]["recommended_test_files"],
            ["tests/test_app.py"],
        )
        self.assertEqual(dependency["lineage"][0]["status"], "version-drift")
        self.assertEqual(dependency["citations"][0]["identifier"], "GHSA-DEMO")
        self.assertEqual(len(dependency["citations"]), 1)
        self.assertEqual(
            result["summary"]["exposure_findings_with_sdk_package_risk"], 1
        )
        self.assertEqual(result["summary"]["sink_surfaces_with_sdk_package_risk"], 1)
        self.assertEqual(result["summary"]["sdk_packages_correlated"], 1)
        self.assertEqual(result["summary"]["sdk_packages_with_findings"], 1)
        self.assertEqual(result["summary"]["sdk_packages_with_version_drift"], 1)
        self.assertEqual(result["summary"]["sdk_distinct_advisories"], 1)
        self.assertEqual(result["summary"]["sdk_advisory_observations"], 1)
        self.assertEqual(result["summary"]["sdk_advisories_with_import_evidence"], 1)
        self.assertEqual(result["summary"]["sdk_advisories_in_executable_imports"], 1)
        self.assertEqual(result["summary"]["sdk_advisories_with_focused_tests"], 1)
        self.assertEqual(
            result["summary"]["sdk_advisories_with_import_path_owners"], 1
        )
        self.assertEqual(
            result["summary"]["sdk_advisories_with_uncovered_import_paths"], 1
        )
        self.assertEqual(
            result["summary"]["sdk_advisories_with_test_coverage_mismatch"], 1
        )
        self.assertTrue(
            any("GHSA-DEMO" in step for step in assessment["verification_steps"])
        )
        rendered = "\n".join(_render_data_exposure_summary(result))
        detailed = "\n".join(_markdown_data_exposure_context(exposure))
        self.assertIn("SDK packages sentry-sdk", rendered)
        self.assertIn(
            "1 distinct advisories / 1 observations via osv-scanner", rendered
        )
        self.assertIn("advisories GHSA-DEMO", rendered)
        self.assertIn("use executable-import, direct dependency", rendered)
        self.assertIn("focused tests tests/test\\_app.py", rendered)
        self.assertIn("test/coverage alignment coverage-gap", rendered)
        self.assertIn("owners @observability", rendered)
        self.assertIn("SDK dependency cross-reference", detailed)
        self.assertIn("[GHSA-DEMO](https://example.invalid/GHSA-DEMO)", detailed)
        schema = json.loads(read_bundled_schema("data-exposure-1.5"))
        Draft202012Validator(schema).validate(result)

    def test_matched_sdk_lineage_without_package_findings_is_not_risk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import sentry_sdk\nsentry_sdk.capture_message('status')\n",
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text(
                '[project]\nname = "demo"\nversion = "1"\n'
                'dependencies = ["sentry-sdk>=2"]\n',
                encoding="utf-8",
            )
            result = build_data_exposure_synthesis(root, [], {})
            apply_data_exposure_fusion(
                result,
                [],
                {
                    "package_lineage": [
                        {
                            "package": "sentry-sdk",
                            "source_versions": ["2.0"],
                            "artifact_versions": ["2.0"],
                            "status": "matched",
                            "finding_ids": [],
                        }
                    ]
                },
            )

        dependency = result["sink_surfaces"][0]["sdk_dependency_context"]
        self.assertTrue(dependency["context_available"])
        self.assertFalse(dependency["risk_present"])
        self.assertEqual(dependency["risk_tier"], "none")
        self.assertEqual(result["summary"]["sink_surfaces_with_sdk_package_risk"], 0)

    def test_stdout_surface_requires_sensitive_context_hint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "print('ordinary status')\nprint('token', 'synthetic')\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(result["summary"]["production_sink_surfaces"], 1)
        self.assertEqual(result["sink_surfaces"][0]["label"], "standard output")

    def test_recognizes_custom_loggers_request_payloads_and_process_streams(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\n"
                "import sys\n\n"
                "audit = logging.getLogger(__name__)\n"
                "payload = request.json()\n"
                "audit.info('request payload=%s', payload)\n"
                "sys.stderr.write(api_token)\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        labels = {item["label"] for item in result["sink_surfaces"]}
        self.assertIn("request data in structured log", labels)
        self.assertIn("process output stream", labels)

    def test_response_data_is_not_mislabeled_as_http_request_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\n\n"
                "def summarize(embedding_response):\n"
                "    logging.info('dimensions=%s', len(embedding_response.data))\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(result["summary"]["production_sink_surfaces"], 1)
        self.assertEqual(result["sink_surfaces"][0]["label"], "log.info")

    def test_request_named_data_retains_request_payload_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\n\n"
                "def audit(incoming_request):\n"
                "    logging.info('payload=%s', incoming_request.data)\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(
            result["sink_surfaces"][0]["label"], "request data in structured log"
        )

    def test_propagates_data_classes_and_distinguishes_protection_kind(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\nimport os\n\n"
                "secret = os.getenv('PAYMENT_API_TOKEN')\n"
                "copied = secret\n"
                "logging.error('credential=%s', copied)\n"
                "safe = redact(copied)\n"
                "logging.info('credential=%s', safe)\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        unsafe, protected = result["sink_surfaces"]
        self.assertEqual(unsafe["data_classes"], ["credentials", "financial"])
        self.assertEqual(unsafe["review_priority"], "high")
        self.assertEqual(unsafe["protection_status"], "not-observed")
        self.assertIn("no-protection-observed", unsafe["risk_factors"])
        self.assertEqual(protected["protection_status"], "redacted-or-masked")
        self.assertEqual(protected["review_priority"], "medium")

    def test_prioritizes_broad_runtime_state_without_claiming_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\n\n"
                "def diagnose(settings):\n"
                "    logging.warning('state=%r', vars(settings))\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        surface = result["sink_surfaces"][0]
        self.assertIn("broad-runtime-state", surface["risk_factors"])
        self.assertEqual(surface["review_priority"], "high")
        self.assertEqual(result["summary"]["exposure_findings"], 0)

    def test_local_alias_context_does_not_leak_between_functions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\nimport os\n\n"
                "def load():\n"
                "    value = os.getenv('AUTH_TOKEN')\n"
                "    return value\n\n"
                "def report(value):\n"
                "    logging.info('value=%s', value)\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        surface = result["sink_surfaces"][0]
        self.assertEqual(surface["data_classes"], [])
        self.assertEqual(surface["review_priority"], "medium")

    def test_classifies_request_health_and_personal_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\n\n"
                "def audit(request):\n"
                "    patient_email = request.json()\n"
                "    logging.info('diagnosis=%s', patient_email)\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        surface = result["sink_surfaces"][0]
        self.assertEqual(
            surface["data_classes"], ["health", "personal", "request-content"]
        )
        self.assertIn("full-request-content", surface["risk_factors"])
        self.assertEqual(surface["trust_boundary"], "operational-data-plane")
        self.assertTrue(
            any("synthetic" in step for step in surface["verification_steps"])
        )

    def test_cross_references_inventory_surface_with_structure_tests_and_findings(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "import logging\n\n"
                "def report(value):\n"
                "    value = normalize(value)\n"
                "    logging.info('value=%s', value)\n",
                encoding="utf-8",
            )
            nearby = _finding(
                path="src/app.py",
                line=5,
                classifications=["CWE-78"],
                rule_id="B602",
            )
            nearby.area = "injection"
            nearby.evidence["owners"] = ["@security-team"]
            artifacts = {
                "coverage-summary.json": {
                    "files": [
                        {
                            "path": "src/app.py",
                            "missing_lines": [5],
                            "summary": {"percent_covered": 40.0},
                        }
                    ]
                },
                "diff-coverage.json": {
                    "src_stats": {
                        "src/app.py": {
                            "covered_lines": [],
                            "violation_lines": [5],
                            "percent_covered": 0.0,
                        }
                    }
                },
                "reachability.json": {
                    "nodes": [
                        {
                            "path": "src/app.py",
                            "start_line": 3,
                            "end_line": 5,
                            "state": "executable",
                            "runtime_observation": "observed",
                        }
                    ]
                },
                "graphify.json": {
                    "topology": {
                        "file_edges": [
                            {
                                "source": "src/cli.py",
                                "target": "src/app.py",
                                "relation": "calls",
                            },
                            {
                                "source": "src/api.py",
                                "target": "src/app.py",
                                "relation": "imports",
                            },
                        ]
                    }
                },
                "structural-synthesis.json": {
                    "change_impact_assessments": [
                        {
                            "path": "src/app.py",
                            "priority": "high",
                            "risk_score": 85,
                            "classification": "changed-lines-under-tested",
                            "direct_test_files": ["tests/test_app.py"],
                            "transitive_test_files": [],
                            "associated_test_files": [],
                            "test_selection_confidence": "high",
                            "focused_test_validation_status": "passed",
                            "test_coverage_alignment": "coverage-gap",
                            "validation_gap_reasons": [
                                "Focused tests passed, but changed lines were uncovered."
                            ],
                            "validation_action": "Extend the focused application tests.",
                            "recommended_action": "Run the focused application tests.",
                        }
                    ],
                    "island_assessments": [],
                    "import_cycles": [
                        {
                            "cycle_id": "cycle-app",
                            "paths": ["src/app.py", "src/dependency.py"],
                            "priority": "high",
                            "recommended_action": "Break the import cycle.",
                        }
                    ],
                },
            }

            result = build_data_exposure_synthesis(root, [nearby], artifacts)

        self.assertEqual(result["summary"]["exposure_findings"], 0)
        self.assertEqual(result["summary"]["structurally_enriched_surfaces"], 1)
        self.assertEqual(result["summary"]["changed_sink_surfaces"], 1)
        self.assertEqual(result["summary"]["uncovered_sink_surfaces"], 1)
        self.assertEqual(result["summary"]["runtime_observed_sink_surfaces"], 1)
        self.assertEqual(result["summary"]["compound_sink_surfaces"], 1)
        self.assertEqual(result["summary"]["owned_sink_surfaces"], 1)
        self.assertEqual(result["summary"]["sink_surfaces_with_mapped_tests"], 1)
        self.assertEqual(
            result["summary"]["sink_surfaces_with_validation_mismatch"], 1
        )
        self.assertEqual(result["summary"]["high_change_risk_sink_surfaces"], 1)
        self.assertEqual(result["summary"]["sink_surfaces_in_structural_hotspots"], 1)
        surface = result["sink_surfaces"][0]
        context = surface["structural_context"]
        self.assertTrue(context["changed_line"])
        self.assertFalse(context["line_covered"])
        self.assertEqual(context["reachability_states"], ["executable"])
        self.assertEqual(context["runtime_observations"], ["observed"])
        self.assertEqual(context["graph_upstream_files"], 2)
        self.assertEqual(context["related_finding_ids"], ["PYSEC-EXPOSURE"])
        self.assertEqual(context["owners"], ["@security-team"])
        self.assertEqual(context["mapped_test_files"], ["tests/test_app.py"])
        self.assertEqual(context["change_risk_score"], 85)
        self.assertEqual(context["change_risk_priority"], "high")
        self.assertEqual(context["focused_test_validation_status"], "passed")
        self.assertEqual(context["test_coverage_alignment"], "coverage-gap")
        self.assertEqual(context["structural_risk_ids"], ["cycle-app"])
        self.assertEqual(surface["review_priority"], "high")
        self.assertTrue(
            any("focused test" in step for step in surface["verification_steps"])
        )
        self.assertTrue(
            any("graph-selected" in step for step in surface["verification_steps"])
        )
        rendered = "\n".join(_render_data_exposure_summary(result))
        self.assertIn("Sink surfaces joined with structural/test context | 1", rendered)
        self.assertIn("runtime observed", rendered)
        self.assertIn("nearby PYSEC-EXPOSURE via semgrep", rendered)
        self.assertIn("owner @security-team", rendered)
        self.assertIn("mapped tests/test\\_app.py", rendered)
        self.assertIn("validation coverage-gap", rendered)
        self.assertIn("Add a focused test", rendered)
        schema = json.loads(read_bundled_schema("data-exposure-1.5"))
        Draft202012Validator(schema).validate(result)

    def test_inventories_query_exception_and_risky_sdk_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import os\n"
                "import requests\n"
                "import sentry_sdk\n"
                "from fastapi import HTTPException\n\n"
                "sentry_sdk.init(send_default_pii=True, before_send=redact_event)\n"
                "requests.get('https://example.invalid', params={'token': api_token})\n"
                "try:\n"
                "    work()\n"
                "except Exception as error:\n"
                "    raise HTTPException(status_code=500, detail=str(error))\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        by_label = {item["label"]: item for item in result["sink_surfaces"]}
        self.assertTrue(
            by_label["automatic PII collection enabled"]["sanitizer_visible"]
        )
        self.assertIn("sensitive HTTP query parameters", by_label)
        self.assertIn("raw exception in HTTP response", by_label)

    def test_inventories_broad_opentelemetry_header_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import os\n"
                "os.environ[\n"
                "    'OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST'\n"
                "] = '.*'\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(len(result["sink_surfaces"]), 1)
        self.assertEqual(
            result["sink_surfaces"][0]["label"],
            "broad OpenTelemetry HTTP header capture",
        )

    def test_inventories_capture_configuration_outside_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".env").write_text(
                "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY\n"
                "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST=.*\n",
                encoding="utf-8",
            )
            (root / "service.toml").write_text(
                'OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT = "true"\n',
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        labels = [item["label"] for item in result["sink_surfaces"]]
        self.assertIn("GenAI message content capture enabled", labels)
        self.assertIn("invalid GenAI content-capture mode", labels)
        self.assertIn("broad OpenTelemetry HTTP header capture", labels)
        self.assertEqual(result["summary"]["configuration_review_surfaces"], 3)

    def test_inventories_genai_capture_setdefault_and_putenv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import os\n"
                "os.environ.setdefault(\n"
                "    'OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT',\n"
                "    'EVENT_ONLY',\n"
                ")\n"
                "os.putenv(\n"
                "    'OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT',\n"
                "    'true',\n"
                ")\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        labels = {item["label"] for item in result["sink_surfaces"]}
        self.assertIn("GenAI message content capture enabled", labels)
        self.assertIn("invalid GenAI content-capture mode", labels)

    def test_inventories_nested_manifests_requirements_and_cloud_sdks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "packages" / "worker"
            package.mkdir(parents=True)
            (package / "pyproject.toml").write_text(
                "[project]\nname = 'worker'\nversion = '1'\n"
                "dependencies = ['azure-monitor-opentelemetry>=1']\n"
                "[project.optional-dependencies]\n"
                "observability = ['langfuse>=3']\n",
                encoding="utf-8",
            )
            (root / "requirements-observability.txt").write_text(
                "google-cloud-logging==3.12.1\n",
                encoding="utf-8",
            )
            (package / "app.py").write_text(
                "from google.cloud import logging as cloud_logging\n"
                "import phoenix as px\n"
                "cloud_logging.Client()\n"
                "px.Client()\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        sdks = {item["sdk"] for item in result["sdk_observations"]}
        self.assertIn("Azure Monitor OpenTelemetry", sdks)
        self.assertIn("Langfuse", sdks)
        self.assertIn("Google Cloud Logging", sdks)
        self.assertIn("Arize Phoenix", sdks)

    def test_enriches_supported_finding_with_sdk_and_security_practice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "import os\n"
                "import sentry_sdk\n\n"
                "token = os.getenv('AUTH_TOKEN')\n"
                "sentry_sdk.set_context('request', {'token': token})\n",
                encoding="utf-8",
            )
            finding = _finding(line=5)

            result = build_data_exposure_synthesis(
                root,
                [finding],
                {"graphify.json": {}, "reachability.json": {}},
            )

        assessment = result["finding_assessments"][0]
        self.assertEqual(assessment["sink_family"], "error-monitoring")
        self.assertEqual(assessment["sdk"], "Sentry SDK")
        self.assertEqual(assessment["confidence"], "high")
        self.assertEqual(
            finding.evidence["data_exposure"]["concern"],
            "sensitive-information-in-sent-data",
        )
        self.assertIn(
            "CWE-201", {citation.identifier for citation in finding.citations}
        )

    def test_logging_finding_gets_cwe_and_owasp_citations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "import logging\nimport os\n\n"
                "token = os.getenv('AUTH_TOKEN')\n"
                "logging.error('token=%s', token)\n",
                encoding="utf-8",
            )
            finding = _finding(
                line=5,
                classifications=["CWE-532", "CWE-200"],
                rule_id="python.sensitive-data-to-log",
            )

            build_data_exposure_synthesis(root, [finding], {})

        identifiers = {citation.identifier for citation in finding.citations}
        self.assertIn("CWE-532", identifiers)
        self.assertIn("OWASP-LOGGING", identifiers)
        self.assertEqual(finding.evidence["data_exposure"]["sink_family"], "logging")

    def test_private_data_keeps_distinct_privacy_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            finding = _finding(
                classifications=["CWE-201", "CWE-359"],
                rule_id="python.private-data-to-telemetry",
            )

            result = build_data_exposure_synthesis(root, [finding], {})

        self.assertEqual(
            finding.evidence["data_exposure"]["concern"], "private-data-exposure"
        )
        self.assertEqual(result["finding_assessments"][0]["data_classes"], ["personal"])
        self.assertIn(
            "CWE-359", {citation.identifier for citation in finding.citations}
        )

    def test_url_query_finding_gets_specific_action_and_citation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "import os\nimport requests\n\n"
                "token = os.getenv('API_KEY')\n"
                "requests.get('https://example.invalid', params={'token': token})\n",
                encoding="utf-8",
            )
            finding = _finding(
                line=5,
                classifications=["CWE-598", "CWE-200"],
                rule_id="python.sensitive-data-in-url-query",
            )

            result = build_data_exposure_synthesis(root, [finding], {})

        assessment = result["finding_assessments"][0]
        self.assertEqual(assessment["sink_family"], "url-query")
        self.assertEqual(assessment["concern"], "sensitive-data-in-url-query")
        self.assertIn("browser history", assessment["recommended_action"])
        self.assertIn(
            "CWE-598", {citation.identifier for citation in finding.citations}
        )

    def test_inventories_dynamic_sensitive_url_without_static_name_false_positive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import os\nimport requests\n\n"
                "token = os.getenv('API_TOKEN')\n"
                "requests.get(f'https://example.invalid/check?token={token}')\n"
                "requests.get('https://example.invalid/tokenize')\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        dynamic, static = result["sink_surfaces"]
        self.assertEqual(dynamic["sink_family"], "url")
        self.assertEqual(dynamic["review_priority"], "high")
        self.assertIn("url-propagation", dynamic["risk_factors"])
        self.assertEqual(static["sink_family"], "network-egress")
        self.assertEqual(static["data_classes"], [])

    def test_ignores_unrelated_quality_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            finding = _finding(classifications=["CWE-78"], rule_id="B602")
            finding.area = "logging"

            result = build_data_exposure_synthesis(root, [finding], {})

        self.assertEqual(result["finding_assessments"], [])
        self.assertNotIn("data_exposure", finding.evidence)

    def test_artifact_validates_against_bundled_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = build_data_exposure_synthesis(Path(temporary), [], {})
        schema = json.loads(read_bundled_schema("data-exposure-1.5"))
        Draft202012Validator(schema).validate(result)

    def test_joins_finalized_fusion_into_exposure_verification_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "import logging\nimport os\n\n"
                "token = os.getenv('AUTH_TOKEN')\n"
                "logging.error('token=%s', token)\n",
                encoding="utf-8",
            )
            finding = _finding(
                line=5,
                classifications=["CWE-532"],
                rule_id="python.sensitive-data-to-log",
            )
            finding.evidence["owners"] = ["@privacy-team"]
            result = build_data_exposure_synthesis(root, [finding], {})
            finding.evidence["fusion"] = {
                "review_tier": "urgent",
                "corroboration": "contextual",
                "review_reasons": [
                    "finding is on a changed line",
                    "finding line lacks retained test coverage",
                ],
                "related_finding_ids": ["PYSEC-RELATED"],
                "related_tools": ["graphify", "reachability"],
                "source_context": {
                    "changed_line": True,
                    "line_covered": False,
                    "coverage_percent": 65.4,
                    "diff_coverage_percent": 0.0,
                    "reachability_states": ["executable"],
                    "runtime_observations": ["observed"],
                    "graph_upstream_files": 12,
                    "graph_downstream_files": 3,
                    "graph_degree": 8,
                },
                "structural_context": {
                    "change_impact": {
                        "priority": "high",
                        "risk_score": 90,
                        "classification": "changed-lines-under-tested",
                        "direct_test_files": ["tests/test_app.py"],
                        "transitive_test_files": [],
                        "associated_test_files": [],
                        "test_selection_confidence": "high",
                        "focused_test_validation_status": "passed",
                        "test_coverage_alignment": "coverage-gap",
                        "validation_gap_reasons": [
                            "Focused tests passed, but the finding line was uncovered."
                        ],
                        "validation_action": "Extend the focused test.",
                        "recommended_action": "Run and extend the focused test.",
                    },
                    "import_cycle": {
                        "cycle_id": "cycle-app",
                        "priority": "high",
                    },
                },
            }

            apply_data_exposure_fusion(result, [finding])

        assessment = result["finding_assessments"][0]
        cross = assessment["cross_references"]
        self.assertEqual(assessment["triage_tier"], "urgent")
        self.assertTrue(cross["fusion_available"])
        self.assertFalse(cross["line_covered"])
        self.assertEqual(cross["reachability_states"], ["executable"])
        self.assertIn("PYSEC-RELATED", cross["related_finding_ids"])
        self.assertEqual(cross["owners"], ["@privacy-team"])
        self.assertEqual(cross["mapped_test_files"], ["tests/test_app.py"])
        self.assertEqual(cross["change_risk_score"], 90)
        self.assertEqual(cross["structural_risk_ids"], ["cycle-app"])
        self.assertEqual(cross["structural_risk_kinds"], ["import-cycle:high"])
        self.assertTrue(
            any(
                "synthetic credential" in step
                for step in assessment["verification_steps"]
            )
        )
        self.assertTrue(
            any("graph-guided" in step for step in assessment["verification_steps"])
        )
        self.assertEqual(result["summary"]["fusion_enriched_findings"], 1)
        self.assertEqual(result["summary"]["urgent_cross_referenced_findings"], 1)
        self.assertEqual(result["summary"]["uncovered_exposure_findings"], 1)
        self.assertEqual(result["summary"]["runtime_observed_exposure_findings"], 1)
        self.assertEqual(result["summary"]["owned_exposure_findings"], 1)
        self.assertEqual(result["summary"]["exposure_findings_with_mapped_tests"], 1)
        self.assertEqual(
            result["summary"]["exposure_findings_with_validation_mismatch"], 1
        )
        self.assertEqual(result["summary"]["high_change_risk_exposure_findings"], 1)
        summary_markdown = "\n".join(_render_data_exposure_summary(result))
        finding_markdown = "\n".join(_markdown_data_exposure_context(finding))
        self.assertIn(
            "Findings joined with finalized evidence fusion | 1", summary_markdown
        )
        self.assertIn("`urgent` / credentials", summary_markdown)
        self.assertIn(
            "owners @privacy-team; mapped tests/test\\_app.py", summary_markdown
        )
        self.assertIn("structural import-cycle:high", summary_markdown)
        self.assertIn("validation coverage-gap", summary_markdown)
        self.assertIn("joined evidence `fusion urgent", finding_markdown)
        self.assertIn("owners @privacy-team", finding_markdown)
        self.assertIn("mapped tests tests/test_app.py", finding_markdown)
        self.assertIn("Exposure verification", finding_markdown)
        schema = json.loads(read_bundled_schema("data-exposure-1.5"))
        Draft202012Validator(schema).validate(result)

    def test_not_observed_runtime_signal_does_not_count_as_runtime_observed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            finding = _finding()
            result = build_data_exposure_synthesis(root, [finding], {})
            finding.evidence["fusion"] = {
                "review_tier": "elevated",
                "corroboration": "contextual",
                "source_context": {
                    "reachability_states": ["executable"],
                    "runtime_observations": ["not-observed"],
                },
            }

            apply_data_exposure_fusion(result, [finding])

        self.assertEqual(result["summary"]["runtime_observed_exposure_findings"], 0)
        steps = result["finding_assessments"][0]["verification_steps"]
        self.assertFalse(any("observed path" in step for step in steps))
        self.assertTrue(any("modeled entry-point" in step for step in steps))

    def test_portable_reports_render_exposure_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "import logging\nimport os\n\n"
                "token = os.getenv('AUTH_TOKEN')\n"
                "logging.error('token=%s', token)\n",
                encoding="utf-8",
            )
            finding = _finding(
                line=5,
                classifications=["CWE-532"],
                rule_id="python.sensitive-data-to-log",
            )
            result = build_data_exposure_synthesis(root, [finding], {})

        summary = "\n".join(_render_data_exposure_summary(result))
        context = "\n".join(_markdown_data_exposure_context(finding))
        sonar = render_sonarqube_external_issues([finding])
        sarif = render_sarif([finding])
        self.assertIn("Sensitive-data exposure", summary)
        self.assertIn("sensitive-information-in-logs", context)
        self.assertIn(
            "Sensitive-data path",
            sonar["issues"][0]["primaryLocation"]["message"],
        )
        self.assertIn("data_exposure", sarif["runs"][0]["results"][0]["properties"])


if __name__ == "__main__":
    unittest.main()
