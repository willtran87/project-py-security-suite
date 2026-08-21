from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.adapters.sarif import parse_sarif_findings
from py_security_suite.advanced_delta import (
    compare_advanced_analysis,
    render_advanced_delta_markdown,
)
from py_security_suite.advanced_analysis import build_advanced_analysis
from py_security_suite.models import (
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    json_ready,
)
from py_security_suite.report_inspection import read_bundled_schema
from py_security_suite.reports import render_sarif


class AdvancedAnalysisTests(unittest.TestCase):
    def test_cross_evidence_analysis_detects_bypass_and_preserves_taint_path(
        self,
    ) -> None:
        finding = _finding("PYSEC-FLOW", "codeql", "src/sink.py")
        finding.evidence["sarif_code_flows"] = [
            {
                "tool": "codeql",
                "semantic_basis": "security-path-problem",
                "step_count": 3,
                "steps": [
                    {"path": "src/entry.py", "line": 3, "message": "user input"},
                    {"path": "src/auth.py", "line": 7, "message": "validate"},
                    {"path": "src/sink.py", "line": 9, "message": "send"},
                ],
            }
        ]
        artifacts = _artifacts()

        result = build_advanced_analysis(Path.cwd(), [finding], artifacts)

        control = result["control_topology"][0]
        self.assertEqual(control["path"], "src/auth.py")
        self.assertEqual(control["topology_status"], "bypass-capable")
        self.assertEqual(result["summary"]["bypass_capable_control_points"], 1)
        self.assertEqual(result["summary"]["scanner_confirmed_taint_paths"], 1)
        self.assertEqual(
            result["taint_paths"][0]["classification"],
            "scanner-confirmed-source-to-sink",
        )
        self.assertEqual(result["taint_paths"][0]["route_alignment"], "aligned")
        self.assertTrue(result["telemetry_privacy_topology"])
        self.assertTrue(result["dependency_trust_routes"])
        schema = json.loads(read_bundled_schema("advanced-analysis-1.0"))
        Draft202012Validator(schema).validate(result)

    def test_artifact_entry_point_and_record_are_projected_into_source_model(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            wheel = target / "dist" / "demo-1.0-py3-none-any.whl"
            wheel.parent.mkdir()
            _write_wheel(wheel)
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            artifacts = _artifacts()
            artifacts["artifact-manifest.json"] = {
                "schema_version": "1.0",
                "artifacts": [
                    {
                        "path": "dist/demo-1.0-py3-none-any.whl",
                        "sha256": digest,
                        "size_bytes": wheel.stat().st_size,
                    }
                ],
            }
            result = build_advanced_analysis(target, [], artifacts)

        parity = result["artifact_route_parity"][0]
        self.assertEqual(parity["analysis_status"], "complete")
        self.assertEqual(parity["summary"]["record_integrity_gaps"], 0)
        self.assertEqual(parity["summary"]["unmodeled_entry_points"], 1)
        self.assertEqual(
            parity["published_entry_points"][0]["parity_status"],
            "graph-member-not-entry-modeled",
        )

    def test_wheel_structure_rejects_ambiguous_and_unsafe_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            wheel = target / "dist" / "demo-1.0-py3-none-any.whl"
            wheel.parent.mkdir()
            _write_wheel(wheel)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(wheel, "a") as archive:
                    archive.writestr("demo/cli.py", b"shadowed = True\n")
                    archive.writestr("demo/CLI.py", b"case_collision = True\n")
                    archive.writestr("../escape.py", b"escape = True\n")
                    archive.writestr("demo\\ambiguous.py", b"ambiguous = True\n")
                    link = zipfile.ZipInfo("demo/link.py")
                    link.create_system = 3
                    link.external_attr = 0o120777 << 16
                    archive.writestr(link, b"cli.py")
            artifacts = _artifacts()
            artifacts["artifact-manifest.json"] = {
                "schema_version": "1.0",
                "artifacts": [
                    {
                        "path": "dist/demo-1.0-py3-none-any.whl",
                        "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                        "size_bytes": wheel.stat().st_size,
                    }
                ],
            }

            result = build_advanced_analysis(target, [], artifacts)

        parity = result["artifact_route_parity"][0]
        kinds = {item["kind"] for item in parity["record_gaps"]}
        self.assertTrue(
            {
                "case-colliding-members",
                "duplicate-member-name",
                "symbolic-link-member",
                "unsafe-member-name",
            }.issubset(kinds)
        )
        self.assertGreaterEqual(parity["summary"]["record_integrity_gaps"], 4)

    def test_wheel_record_accepts_stronger_hashes_and_rejects_unsigned_rows(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            wheel = target / "dist" / "demo-1.0-py3-none-any.whl"
            wheel.parent.mkdir()
            _write_wheel(
                wheel,
                record_algorithm="sha384",
                unsigned_path="demo/cli.py",
                duplicate_record_path="demo/cli.py",
            )
            artifacts = _artifacts()
            artifacts["artifact-manifest.json"] = {
                "schema_version": "1.0",
                "artifacts": [
                    {
                        "path": "dist/demo-1.0-py3-none-any.whl",
                        "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                        "size_bytes": wheel.stat().st_size,
                    }
                ],
            }

            result = build_advanced_analysis(target, [], artifacts)

        gaps = result["artifact_route_parity"][0]["record_gaps"]
        kinds = {item["kind"] for item in gaps}
        self.assertIn("duplicate-record-row", kinds)
        self.assertIn("missing-record-hash", kinds)
        self.assertIn("missing-record-size", kinds)
        self.assertNotIn("unsupported-record-hash", kinds)
        self.assertNotIn("record-hash-mismatch", kinds)

    def test_control_dominance_is_scoped_to_route_entry_identity(self) -> None:
        artifacts = _artifacts()
        artifacts["graphify.json"]["nodes"].append({"path": "src/other.py"})
        artifacts["graphify.json"]["topology"]["file_edges"] = [
            {"source": "src/entry.py", "target": "src/auth.py"},
            {"source": "src/auth.py", "target": "src/sink.py"},
            {"source": "src/other.py", "target": "src/sink.py"},
        ]
        artifacts["reachability.json"]["entry_points"].append(
            {"id": "entry:other", "path": "src/other.py"}
        )

        scoped = build_advanced_analysis(Path.cwd(), [], artifacts)

        self.assertEqual(scoped["control_topology"][0]["topology_status"], "mandatory")

        artifacts["risk-paths.json"]["routes"][0]["entry_point_exposures"].append(
            {
                "entry_point": {"id": "entry:other"},
                "files": ["src/other.py", "src/sink.py"],
            }
        )
        multi_entry = build_advanced_analysis(Path.cwd(), [], artifacts)

        self.assertEqual(
            multi_entry["control_topology"][0]["topology_status"],
            "bypass-capable",
        )

    def test_control_dominance_is_unknown_when_route_entry_cannot_be_mapped(
        self,
    ) -> None:
        artifacts = _artifacts()
        artifacts["risk-paths.json"]["routes"][0]["entry_point_exposures"].append(
            {
                "entry_point": {"id": "entry:missing"},
                "files": ["src/entry.py", "src/auth.py", "src/sink.py"],
            }
        )

        result = build_advanced_analysis(Path.cwd(), [], artifacts)

        control = result["control_topology"][0]
        self.assertEqual(control["topology_status"], "not-established")
        self.assertIn("could not be mapped", control["interpretation"])
        schema = json.loads(read_bundled_schema("advanced-analysis-1.0"))
        Draft202012Validator(schema).validate(result)

    def test_sarif_retains_bounded_code_flow_without_snippets(self) -> None:
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "py/flow",
                                        "shortDescription": {"text": "Flow"},
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/flow",
                                "level": "error",
                                "message": {"text": "source reaches sink"},
                                "locations": [_sarif_location("src/sink.py", 9)],
                                "codeFlows": [
                                    {
                                        "threadFlows": [
                                            {
                                                "locations": [
                                                    {
                                                        "location": _sarif_location(
                                                            "src/sink.py", 9
                                                        ),
                                                        "message": {"text": "sink"},
                                                        "executionOrder": 20,
                                                        "importance": "essential",
                                                        "kinds": ["sink"],
                                                    },
                                                    {
                                                        "location": _sarif_location(
                                                            "src/source.py", 3
                                                        ),
                                                        "message": {"text": "source"},
                                                        "executionOrder": 10,
                                                        "nestingLevel": 1,
                                                        "kinds": ["source"],
                                                    },
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )

        finding = parse_sarif_findings(
            payload,
            Path.cwd(),
            tool_name="codeql",
            default_area="data-flow",
            default_impact="impact",
            default_remediation="fix",
        )[0]

        flow = finding.evidence["sarif_code_flows"][0]
        self.assertEqual(flow["step_count"], 2)
        self.assertEqual(flow["steps"][0]["path"], "src/source.py")
        self.assertEqual(flow["steps"][0]["execution_order"], 10)
        self.assertEqual(flow["steps"][0]["nesting_level"], 1)
        self.assertEqual(flow["steps"][0]["kinds"], ["source"])
        self.assertEqual(flow["steps"][1]["importance"], "essential")
        self.assertEqual(flow["steps"][1]["kinds"], ["sink"])
        self.assertEqual(flow["semantic_basis"], "native-source-sink-kinds")
        self.assertNotIn("snippet", flow["steps"][0])

    def test_sarif_secondary_location_corroborates_native_sink_alignment(
        self,
    ) -> None:
        payload = json.dumps(
            {
                "runs": [
                    {
                        "originalUriBaseIds": {
                            "ROOT": {"uri": "./"},
                            "SRC": {"uri": "src/", "uriBaseId": "ROOT"},
                        },
                        "artifacts": [
                            {"location": {"uri": "wrapper.py", "uriBaseId": "SRC"}},
                            {"location": {"uri": "sink.py", "uriBaseId": "SRC"}},
                            {"location": {"uri": "entry.py", "uriBaseId": "SRC"}},
                        ],
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "py/multi-location-flow",
                                        "properties": {"kind": "path-problem"},
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/multi-location-flow",
                                "message": {"text": "source reaches sink"},
                                "locations": [
                                    _sarif_indexed_location(0, 5),
                                    _sarif_indexed_location(1, 9),
                                ],
                                "codeFlows": [
                                    {
                                        "threadFlows": [
                                            {
                                                "locations": [
                                                    {
                                                        "location": _sarif_indexed_location(
                                                            2, 3
                                                        ),
                                                        "kinds": ["source"],
                                                    },
                                                    {
                                                        "location": _sarif_indexed_location(
                                                            1, 9
                                                        ),
                                                        "kinds": ["sink"],
                                                    },
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )
        finding = parse_sarif_findings(
            payload,
            Path.cwd(),
            tool_name="codeql",
            default_area="data-flow",
            default_impact="impact",
            default_remediation="fix",
        )[0]
        artifacts = _artifacts()
        artifacts["risk-paths.json"]["routes"][0]["target"]["finding_id"] = (
            finding.finding_id
        )

        result = build_advanced_analysis(Path.cwd(), [finding], artifacts)
        portable = render_sarif([finding])["runs"][0]["results"][0]

        self.assertEqual(
            [(location.path, location.start_line) for location in finding.locations],
            [("src/wrapper.py", 5), ("src/sink.py", 9)],
        )
        self.assertEqual(
            finding.evidence["sarif_location_summary"],
            {
                "reported_count": 2,
                "retained_count": 2,
                "duplicate_count": 0,
                "invalid_count": 0,
                "limit_omitted_count": 0,
                "omitted_count": 0,
                "truncated": False,
                "path_resolution_counts": {"artifact-index-resolved": 2},
            },
        )
        self.assertEqual(result["taint_paths"][0]["route_alignment"], "aligned")
        self.assertEqual(
            finding.evidence["sarif_code_flows"][0]["steps"][0]["path_resolution"],
            "artifact-index-resolved",
        )
        self.assertEqual(
            [
                location["physicalLocation"]["artifactLocation"]["uri"]
                for location in portable["locations"]
            ],
            ["src/wrapper.py", "src/sink.py"],
        )
        self.assertEqual(
            portable["properties"]["sarif_location_summary"]["retained_count"],
            2,
        )
        self.assertEqual(
            portable["properties"]["sarif_result_semantics"]["kind"], "fail"
        )
        self.assertEqual(
            portable["properties"]["sarif_rule_reference"],
            {"basis": "rule-id", "rule_index": None, "metadata_resolved": True},
        )
        self.assertEqual(
            portable["properties"]["sarif_message_reference"]["basis"],
            "inline-text",
        )

    def test_sarif_sanitizes_finding_and_flow_messages_before_normalization(
        self,
    ) -> None:
        result_secret = "result_secret_must_not_survive"
        bearer_secret = "bearer_secret_must_not_survive"
        userinfo_secret = "user:password_must_not_survive"
        uri_secret = "uri_user:uri_password_must_not_survive"
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "py/secret-flow",
                                        "shortDescription": {"text": "Secret flow"},
                                        "properties": {"kind": "path-problem"},
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/secret-flow",
                                "message": {"text": f"token={result_secret}"},
                                "locations": [_sarif_location("src/sink.py", 9)],
                                "codeFlows": [
                                    {
                                        "threadFlows": [
                                            {
                                                "locations": [
                                                    {
                                                        "location": _sarif_location(
                                                            "src/source.py", 3
                                                        ),
                                                        "message": {
                                                            "text": "Authorization: Bearer "
                                                            + bearer_secret
                                                        },
                                                        "kinds": ["source"],
                                                    },
                                                    {
                                                        "location": _sarif_location(
                                                            "https://"
                                                            + uri_secret
                                                            + "@example.test/sink.py",
                                                            9,
                                                        ),
                                                        "message": {
                                                            "text": "send https://"
                                                            + userinfo_secret
                                                            + "@example.test/path"
                                                        },
                                                        "kinds": ["sink"],
                                                    },
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )

        finding = parse_sarif_findings(
            payload,
            Path.cwd(),
            tool_name="codeql",
            default_area="data-flow",
            default_impact="impact",
            default_remediation="fix",
        )[0]
        serialized = json.dumps(json_ready(finding))

        self.assertNotIn(result_secret, serialized)
        self.assertNotIn(bearer_secret, serialized)
        self.assertNotIn(userinfo_secret, serialized)
        self.assertNotIn(uri_secret, serialized)
        self.assertIn("<redacted>", serialized)
        self.assertEqual(
            finding.evidence["sarif_code_flows"][0]["steps"][1]["path"],
            "<external-artifact>",
        )
        self.assertEqual(
            finding.evidence["sarif_code_flows"][0]["semantic_basis"],
            "native-source-sink-kinds",
        )

    def test_secret_sarif_lane_redacts_unstructured_result_text(self) -> None:
        secrets = {
            "result": "unstructured-result-value-without-a-known-prefix",
            "title": "unstructured-title-value-without-a-known-prefix",
            "help": "unstructured-help-value-without-a-known-prefix",
            "impact": "unstructured-impact-value-without-a-known-prefix",
            "remediation": "unstructured-remediation-value-without-a-known-prefix",
            "flow": "unstructured-flow-value-without-a-known-prefix",
        }
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "secret-rule",
                                        "shortDescription": {"text": secrets["title"]},
                                        "help": {"text": secrets["help"]},
                                        "messageStrings": {
                                            "secret": {"text": "Detected value {0}"}
                                        },
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "secret-rule",
                                "message": {
                                    "id": "secret",
                                    "arguments": [secrets["result"]],
                                },
                                "locations": [_sarif_location("src/config.py", 4)],
                                "properties": {
                                    "impact": secrets["impact"],
                                    "remediation": secrets["remediation"],
                                },
                                "codeFlows": [
                                    {
                                        "threadFlows": [
                                            {
                                                "locations": [
                                                    {
                                                        "location": _sarif_location(
                                                            "src/config.py", 4
                                                        ),
                                                        "message": {
                                                            "text": secrets["flow"]
                                                        },
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )

        finding = parse_sarif_findings(
            payload,
            Path.cwd(),
            tool_name="gitleaks",
            default_area="secrets",
            default_impact="impact",
            default_remediation="fix",
        )[0]

        serialized = json.dumps(json_ready(finding))
        for secret in secrets.values():
            self.assertNotIn(secret, serialized)
        self.assertIn("sensitive scanner text", finding.description)

    def test_generic_quality_code_flow_is_not_promoted_to_taint(self) -> None:
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "py/quality-path",
                                        "properties": {
                                            "kind": "problem",
                                            "tags": ["maintainability"],
                                        },
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/quality-path",
                                "message": {"text": "generic control-flow path"},
                                "locations": [_sarif_location("src/sink.py", 9)],
                                "codeFlows": [
                                    {
                                        "threadFlows": [
                                            {
                                                "locations": [
                                                    {
                                                        "location": _sarif_location(
                                                            "src/entry.py", 3
                                                        )
                                                    },
                                                    {
                                                        "location": _sarif_location(
                                                            "src/sink.py", 9
                                                        )
                                                    },
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )
        finding = parse_sarif_findings(
            payload,
            Path.cwd(),
            tool_name="codeql",
            default_area="quality",
            default_impact="impact",
            default_remediation="fix",
        )[0]

        self.assertEqual(
            finding.evidence["sarif_code_flows"][0]["semantic_basis"],
            "unclassified-code-flow",
        )
        result = build_advanced_analysis(Path.cwd(), [finding], _artifacts())
        self.assertEqual(result["taint_paths"], [])

    def test_taint_route_alignment_requires_complete_ordered_endpoint_evidence(
        self,
    ) -> None:
        scenarios = (
            (
                "sink-only-overlap",
                [
                    {"path": "src/outside.py", "line": 3, "message": "source"},
                    {"path": "src/sink.py", "line": 9, "message": "sink"},
                ],
                None,
            ),
            (
                "route-order-conflict",
                [
                    {"path": "src/entry.py", "line": 3, "message": "source"},
                    {"path": "src/sink.py", "line": 9, "message": "sink"},
                ],
                ["src/sink.py", "src/entry.py"],
            ),
            (
                "sink-line-conflict",
                [
                    {"path": "src/entry.py", "line": 3, "message": "source"},
                    {"path": "src/sink.py", "line": 10, "message": "sink"},
                ],
                None,
            ),
        )
        for name, steps, exposure_files in scenarios:
            with self.subTest(name=name):
                finding = _finding("PYSEC-FLOW", "codeql", "src/sink.py")
                finding.evidence["sarif_code_flows"] = [
                    {
                        "tool": "codeql",
                        "semantic_basis": "security-path-problem",
                        "step_count": len(steps),
                        "steps": steps,
                    }
                ]
                artifacts = _artifacts()
                if exposure_files is not None:
                    artifacts["risk-paths.json"]["routes"][0]["entry_point_exposures"][
                        0
                    ]["files"] = exposure_files

                result = build_advanced_analysis(Path.cwd(), [finding], artifacts)

                self.assertEqual(
                    result["taint_paths"][0]["route_alignment"],
                    "not-established",
                )
                self.assertIn(
                    "do not treat the retained entry-route model as corroboration",
                    result["taint_paths"][0]["recommended_action"],
                )

    def test_contradictory_native_endpoint_markers_are_not_promoted(self) -> None:
        finding = _finding("PYSEC-FLOW", "codeql", "src/sink.py")
        finding.evidence["sarif_code_flows"] = [
            {
                "tool": "codeql",
                "step_count": 2,
                "steps": [
                    {
                        "path": "src/entry.py",
                        "line": 3,
                        "message": "marked sink first",
                        "kinds": ["sink"],
                    },
                    {
                        "path": "src/sink.py",
                        "line": 9,
                        "message": "marked source last",
                        "kinds": ["source"],
                    },
                ],
            }
        ]

        result = build_advanced_analysis(Path.cwd(), [finding], _artifacts())

        self.assertEqual(result["taint_paths"], [])

    def test_telemetry_redaction_requires_every_aligned_native_path(self) -> None:
        finding = _finding("PYSEC-FLOW", "codeql", "src/sink.py")
        finding.evidence["sarif_code_flows"] = [
            {
                "tool": "codeql",
                "semantic_basis": "native-source-sink-kinds",
                "step_count": 3,
                "steps": [
                    {
                        "path": "src/entry.py",
                        "line": 3,
                        "message": "catalog request",
                        "kinds": ["source"],
                    },
                    {
                        "path": "src/auth.py",
                        "line": 7,
                        "message": "privacy transform",
                        "kinds": ["sanitizer"],
                    },
                    {
                        "path": "src/sink.py",
                        "line": 9,
                        "message": "send",
                        "kinds": ["sink"],
                    },
                ],
            },
            {
                "tool": "codeql",
                "semantic_basis": "native-source-sink-kinds",
                "step_count": 2,
                "steps": [
                    {
                        "path": "src/entry.py",
                        "line": 3,
                        "message": "alternate source",
                        "kinds": ["source"],
                    },
                    {
                        "path": "src/sink.py",
                        "line": 9,
                        "message": "send",
                        "kinds": ["sink"],
                    },
                ],
            },
        ]
        artifacts = _artifacts()
        artifacts["graphify.json"]["topology"]["file_edges"] = artifacts[
            "graphify.json"
        ]["topology"]["file_edges"][:2]
        artifacts["risk-paths.json"]["sensitive_data_routes"][0][
            "protection_status"
        ] = "observed"

        result = build_advanced_analysis(Path.cwd(), [finding], artifacts)

        privacy = result["telemetry_privacy_topology"][0]
        self.assertEqual(
            privacy["redaction_order"],
            "redaction-not-on-all-confirmed-paths",
        )
        self.assertEqual(privacy["review_status"], "redaction-path-gap")
        self.assertEqual(privacy["redaction_evidence_basis"], ["native-step-kind"])
        self.assertEqual(
            [item["status"] for item in privacy["redaction_path_assessments"]],
            ["redaction-before-export", "redaction-not-observed"],
        )
        control = privacy["control_flow_assessments"][0]
        self.assertEqual(
            control["flow_observation_status"], "observed-on-some-aligned-paths"
        )
        self.assertEqual(
            result["summary"]["telemetry_routes_with_redaction_order_risk"], 1
        )
        self.assertTrue(
            any(
                edge["relationship"] == "observed-before-native-sink-on"
                for edge in result["evidence_graph"]["edges"]
            )
        )

    def test_telemetry_protection_is_not_claimed_without_native_correlation(
        self,
    ) -> None:
        finding = _finding("PYSEC-FLOW", "codeql", "src/sink.py")
        finding.evidence["sarif_code_flows"] = [
            {
                "tool": "codeql",
                "semantic_basis": "native-source-sink-kinds",
                "step_count": 3,
                "steps": [
                    {
                        "path": "src/entry.py",
                        "line": 3,
                        "kinds": ["source"],
                    },
                    {
                        "path": "src/privacy.py",
                        "line": 6,
                        "kinds": ["sanitizer"],
                    },
                    {
                        "path": "src/sink.py",
                        "line": 9,
                        "kinds": ["sink"],
                    },
                ],
            }
        ]
        artifacts = _artifacts()
        artifacts["graphify.json"]["topology"]["file_edges"] = artifacts[
            "graphify.json"
        ]["topology"]["file_edges"][:2]
        artifacts["risk-paths.json"]["routes"][0]["entry_point_exposures"][0][
            "files"
        ] = ["src/entry.py", "src/privacy.py", "src/sink.py"]
        artifacts["risk-paths.json"]["sensitive_data_routes"][0][
            "protection_status"
        ] = "observed"

        result = build_advanced_analysis(Path.cwd(), [finding], artifacts)

        privacy = result["telemetry_privacy_topology"][0]
        self.assertEqual(privacy["redaction_order"], "redaction-before-export")
        self.assertEqual(
            privacy["review_status"],
            "control-flow-correlation-not-established",
        )
        self.assertEqual(privacy["control_point_ids_observed_before_sink"], [])

    def test_telemetry_protected_decision_requires_native_sanitizer_semantics(
        self,
    ) -> None:
        scenarios: tuple[tuple[str, str, list[str], str, str, str], ...] = (
            (
                "unrelated-prefix",
                "sanity check",
                [],
                "not-established",
                "redaction-not-established",
                "none",
            ),
            (
                "heuristic-label",
                "sanitize telemetry value",
                [],
                "redaction-before-export",
                "redaction-effect-not-established",
                "heuristic-or-partial",
            ),
            (
                "native-kind",
                "privacy transform",
                ["sanitizer"],
                "redaction-before-export",
                "protected-static-route",
                "native-on-every-aligned-path",
            ),
        )
        for (
            name,
            marker_message,
            sanitizer_kinds,
            expected_order,
            expected_status,
            expected_quality,
        ) in scenarios:
            with self.subTest(name=name):
                finding = _finding("PYSEC-FLOW", "codeql", "src/sink.py")
                finding.evidence["sarif_code_flows"] = [
                    {
                        "tool": "codeql",
                        "semantic_basis": "security-path-problem",
                        "step_count": 3,
                        "steps": [
                            {
                                "path": "src/entry.py",
                                "line": 3,
                                "kinds": ["source"],
                            },
                            {
                                "path": "src/auth.py",
                                "line": 7,
                                "message": marker_message,
                                "kinds": sanitizer_kinds,
                            },
                            {
                                "path": "src/sink.py",
                                "line": 9,
                                "kinds": ["sink"],
                            },
                        ],
                    }
                ]
                artifacts = _artifacts()
                artifacts["graphify.json"]["topology"]["file_edges"] = artifacts[
                    "graphify.json"
                ]["topology"]["file_edges"][:2]
                artifacts["risk-paths.json"]["sensitive_data_routes"][0][
                    "protection_status"
                ] = "observed"

                result = build_advanced_analysis(Path.cwd(), [finding], artifacts)

                privacy = result["telemetry_privacy_topology"][0]
                self.assertEqual(privacy["redaction_order"], expected_order)
                self.assertEqual(privacy["review_status"], expected_status)
                self.assertEqual(
                    privacy["redaction_evidence_quality"], expected_quality
                )

    def test_threat_test_assurance_follows_control_campaign_and_source_identity(
        self,
    ) -> None:
        threat = _finding("PYTM-THREAT", "pytm", "src/sink.py")
        artifacts = _artifacts()

        selected_only = build_advanced_analysis(Path.cwd(), [threat], artifacts)

        trace = selected_only["threat_control_test_traceability"][0]
        self.assertEqual(trace["candidate_test_files"], ["tests/test_auth.py"])
        self.assertEqual(trace["verified_test_files"], [])
        self.assertEqual(
            trace["closure_status"],
            "control-without-current-passing-test-evidence",
        )
        self.assertEqual(selected_only["summary"]["threats_without_test_evidence"], 1)
        control = selected_only["control_topology"][0]
        self.assertEqual(control["candidate_test_files"], ["tests/test_auth.py"])
        self.assertEqual(control["test_files"], [])

        campaign = artifacts["risk-paths.json"]["validation_campaigns"][0]
        _add_source_bound_passing_campaign_evidence(campaign)
        current = build_advanced_analysis(Path.cwd(), [threat], artifacts)

        trace = current["threat_control_test_traceability"][0]
        self.assertEqual(trace["verified_test_files"], ["tests/test_auth.py"])
        self.assertEqual(trace["test_evidence_status"], "source-bound-passing")
        self.assertEqual(
            trace["closure_status"],
            "mapped-control-and-source-bound-passing-test-candidate",
        )
        self.assertEqual(trace["semantic_test_intent"], "not-established")
        self.assertEqual(current["summary"]["threats_without_test_evidence"], 0)
        self.assertTrue(
            any(
                edge["relationship"]
                == "source-bound-passing-test-for-candidate-control"
                for edge in current["evidence_graph"]["edges"]
            )
        )

        campaign["source_snapshot"]["evidence_revision_binding"] = "mismatch"
        stale = build_advanced_analysis(Path.cwd(), [threat], artifacts)

        trace = stale["threat_control_test_traceability"][0]
        self.assertEqual(trace["verified_test_files"], [])
        self.assertEqual(trace["test_evidence_status"], "source-revision-mismatch")

    def test_mutation_test_assurance_rejects_selected_only_test_files(self) -> None:
        mutation = _finding("MUTMUT-CONTROL", "mutmut", "src/auth.py")
        artifacts = _artifacts()

        selected_only = build_advanced_analysis(Path.cwd(), [mutation], artifacts)

        leverage = selected_only["security_mutation_leverage"][0]
        self.assertEqual(leverage["candidate_test_files"], ["tests/test_auth.py"])
        self.assertEqual(leverage["verified_test_files"], [])
        self.assertEqual(
            selected_only["summary"][
                "security_control_mutations_without_test_evidence"
            ],
            1,
        )

        _add_source_bound_passing_campaign_evidence(
            artifacts["risk-paths.json"]["validation_campaigns"][0]
        )
        current = build_advanced_analysis(Path.cwd(), [mutation], artifacts)

        leverage = current["security_mutation_leverage"][0]
        self.assertEqual(leverage["verified_test_files"], ["tests/test_auth.py"])
        self.assertEqual(leverage["test_evidence_status"], "source-bound-passing")
        self.assertEqual(
            current["summary"]["security_control_mutations_without_test_evidence"],
            0,
        )

    def test_dependency_scoring_does_not_treat_inventory_as_package_presence(
        self,
    ) -> None:
        artifacts = _artifacts()
        dependency_route = artifacts["risk-paths.json"]["routes"][1]
        context = dependency_route["target"]["correlations"]
        context["known_exploited"] = False
        context["epss_high"] = False
        dependency_route["runtime_context"]["observations"] = []
        context["versions"] = ["1.0"]
        context["package_lifecycle"] = {
            "artifact_inventory_available": True,
            "comparison_available": True,
            "assessment": "package-not-observed",
            "artifact_versions": [],
        }

        absent = build_advanced_analysis(Path.cwd(), [], artifacts)

        trust = absent["dependency_trust_routes"][0]
        self.assertEqual(trust["artifact_exposure"]["status"], "package-not-observed")
        self.assertEqual(trust["review_score"], 0)
        self.assertEqual(trust["review_tier"], "low")
        self.assertNotIn("present-in-artifact-inventory", trust["risk_factors"])

        context["package_lifecycle"].update(
            {"assessment": "matched", "artifact_versions": ["1.0"]}
        )
        affected = build_advanced_analysis(Path.cwd(), [], artifacts)

        trust = affected["dependency_trust_routes"][0]
        self.assertEqual(
            trust["artifact_exposure"]["status"], "affected-version-observed"
        )
        self.assertEqual(
            trust["artifact_exposure"]["affected_artifact_versions"], ["1.0"]
        )
        self.assertIn("affected-version-observed-in-artifact", trust["risk_factors"])
        self.assertEqual(trust["review_score"], 3)

    def test_digest_bound_delta_detects_control_and_privacy_regressions(self) -> None:
        artifacts = _artifacts()
        artifacts["graphify.json"]["topology"]["file_edges"] = artifacts[
            "graphify.json"
        ]["topology"]["file_edges"][:2]
        finding = _finding("PYSEC-FLOW", "codeql", "src/sink.py")
        finding.evidence["sarif_code_flows"] = [
            {
                "tool": "codeql",
                "semantic_basis": "security-path-problem",
                "step_count": 3,
                "steps": [
                    {"path": "src/entry.py", "line": 3, "message": "source"},
                    {"path": "src/auth.py", "line": 7, "message": "control"},
                    {"path": "src/sink.py", "line": 9, "message": "sink"},
                ],
            }
        ]
        baseline = build_advanced_analysis(Path.cwd(), [finding], artifacts)
        current = json.loads(json.dumps(baseline))
        current["control_topology"][0]["topology_status"] = "bypass-capable"
        current["telemetry_privacy_topology"][0]["review_status"] = (
            "redaction-order-risk"
        )
        current["taint_paths"][0]["route_alignment"] = "not-established"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before_path = root / "before.json"
            after_path = root / "after.json"
            before_path.write_text(json.dumps(baseline), encoding="utf-8")
            after_path.write_text(json.dumps(current), encoding="utf-8")
            result = compare_advanced_analysis(
                before_path,
                after_path,
                baseline_sha256=hashlib.sha256(before_path.read_bytes()).hexdigest(),
                current_sha256=hashlib.sha256(after_path.read_bytes()).hexdigest(),
            )

        self.assertEqual(result["verdict"], "regression")
        self.assertEqual(result["summary"]["control_regressions"], 1)
        self.assertEqual(result["summary"]["privacy_regressions"], 1)
        self.assertEqual(result["summary"]["taint_route_alignment_regressions"], 1)
        self.assertIn("Actionable regressions", render_advanced_delta_markdown(result))
        self.assertIn("taint alignment", render_advanced_delta_markdown(result))
        schema = json.loads(read_bundled_schema("advanced-analysis-delta-1.0"))
        Draft202012Validator(schema).validate(result)


def _finding(identifier: str, tool: str, path: str) -> Finding:
    return Finding(
        finding_id=identifier,
        fingerprint=f"sha256:{'a' * 64}",
        title="Sensitive telemetry flow",
        description="Input reaches telemetry",
        impact="Sensitive data could cross a boundary.",
        remediation="Protect the route.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="data-exposure",
        locations=[Location(path=path, start_line=9)],
        sources=[Source(tool=tool, rule_id="flow", message="flow")],
    )


def _artifacts() -> dict[str, Any]:
    target = {
        "id": "finding:PYSEC-FLOW",
        "finding_id": "PYSEC-FLOW",
        "kind": "finding",
        "path": "src/sink.py",
        "domain": "security",
        "correlations": {},
    }
    dependency = {
        "id": "dependency:demo",
        "kind": "dependency-advisory-import",
        "path": "src/sink.py",
        "domain": "supply-chain",
        "correlations": {
            "package": "demo",
            "primary_identifier": "CVE-2026-1",
            "identifiers": ["CVE-2026-1"],
            "known_exploited": True,
            "epss_high": True,
            "fix_available": True,
            "fixed_version_candidates": ["2.0"],
            "package_lifecycle": {
                "artifact_inventory_available": True,
                "assessment": "matched",
                "evidence_artifacts": ["artifact-sbom.cdx.json"],
            },
        },
    }
    return {
        "graphify.json": {
            "nodes": [
                {"path": "src/entry.py"},
                {"path": "src/auth.py"},
                {"path": "src/bypass.py"},
                {"path": "src/sink.py"},
                {"path": "src/demo/cli.py"},
            ],
            "topology": {
                "file_edges": [
                    {"source": "src/entry.py", "target": "src/auth.py"},
                    {"source": "src/auth.py", "target": "src/sink.py"},
                    {"source": "src/entry.py", "target": "src/bypass.py"},
                    {"source": "src/bypass.py", "target": "src/sink.py"},
                ]
            },
        },
        "reachability.json": {
            "entry_points": [{"id": "entry:cli", "path": "src/entry.py"}]
        },
        "risk-paths.json": {
            "routes": [
                {
                    "route_id": "route-flow",
                    "target": target,
                    "files": ["src/entry.py", "src/auth.py", "src/sink.py"],
                    "entry_point_exposures": [
                        {
                            "entry_point": {"id": "entry:cli"},
                            "files": ["src/entry.py", "src/auth.py", "src/sink.py"],
                        }
                    ],
                    "validation_campaign_ids": ["campaign-auth"],
                    "convergence_hotspot_ids": [],
                    "owners": ["@security"],
                    "validation": {"assessment_status": "gap"},
                    "runtime_context": {"observations": []},
                    "evidence_assurance": {"review_status": "assured"},
                },
                {
                    "route_id": "route-dependency",
                    "target": dependency,
                    "files": ["src/entry.py", "src/auth.py", "src/sink.py"],
                    "entry_point_exposures": [],
                    "validation_campaign_ids": [],
                    "convergence_hotspot_ids": [],
                    "owners": ["@security"],
                    "validation": {"assessment_status": "gap"},
                    "runtime_context": {"observations": ["observed"]},
                    "evidence_assurance": {"review_status": "assured"},
                },
            ],
            "validation_campaigns": [
                {
                    "campaign_id": "campaign-auth",
                    "hotspot_id": "hotspot-auth",
                    "path": "src/auth.py",
                    "selected_test_files": ["tests/test_auth.py"],
                }
            ],
            "convergence_hotspots": [
                {
                    "hotspot_id": "hotspot-auth",
                    "path": "src/auth.py",
                    "kind": "shared-transit",
                }
            ],
            "sensitive_data_routes": [
                {
                    "sensitive_route_id": "sensitive-flow",
                    "route_id": "route-flow",
                    "target_id": "finding:PYSEC-FLOW",
                    "finding_id": "PYSEC-FLOW",
                    "path": "src/sink.py",
                    "line": 9,
                    "sink_family": "telemetry",
                    "trust_boundary": "telemetry-exporter",
                    "data_classes": ["credentials"],
                    "protection_status": "not-observed",
                    "entry_point_ids": ["entry:cli"],
                    "entry_point_exposure_count": 1,
                    "validation_status": "gap",
                    "owners": ["@security"],
                    "citations": [],
                }
            ],
        },
    }


def _write_wheel(
    path: Path,
    *,
    record_algorithm: str = "sha256",
    unsigned_path: str | None = None,
    duplicate_record_path: str | None = None,
) -> None:
    members = {
        "demo/cli.py": b"def main():\n    return 0\n",
        "demo-1.0.dist-info/entry_points.txt": b"[console_scripts]\ndemo = demo.cli:main\n",
        "demo-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
    }
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    row: list[str | int]
    for name, content in members.items():
        if name == unsigned_path:
            row = [name, "", ""]
            writer.writerow(row)
            if name == duplicate_record_path:
                writer.writerow(row)
            continue
        digest = (
            base64.urlsafe_b64encode(hashlib.new(record_algorithm, content).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        row = [name, f"{record_algorithm}={digest}", len(content)]
        writer.writerow(row)
        if name == duplicate_record_path:
            writer.writerow(row)
    writer.writerow(["demo-1.0.dist-info/RECORD", "", ""])
    members["demo-1.0.dist-info/RECORD"] = output.getvalue().encode("utf-8")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def _add_source_bound_passing_campaign_evidence(campaign: dict[str, Any]) -> None:
    campaign.update(
        {
            "focused_test_validation_status": "passed",
            "test_case_inventory_complete": True,
            "test_execution_sources": ["junit-summary.json"],
            "focused_test_execution": [
                {
                    "path": "tests/test_auth.py",
                    "status": "passed",
                    "tests": 1,
                    "passed": 1,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 0,
                    "sources": ["junit-summary.json"],
                }
            ],
            "source_snapshot": {
                "selected_test_files_bound": 1,
                "selected_test_files_missing": [],
                "evidence_revision_binding": "aligned",
            },
        }
    )


def _sarif_location(
    path: str, line: int, uri_base_id: str | None = None
) -> dict[str, object]:
    artifact_location = {"uri": path}
    if uri_base_id is not None:
        artifact_location["uriBaseId"] = uri_base_id
    return {
        "physicalLocation": {
            "artifactLocation": artifact_location,
            "region": {"startLine": line},
        }
    }


def _sarif_indexed_location(index: int, line: int) -> dict[str, object]:
    return {
        "physicalLocation": {
            "artifactLocation": {"index": index},
            "region": {"startLine": line},
        }
    }
