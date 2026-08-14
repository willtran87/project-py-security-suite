from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import tempfile
import unittest
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
from py_security_suite.models import Confidence, Finding, Location, Severity, Source
from py_security_suite.report_inspection import read_bundled_schema


class AdvancedAnalysisTests(unittest.TestCase):
    def test_cross_evidence_analysis_detects_bypass_and_preserves_taint_path(
        self,
    ) -> None:
        finding = _finding("PYSEC-FLOW", "codeql", "src/sink.py")
        finding.evidence["sarif_code_flows"] = [
            {
                "tool": "codeql",
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
                                                            "src/source.py", 3
                                                        ),
                                                        "message": {"text": "source"},
                                                    },
                                                    {
                                                        "location": _sarif_location(
                                                            "src/sink.py", 9
                                                        ),
                                                        "message": {"text": "sink"},
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
        self.assertNotIn("snippet", flow["steps"][0])

    def test_digest_bound_delta_detects_control_and_privacy_regressions(self) -> None:
        artifacts = _artifacts()
        artifacts["graphify.json"]["topology"]["file_edges"] = artifacts[
            "graphify.json"
        ]["topology"]["file_edges"][:2]
        baseline = build_advanced_analysis(Path.cwd(), [], artifacts)
        current = json.loads(json.dumps(baseline))
        current["control_topology"][0]["topology_status"] = "bypass-capable"
        current["telemetry_privacy_topology"][0]["review_status"] = (
            "redaction-order-risk"
        )
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
        self.assertIn("Actionable regressions", render_advanced_delta_markdown(result))
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


def _write_wheel(path: Path) -> None:
    members = {
        "demo/cli.py": b"def main():\n    return 0\n",
        "demo-1.0.dist-info/entry_points.txt": b"[console_scripts]\ndemo = demo.cli:main\n",
        "demo-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
    }
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    for name, content in members.items():
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(content).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        writer.writerow([name, f"sha256={digest}", len(content)])
    writer.writerow(["demo-1.0.dist-info/RECORD", "", ""])
    members["demo-1.0.dist-info/RECORD"] = output.getvalue().encode("utf-8")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def _sarif_location(path: str, line: int) -> dict[str, object]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": line},
        }
    }
