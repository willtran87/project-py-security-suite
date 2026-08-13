from __future__ import annotations

import json
import unittest

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.evidence_fusion import build_evidence_fusion
from py_security_suite.models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    ToolRun,
    ToolStatus,
)
from py_security_suite.report_inspection import read_bundled_schema
from py_security_suite.reports import _markdown_fusion_context, _render_fusion_summary


def _finding(
    finding_id: str,
    *,
    tool: str,
    path: str,
    classification: str,
    package: str | None = None,
    line: int | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        fingerprint=f"sha256:{finding_id.casefold()}",
        title=f"{classification} finding",
        description="Detected issue",
        impact="Security impact",
        remediation="Remediate and retest",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="dependencies" if package else "source-security",
        locations=[
            Location(
                path=path,
                start_line=line,
                end_line=line,
                package=package,
                version="1.0" if package else None,
                ecosystem="PyPI" if package else None,
            )
        ],
        sources=[Source(tool=tool, rule_id=classification, message="Detected")],
        classifications=[classification],
    )


class EvidenceFusionTests(unittest.TestCase):
    def test_cross_references_source_artifact_graph_test_and_digest_evidence(
        self,
    ) -> None:
        osv = _finding(
            "OSV-FINDING",
            tool="osv-scanner",
            path="uv.lock",
            classification="GHSA-AAAA-BBBB-CCCC",
            package="Example_Pkg",
        )
        osv.evidence["advisory_aliases"] = ["CVE-2026-1000"]
        osv.citations = [
            Citation(
                kind="advisory",
                identifier="GHSA-AAAA-BBBB-CCCC",
                title="GHSA description",
                uri="https://osv.dev/vulnerability/GHSA-AAAA-BBBB-CCCC",
            ),
            Citation(
                kind="advisory_alias",
                identifier="cve-2026-1000",
                title="CVE-2026-1000 (alias of GHSA-AAAA-BBBB-CCCC)",
                uri="https://osv.dev/vulnerability/cve-2026-1000",
            ),
        ]
        grype = _finding(
            "GRYPE-FINDING",
            tool="grype",
            path="dist/app.whl",
            classification="CVE-2026-1000",
            package="example-pkg",
        )
        grype.citations = [
            Citation(
                kind="advisory",
                identifier="CVE-2026-1000",
                title="Canonical CVE description",
                uri="https://example.invalid/CVE-2026-1000",
            )
        ]
        source = _finding(
            "SOURCE-FINDING",
            tool="bandit",
            path="src/app.py",
            classification="CWE-78",
            line=12,
        )
        source.evidence["graph_context"] = {
            "degree": 20,
            "two_hop_upstream_count": 12,
            "two_hop_downstream_count": 4,
            "corroborating_evidence": {
                "reachability_states": ["executable"],
                "runtime_observations": ["observed"],
                "maximum_complexity": 25,
                "maximum_complexity_rank": "D",
            },
        }
        grype.evidence.update(
            {
                "artifact_path": "dist/app.whl",
                "artifact_sha256": "c" * 64,
            }
        )
        artifacts = {
            "source-inventory.json": {
                "files": [{"path": "src/app.py", "sha256": "b" * 64, "size_bytes": 100}]
            },
            "coverage-summary.json": {
                "files": [
                    {
                        "path": "src/app.py",
                        "missing_lines": [12],
                        "summary": {"percent_covered": 55.0},
                    }
                ]
            },
            "diff-coverage.json": {
                "src_stats": {
                    "src/app.py": {
                        "covered_lines": [],
                        "violation_lines": [12],
                        "percent_covered": 0.0,
                    }
                }
            },
            "sbom.cdx.json": {
                "components": [
                    {
                        "bom-ref": "example-pkg@1.0",
                        "name": "example-pkg",
                        "version": "1.0",
                    }
                ],
                "dependencies": [{"ref": "example-pkg@1.0", "dependsOn": []}],
            },
            "artifact-sbom.cdx.json": {
                "components": [
                    {"name": "example_pkg", "version": "1.0"},
                    {"name": "artifact-only", "version": "2.0"},
                ]
            },
            "artifact-manifest.json": {
                "artifacts": [
                    {
                        "path": "dist/app.whl",
                        "sha256": "a" * 64,
                        "size_bytes": 500,
                    }
                ]
            },
            "graph-analysis.json": {
                "structural_hotspots": [
                    {
                        "path": "src/app.py",
                        "degree": 20,
                        "coverage_percent": 55.0,
                        "maximum_complexity_rank": "D",
                        "finding_ids": ["SOURCE-FINDING"],
                    }
                ]
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
                        "id": "example_pkg",
                        "kind": "external",
                        "label": "example_pkg",
                        "path": ".",
                    },
                ],
                "edges": [
                    {
                        "source": "app",
                        "target": "example_pkg",
                        "relation": "imports",
                        "path": "src/app.py",
                        "line": 1,
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
        }
        runs = [
            ToolRun(
                tool=name,
                status=ToolStatus.COMPLETED,
                command=[name],
                duration_seconds=1,
            )
            for name in ("osv-scanner", "grype", "graphify", "coverage")
        ]

        document = build_evidence_fusion([osv, grype, source], artifacts, runs)

        self.assertEqual(osv.evidence["fusion"]["corroboration"], "cross-stage")
        self.assertIn("grype", osv.evidence["fusion"]["related_tools"])
        self.assertEqual(source.evidence["fusion"]["review_tier"], "urgent")
        self.assertTrue(source.evidence["fusion"]["source_context"]["changed_line"])
        self.assertFalse(source.evidence["fusion"]["source_context"]["line_covered"])
        self.assertTrue(grype.evidence["fusion"]["artifact_context"]["manifest_bound"])
        self.assertFalse(
            grype.evidence["fusion"]["artifact_context"][
                "finding_sha256_matches_manifest"
            ]
        )
        self.assertEqual(document["summary"]["contradictions"], 1)
        self.assertEqual(document["contradictions"][0]["finding_id"], "GRYPE-FINDING")
        self.assertEqual(document["summary"]["cross_stage_findings"], 2)
        self.assertEqual(document["summary"]["compound_hotspots"], 1)
        self.assertEqual(document["schema_version"], "1.1")
        self.assertEqual(document["summary"]["distinct_advisories"], 1)
        self.assertEqual(document["summary"]["advisory_observations"], 2)
        self.assertEqual(document["summary"]["alias_collapsed_observations"], 1)
        advisory = document["advisory_clusters"][0]
        self.assertEqual(advisory["primary_identifier"], "CVE-2026-1000")
        self.assertEqual(
            advisory["identifiers"],
            ["CVE-2026-1000", "GHSA-AAAA-BBBB-CCCC"],
        )
        self.assertEqual(advisory["finding_ids"], ["GRYPE-FINDING", "OSV-FINDING"])
        self.assertEqual(advisory["tools"], ["grype", "osv-scanner"])
        self.assertTrue(advisory["cross_tool"])
        self.assertEqual(
            [item["identifier"] for item in advisory["citations"]],
            ["CVE-2026-1000", "GHSA-AAAA-BBBB-CCCC"],
        )
        self.assertEqual(advisory["citations"][0]["title"], "Canonical CVE description")
        usage = advisory["dependency_usage"]
        self.assertEqual(usage["assessment"], "executable-import")
        self.assertEqual(usage["source_relationship"], "direct")
        self.assertTrue(usage["import_observed"])
        self.assertEqual(usage["import_paths"], ["src/app.py"])
        self.assertEqual(usage["reachability_states"], ["executable"])
        self.assertEqual(document["summary"]["advisories_with_import_evidence"], 1)
        self.assertEqual(document["summary"]["advisories_in_executable_imports"], 1)
        rendered = "\n".join(_render_fusion_summary(document))
        detailed = "\n".join(_markdown_fusion_context(osv))
        self.assertIn("Advisories with exact static import evidence | 1", rendered)
        self.assertIn("dependency use executable-import", detailed)
        self.assertIn("imports src/app.py", detailed)
        self.assertEqual(
            osv.evidence["fusion"]["advisory_context"]["cluster_id"],
            advisory["cluster_id"],
        )
        self.assertEqual(
            next(
                item
                for item in document["package_lineage"]
                if item["package"] == "artifact-only"
            )["status"],
            "artifact-only",
        )

        schema = json.loads(read_bundled_schema("evidence-fusion-1.1"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

    def test_empty_inputs_remain_explicit_and_do_not_infer_safety(self) -> None:
        document = build_evidence_fusion([], {}, [])

        self.assertEqual(document["summary"]["findings_enriched"], 0)
        self.assertEqual(document["package_lineage"], [])
        self.assertEqual(document["advisory_clusters"], [])
        self.assertIn("not treated as proof of safety", document["limitations"][0])

    def test_exposure_protection_and_priority_influence_fusion_reasons(self) -> None:
        finding = _finding(
            "EXPOSURE-FINDING",
            tool="semgrep",
            path="src/telemetry.py",
            classification="CWE-201",
            line=20,
        )
        finding.evidence["data_exposure"] = {
            "sink_family": "telemetry",
            "structural_relevance": "statically-connected",
            "review_priority": "high",
            "protection_status": "not-observed",
        }

        build_evidence_fusion([finding], {}, [])

        reasons = finding.evidence["fusion"]["review_reasons"]
        self.assertIn("sensitive-data flow reaches a telemetry sink", reasons)
        self.assertIn("sensitive-data analysis assigns high review priority", reasons)
        self.assertIn(
            "no explicit protection boundary was observed at the sink", reasons
        )
        self.assertEqual(finding.evidence["fusion"]["review_tier"], "elevated")

    def test_deptry_unused_signal_is_context_not_exploitability_proof(self) -> None:
        advisory = _finding(
            "OSV-UNUSED",
            tool="osv-scanner",
            path="uv.lock",
            classification="CVE-2026-2000",
            package="unused-lib",
        )
        deptry = _finding(
            "DEPTRY-UNUSED",
            tool="deptry",
            path="pyproject.toml",
            classification="DEPTRY-DEP002",
        )
        deptry.sources = [
            Source(tool="deptry", rule_id="DEP002", message="unused dependency")
        ]
        deptry.evidence["module"] = "unused_lib"
        artifacts = {
            "sbom.cdx.json": {
                "components": [
                    {
                        "bom-ref": "unused-lib@1.0",
                        "name": "unused-lib",
                        "version": "1.0",
                    }
                ],
                "dependencies": [{"ref": "unused-lib@1.0", "dependsOn": []}],
            },
            "graphify.json": {"nodes": [], "edges": []},
        }

        document = build_evidence_fusion([advisory, deptry], artifacts, [])

        usage = document["advisory_clusters"][0]["dependency_usage"]
        self.assertEqual(usage["assessment"], "declared-unused")
        self.assertEqual(usage["source_relationship"], "direct")
        self.assertFalse(usage["import_observed"])
        self.assertEqual(usage["deptry_statuses"], ["unused-declaration"])
        self.assertEqual(usage["deptry_finding_ids"], ["DEPTRY-UNUSED"])
        self.assertEqual(document["summary"]["advisories_with_unused_declarations"], 1)
        self.assertTrue(
            any("never proves" in limitation for limitation in document["limitations"])
        )

    def test_exact_import_and_deptry_unused_signal_are_reported_as_conflict(
        self,
    ) -> None:
        advisory = _finding(
            "OSV-CONFLICT",
            tool="osv-scanner",
            path="uv.lock",
            classification="CVE-2026-3000",
            package="conflict-lib",
        )
        deptry = _finding(
            "DEPTRY-CONFLICT",
            tool="deptry",
            path="pyproject.toml",
            classification="DEPTRY-DEP002",
        )
        deptry.sources = [
            Source(tool="deptry", rule_id="DEP002", message="unused dependency")
        ]
        deptry.evidence["module"] = "conflict_lib"
        artifacts = {
            "graphify.json": {
                "nodes": [
                    {"id": "app", "kind": "code", "path": "app.py"},
                    {
                        "id": "conflict_lib",
                        "kind": "external",
                        "label": "conflict_lib",
                        "path": ".",
                    },
                ],
                "edges": [
                    {
                        "source": "app",
                        "target": "conflict_lib",
                        "relation": "imports",
                        "path": "app.py",
                    }
                ],
            }
        }

        document = build_evidence_fusion([advisory, deptry], artifacts, [])

        usage = document["advisory_clusters"][0]["dependency_usage"]
        self.assertEqual(usage["assessment"], "import-vs-unused-conflict")
        self.assertTrue(usage["signals_conflict"])
        self.assertEqual(document["summary"]["dependency_use_conflicts"], 1)

    def test_cyclonedx_root_distinguishes_direct_and_transitive_advisories(
        self,
    ) -> None:
        direct = _finding(
            "OSV-DIRECT",
            tool="osv-scanner",
            path="uv.lock",
            classification="CVE-2026-4000",
            package="direct-lib",
        )
        transitive = _finding(
            "OSV-TRANSITIVE",
            tool="osv-scanner",
            path="uv.lock",
            classification="CVE-2026-5000",
            package="transitive-lib",
        )
        artifacts = {
            "sbom.cdx.json": {
                "metadata": {"component": {"bom-ref": "project"}},
                "components": [
                    {"bom-ref": "direct", "name": "direct-lib", "version": "1"},
                    {
                        "bom-ref": "transitive",
                        "name": "transitive-lib",
                        "version": "1",
                    },
                ],
                "dependencies": [
                    {"ref": "project", "dependsOn": ["direct"]},
                    {"ref": "direct", "dependsOn": ["transitive"]},
                    {"ref": "transitive", "dependsOn": []},
                ],
            }
        }

        document = build_evidence_fusion([direct, transitive], artifacts, [])
        relationships = {
            item["package"]: item["dependency_usage"]["source_relationship"]
            for item in document["advisory_clusters"]
        }

        self.assertEqual(
            relationships,
            {"direct-lib": "direct", "transitive-lib": "transitive"},
        )


if __name__ == "__main__":
    unittest.main()
