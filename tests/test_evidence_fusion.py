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
from py_security_suite.validation_alignment import focused_test_execution


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
        osv.evidence["fixed_versions"] = ["1.5"]
        osv.evidence["risk_intelligence"] = {
            "cves": ["CVE-2026-1000"],
            "known_exploited": [
                {
                    "cve": "CVE-2026-1000",
                    "date_added": "2026-01-02",
                    "due_date": "2026-01-23",
                    "known_ransomware_campaign_use": "Known",
                    "required_action": "Apply the vendor remediation.",
                }
            ],
            "epss": [
                {
                    "cve": "CVE-2026-1000",
                    "probability": 0.75,
                    "percentile": 0.99,
                }
            ],
            "vex": [{"cve": "CVE-2026-1000", "state": "exploitable"}],
        }
        osv.classifications.append("EPSS-HIGH")
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
        source.evidence["owners"] = ["@platform-security"]
        grype.evidence.update(
            {
                "artifact_path": "dist/app.whl",
                "artifact_sha256": "c" * 64,
                "fixed_versions": ["2.0"],
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
            "pipdeptree-summary.json": {
                "total_packages": 12,
                "direct_dependencies": 4,
                "transitive_dependencies": 8,
                "max_depth": 3,
                "missing_dependencies": 0,
                "cyclic_dependencies": 0,
                "conflicting_dependencies": {"packages": 0, "edges": 0},
            },
            "junit-summary.json": {
                "schema_version": "1.0",
                "kind": "junit",
                "report_count": 1,
                "totals": {
                    "tests": 2,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 0,
                    "time": 0.02,
                },
                "failures": [],
                "test_cases": [
                    {
                        "name": "test_request",
                        "classname": "tests.test_app",
                        "file": "tests/test_app.py",
                        "line": 5,
                        "time": 0.01,
                        "result": "passed",
                    },
                    {
                        "name": "test_error_path",
                        "classname": "tests.test_app",
                        "file": "tests/test_app.py",
                        "line": 12,
                        "time": 0.01,
                        "result": "passed",
                    },
                ],
                "test_case_inventory_complete": True,
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
            for name in ("osv-scanner", "grype", "graphify", "coverage", "junit")
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
        self.assertEqual(document["schema_version"], "1.3")
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
        self.assertEqual(
            usage["dependency_paths"],
            [
                {
                    "introducing_package": "example-pkg",
                    "path": ["example-pkg@1.0"],
                    "depth": 0,
                }
            ],
        )
        self.assertEqual(usage["introducing_packages"], ["example-pkg"])
        self.assertEqual(usage["dependency_path_confidence"], "high")
        self.assertTrue(usage["environment_health_evidence_available"])
        self.assertTrue(usage["dependency_environment_health"]["healthy"])
        self.assertFalse(usage["dependency_environment_warning"])
        self.assertTrue(usage["import_observed"])
        self.assertEqual(usage["import_paths"], ["src/app.py"])
        self.assertEqual(usage["reachability_states"], ["executable"])
        self.assertTrue(usage["test_mapping_evidence_available"])
        self.assertEqual(usage["recommended_test_files"], ["tests/test_app.py"])
        self.assertEqual(usage["direct_test_files"], ["tests/test_app.py"])
        self.assertEqual(usage["test_selection_confidence"], "high")
        self.assertTrue(usage["test_execution_evidence_available"])
        self.assertTrue(usage["test_case_inventory_available"])
        self.assertTrue(usage["test_case_inventory_complete"])
        self.assertEqual(usage["focused_test_validation_status"], "passed")
        self.assertEqual(
            usage["focused_test_execution"],
            [
                {
                    "path": "tests/test_app.py",
                    "status": "passed",
                    "tests": 2,
                    "passed": 2,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 0,
                    "sources": ["junit-summary.json"],
                    "path_attributions": ["producer"],
                }
            ],
        )
        self.assertEqual(usage["unobserved_recommended_test_files"], [])
        self.assertTrue(usage["ownership_evidence_available"])
        self.assertEqual(usage["import_path_owners"], ["@platform-security"])
        self.assertEqual(
            usage["import_path_ownership"],
            [{"path": "src/app.py", "owners": ["@platform-security"]}],
        )
        self.assertTrue(usage["coverage_evidence_available"])
        self.assertEqual(
            usage["import_path_coverage"],
            [{"path": "src/app.py", "coverage_percent": 55.0}],
        )
        importer = usage["import_path_assessments"][0]
        self.assertEqual(importer["path"], "src/app.py")
        self.assertEqual(importer["import_modules"], ["example_pkg"])
        self.assertEqual(importer["import_lines"], [1])
        self.assertEqual(importer["assessment"], "executable-import")
        self.assertEqual(importer["reachability_states"], ["executable"])
        self.assertEqual(importer["runtime_observations"], ["not-observed"])
        self.assertEqual(importer["owners"], ["@platform-security"])
        self.assertEqual(importer["recommended_test_files"], ["tests/test_app.py"])
        self.assertEqual(importer["focused_test_validation_status"], "passed")
        self.assertEqual(importer["coverage_percent"], 55.0)
        self.assertTrue(importer["coverage_gap"])
        self.assertEqual(importer["test_coverage_alignment"], "coverage-gap")
        self.assertEqual(usage["uncovered_import_paths"], ["src/app.py"])
        self.assertEqual(usage["test_coverage_alignment"], "coverage-gap")
        self.assertIn(
            "Focused tests passed, but retained coverage did not exercise the affected dependency import path(s).",
            usage["validation_gap_reasons"],
        )
        threat = advisory["threat_context"]
        self.assertTrue(threat["known_exploited"])
        self.assertEqual(threat["known_exploited_cves"], ["CVE-2026-1000"])
        self.assertEqual(
            threat["known_exploited_records"][0]["required_action"],
            "Apply the vendor remediation.",
        )
        self.assertEqual(threat["epss_probability"], 0.75)
        self.assertEqual(threat["epss_percentile"], 0.99)
        self.assertEqual(threat["epss_records"][0]["cve"], "CVE-2026-1000")
        self.assertTrue(threat["epss_high"])
        self.assertEqual(threat["vex_disposition"], "exploitable")
        remediation = advisory["remediation_context"]
        self.assertEqual(remediation["priority"], "P0")
        self.assertEqual(remediation["action_kind"], "upgrade")
        self.assertTrue(remediation["fix_available"])
        self.assertEqual(remediation["owners"], ["@platform-security"])
        self.assertEqual(remediation["recommended_test_files"], ["tests/test_app.py"])
        self.assertEqual(remediation["test_selection_confidence"], "high")
        self.assertEqual(remediation["focused_test_validation_status"], "passed")
        self.assertEqual(remediation["test_coverage_alignment"], "coverage-gap")
        self.assertEqual(remediation["introducing_packages"], ["example-pkg"])
        self.assertEqual(remediation["dependency_path_confidence"], "high")
        self.assertEqual(remediation["fixed_version_candidates"], ["1.5", "2.0"])
        self.assertEqual(
            remediation["fixed_version_sources"],
            [
                {"tool": "grype", "versions": ["2.0"]},
                {"tool": "osv-scanner", "versions": ["1.5"]},
            ],
        )
        self.assertIn("Immediately upgrade", remediation["recommended_action"])
        self.assertIn("CISA KEV direction", remediation["recommended_action"])
        self.assertIn("2026-01-23", remediation["recommended_action"])
        self.assertTrue(remediation["verification_steps"])
        self.assertTrue(remediation["evidence_basis"])
        self.assertIn(
            "Package-level use evidence does not establish vulnerable-function exploitability.",
            remediation["uncertainties"],
        )
        self.assertTrue(
            any("below 80%" in item for item in remediation["uncertainties"])
        )
        self.assertEqual(document["summary"]["advisories_with_import_evidence"], 1)
        self.assertEqual(document["summary"]["advisories_in_executable_imports"], 1)
        self.assertEqual(document["summary"]["known_exploited_advisories"], 1)
        self.assertEqual(document["summary"]["high_epss_advisories"], 1)
        self.assertEqual(document["summary"]["advisories_with_fixed_versions"], 1)
        self.assertEqual(document["summary"]["p0_advisories"], 1)
        self.assertEqual(document["summary"]["advisories_with_focused_tests"], 1)
        self.assertEqual(
            document["summary"]["advisories_with_passing_focused_test_evidence"],
            1,
        )
        self.assertEqual(
            document["summary"]["advisories_with_failing_focused_test_evidence"],
            0,
        )
        self.assertEqual(document["summary"]["advisories_with_import_path_owners"], 1)
        self.assertEqual(
            document["summary"]["advisories_with_uncovered_import_paths"], 1
        )
        self.assertEqual(
            document["summary"]["advisories_with_test_coverage_mismatch"], 1
        )
        self.assertEqual(
            document["summary"]["advisories_with_introducing_dependency_paths"],
            1,
        )
        self.assertEqual(
            document["summary"]["advisories_with_dependency_environment_gaps"],
            0,
        )
        rendered = "\n".join(_render_fusion_summary(document))
        detailed = "\n".join(_markdown_fusion_context(osv))
        self.assertIn("Advisories with exact static import evidence | 1", rendered)
        self.assertIn("dependency use executable-import", detailed)
        self.assertIn("remediation P0, upgrade", detailed)
        self.assertIn("Immediately upgrade", detailed)
        self.assertIn("focused tests tests/test\\_app.py", detailed)
        self.assertIn("scanned-state focused-test evidence passed", detailed)
        self.assertIn("test/coverage alignment coverage-gap", detailed)
        self.assertIn("owners @platform-security", detailed)
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

        schema = json.loads(read_bundled_schema("evidence-fusion-1.3"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

    def test_empty_inputs_remain_explicit_and_do_not_infer_safety(self) -> None:
        document = build_evidence_fusion([], {}, [])

        self.assertEqual(document["summary"]["findings_enriched"], 0)
        self.assertEqual(document["package_lineage"], [])
        self.assertEqual(document["advisory_clusters"], [])
        self.assertIn("not treated as proof of safety", document["limitations"][0])

    def test_vex_not_affected_claim_requires_validation_and_does_not_suppress(
        self,
    ) -> None:
        advisory = _finding(
            "OSV-VEX",
            tool="osv-scanner",
            path="uv.lock",
            classification="CVE-2026-4000",
            package="bounded-lib",
        )
        advisory.evidence = {
            "fixed_versions": ["2.0"],
            "risk_intelligence": {
                "cves": ["CVE-2026-4000"],
                "vex": [
                    {
                        "cve": "CVE-2026-4000",
                        "state": "not_affected",
                        "justification": "vulnerable_code_not_present",
                    }
                ],
            },
        }

        document = build_evidence_fusion([advisory], {}, [])

        cluster = document["advisory_clusters"][0]
        self.assertEqual(
            cluster["threat_context"]["vex_disposition"],
            "bounded-or-resolved-claim",
        )
        self.assertEqual(
            cluster["threat_context"]["vex_records"][0]["justification"],
            "vulnerable_code_not_present",
        )
        self.assertEqual(cluster["remediation_context"]["priority"], "P1")
        self.assertEqual(cluster["remediation_context"]["action_kind"], "validate-vex")
        self.assertTrue(cluster["remediation_context"]["fix_available"])
        self.assertIn(
            "preserve the native finding",
            cluster["remediation_context"]["recommended_action"],
        )
        self.assertEqual(document["summary"]["advisories_requiring_vex_validation"], 1)
        self.assertEqual(
            cluster["dependency_usage"]["test_selection_confidence"],
            "not-available",
        )
        self.assertFalse(cluster["dependency_usage"]["coverage_evidence_available"])

    def test_transitive_reverse_graph_selects_medium_confidence_focused_test(
        self,
    ) -> None:
        advisory = _finding(
            "OSV-TRANSITIVE-TEST",
            tool="osv-scanner",
            path="uv.lock",
            classification="CVE-2026-5000",
            package="client-lib",
        )
        artifacts = {
            "graphify.json": {
                "nodes": [
                    {"id": "client", "kind": "code", "path": "src/client.py"},
                    {
                        "id": "client_lib",
                        "kind": "external",
                        "label": "client_lib",
                    },
                ],
                "edges": [
                    {
                        "source": "client",
                        "target": "client_lib",
                        "relation": "imports",
                        "path": "src/client.py",
                    }
                ],
                "topology": {
                    "file_edges": [
                        {
                            "source": "src/service.py",
                            "target": "src/client.py",
                            "relation": "imports",
                        },
                        {
                            "source": "tests/test_service.py",
                            "target": "src/service.py",
                            "relation": "imports",
                        },
                    ]
                },
            },
            "finding-delta.json": {
                "ownership_rules": 1,
                "ownership_rule_details": [
                    {"pattern": "src/*.py", "owners": ["@client-team"]}
                ],
            },
        }

        document = build_evidence_fusion([advisory], artifacts, [])

        usage = document["advisory_clusters"][0]["dependency_usage"]
        self.assertEqual(usage["direct_test_files"], [])
        self.assertEqual(usage["transitive_test_files"], ["tests/test_service.py"])
        self.assertEqual(usage["recommended_test_files"], ["tests/test_service.py"])
        self.assertEqual(usage["test_selection_confidence"], "medium")
        self.assertEqual(usage["focused_test_validation_status"], "not-available")
        self.assertEqual(usage["import_path_owners"], ["@client-team"])

    def test_focused_test_execution_fails_closed_per_selected_file(self) -> None:
        result = focused_test_execution(
            ["tests/test_client.py", "tests/test_missing.py"],
            test_executions={
                "tests/test_client.py": [
                    {
                        "source": "junit-summary.json",
                        "result": "passed",
                        "file_attribution": "classname-module",
                    },
                    {
                        "source": "junit-summary.json",
                        "result": "failure",
                        "file_attribution": "classname-module",
                    },
                ]
            },
            evidence={
                "available": True,
                "case_inventory_available": True,
                "case_inventory_complete": True,
                "sources": ["junit-summary.json"],
            },
        )

        self.assertEqual(result["focused_test_validation_status"], "failed")
        self.assertEqual(
            result["unobserved_recommended_test_files"], ["tests/test_missing.py"]
        )
        self.assertEqual(result["focused_test_execution"][0]["tests"], 2)
        self.assertEqual(result["focused_test_execution"][0]["failures"], 1)

        legacy = focused_test_execution(
            ["tests/test_client.py"],
            test_executions={},
            evidence={
                "available": True,
                "case_inventory_available": False,
                "case_inventory_complete": None,
                "sources": ["junit-summary.json"],
            },
        )
        self.assertEqual(legacy["focused_test_validation_status"], "not-available")

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
            },
            "pipdeptree-summary.json": {
                "total_packages": 2,
                "direct_dependencies": 1,
                "transitive_dependencies": 1,
                "max_depth": 2,
                "missing_dependencies": 0,
                "cyclic_dependencies": 0,
                "conflicting_dependencies": {"packages": 1, "edges": 1},
            },
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
            },
            "pipdeptree-summary.json": {
                "total_packages": 2,
                "direct_dependencies": 1,
                "transitive_dependencies": 1,
                "max_depth": 2,
                "missing_dependencies": 0,
                "cyclic_dependencies": 0,
                "conflicting_dependencies": {"packages": 1, "edges": 1},
            },
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
        usage_by_package = {
            item["package"]: item["dependency_usage"]
            for item in document["advisory_clusters"]
        }
        self.assertEqual(
            usage_by_package["transitive-lib"]["dependency_paths"],
            [
                {
                    "introducing_package": "direct-lib",
                    "path": ["direct-lib@1", "transitive-lib@1"],
                    "depth": 1,
                }
            ],
        )
        self.assertEqual(
            usage_by_package["transitive-lib"]["dependency_path_confidence"],
            "qualified",
        )
        self.assertTrue(
            usage_by_package["transitive-lib"]["dependency_environment_warning"]
        )
        self.assertIn(
            "introducing dependency root(s) direct-lib",
            next(
                item
                for item in document["advisory_clusters"]
                if item["package"] == "transitive-lib"
            )["remediation_context"]["recommended_action"],
        )
        self.assertEqual(
            document["summary"]["advisories_with_dependency_environment_gaps"],
            2,
        )


if __name__ == "__main__":
    unittest.main()
