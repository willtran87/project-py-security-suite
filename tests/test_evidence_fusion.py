from __future__ import annotations

import json
import unittest

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.evidence_fusion import build_evidence_fusion
from py_security_suite.models import (
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    ToolRun,
    ToolStatus,
)
from py_security_suite.report_inspection import read_bundled_schema


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
            classification="CVE-2026-1000",
            package="Example_Pkg",
        )
        grype = _finding(
            "GRYPE-FINDING",
            tool="grype",
            path="dist/app.whl",
            classification="CVE-2026-1000",
            package="example-pkg",
        )
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
                "components": [{"name": "example-pkg", "version": "1.0"}]
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
        self.assertEqual(
            next(
                item
                for item in document["package_lineage"]
                if item["package"] == "artifact-only"
            )["status"],
            "artifact-only",
        )

        schema = json.loads(read_bundled_schema("evidence-fusion-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

    def test_empty_inputs_remain_explicit_and_do_not_infer_safety(self) -> None:
        document = build_evidence_fusion([], {}, [])

        self.assertEqual(document["summary"]["findings_enriched"], 0)
        self.assertEqual(document["package_lineage"], [])
        self.assertIn("not treated as proof of safety", document["limitations"][0])


if __name__ == "__main__":
    unittest.main()
