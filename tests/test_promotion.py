from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from typing import cast
from unittest.mock import patch

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.promotion import (
    build_promotion_plan,
    render_promotion_html,
    render_promotion_markdown,
)


class PromotionPlanTests(unittest.TestCase):
    @patch("py_security_suite.promotion.verify_report")
    def test_plan_consolidates_lifecycle_claim_quality_and_coverage(
        self, verify_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_report(report)
            verify_mock.return_value = {
                "scan_id": "scan-1",
                "checksums_sha256": "f" * 64,
                "file_count": 94,
                "outcome": "incomplete",
            }

            result = build_promotion_plan(report)

        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["authoritative"])
        self.assertEqual(result["summary"]["blocking_findings"], 1)
        self.assertEqual(result["finding_evidence_quality"][0]["percent"], 100.0)
        self.assertEqual(
            result["conditional_coverage"][0]["domain"], "dynamic-threat-modeling"
        )
        self.assertEqual(result["scanner_reliability"]["execution_gaps"], 0)
        self.assertEqual(result["schema_version"], "1.2")
        self.assertFalse(result["validation_accountability"]["evidence_available"])
        self.assertFalse(result["operational_trend"]["available"])
        self.assertEqual(result["lifecycle"][3]["status"], "blocked")
        self.assertTrue(
            any(
                action["id"] == "evidence:comparable-baseline"
                for action in result["next_actions"]
            )
        )
        schema = json.loads(
            files("py_security_suite")
            .joinpath("schemas", "promotion-plan-1.2.schema.json")
            .read_text("utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result)
        markdown = render_promotion_markdown(result)
        html = render_promotion_html(result)
        self.assertIn("# Release promotion plan", markdown)
        self.assertIn("| Stage | Status | Detail |", markdown)
        self.assertIn("<!doctype html>", html)
        self.assertIn("Evidence seal", html)

    @patch("py_security_suite.promotion.verify_report")
    def test_plan_cross_references_closure_ownership_and_bound_trend(
        self, verify_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            _write_report(report)
            (report / "closure-plan.json").write_text(
                json.dumps(_closure_plan()), encoding="utf-8"
            )
            trend_path = root / "trend.json"
            trend_bytes = json.dumps(_operational_trend(), sort_keys=True).encode()
            trend_path.write_bytes(trend_bytes)
            verify_mock.return_value = {
                "scan_id": "scan-1",
                "checksums_sha256": "f" * 64,
                "file_count": 95,
                "outcome": "incomplete",
            }

            result = build_promotion_plan(
                report,
                operational_trend=trend_path,
                operational_trend_sha256=hashlib.sha256(trend_bytes).hexdigest(),
            )

        self.assertTrue(result["validation_accountability"]["evidence_available"])
        self.assertEqual(result["summary"]["validation_alignment_items"], 2)
        self.assertEqual(result["summary"]["validation_debt_delta"], 1)
        self.assertIn("change-validation-alignment", result["release_blockers"])
        self.assertEqual(
            result["validation_accountability"]["owner_queues"],
            [{"owner": "@team", "items": 2}],
        )
        queues = result["validation_accountability"]["work_queues"]
        self.assertEqual(len(queues), 2)
        self.assertTrue(
            all(queue["id"].startswith("validation-queue:") for queue in queues)
        )
        self.assertTrue(
            any(
                action["id"] == "trend:resolve-validation-regression"
                for action in result["next_actions"]
            )
        )
        self.assertIn(
            "@team: 2 item(s)",
            result["audiences"]["developer"]["validation_owner_queues"],
        )
        self.assertTrue(
            result["audiences"]["auditor"]["validation_evidence_comparable"]
        )
        graph_node_ids = {node["id"] for node in result["artifact_graph"]["nodes"]}
        self.assertIn("closure-plan", graph_node_ids)
        self.assertIn("operational-trend", graph_node_ids)
        self.assertIn(
            {
                "from": "closure-plan",
                "to": "operational-trend",
                "relation": "tracked-by",
            },
            result["artifact_graph"]["edges"],
        )
        markdown = render_promotion_markdown(result)
        self.assertIn("## Validation accountability", markdown)
        self.assertIn("| @team | 2 |", markdown)
        self.assertIn("validation-debt-regression", markdown)

    @patch("py_security_suite.promotion.verify_report")
    def test_operational_trend_must_bind_latest_snapshot_to_report(
        self, verify_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            _write_report(report)
            trend = _operational_trend()
            timeline = cast(list[dict[str, object]], trend["timeline"])
            timeline[-1]["checksums_sha256"] = "0" * 64
            trend_path = root / "trend.json"
            trend_bytes = json.dumps(trend, sort_keys=True).encode()
            trend_path.write_bytes(trend_bytes)
            verify_mock.return_value = {
                "scan_id": "scan-1",
                "checksums_sha256": "f" * 64,
                "file_count": 94,
                "outcome": "incomplete",
            }

            with self.assertRaisesRegex(ValueError, "latest snapshot"):
                build_promotion_plan(
                    report,
                    operational_trend=trend_path,
                    operational_trend_sha256=hashlib.sha256(trend_bytes).hexdigest(),
                )

    @patch("py_security_suite.promotion.verify_report")
    def test_zero_validation_items_without_assessment_scope_remains_blocked(
        self, verify_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_report(report)
            (report / "diff-coverage.json").unlink()
            (report / "closure-plan.json").write_text(
                json.dumps(
                    {
                        "schema_version": "1.2",
                        "summary": {
                            "validation_alignment_items": 0,
                            "codeowner_backed_validation_items": 0,
                            "validation_items_with_failing_tests": 0,
                            "validation_items_with_coverage_gaps": 0,
                        },
                        "items": [],
                    }
                ),
                encoding="utf-8",
            )
            verify_mock.return_value = {
                "scan_id": "scan-1",
                "checksums_sha256": "f" * 64,
                "file_count": 94,
                "outcome": "incomplete",
            }

            result = build_promotion_plan(report)

        self.assertFalse(result["validation_accountability"]["evidence_available"])
        self.assertTrue(result["validation_accountability"]["ledger_available"])
        self.assertFalse(result["validation_accountability"]["assessment_available"])
        self.assertIn("change-validation-alignment", result["release_blockers"])
        action = next(
            value
            for value in result["next_actions"]
            if value["id"] == "control:change-validation-alignment"
        )
        self.assertEqual(action["owner"], "quality-engineering")
        self.assertIn("diff-coverage", action["action"])

    def test_action_views_expose_safe_operational_context(self) -> None:
        plan = {
            "status": "blocked",
            "report": {"scan_id": "scan-1", "checksums_sha256": "f" * 64},
            "summary": {
                "active_findings": 1,
                "blocking_findings": 1,
                "release_blockers": 1,
                "evidence_quality_average": 100.0,
            },
            "lifecycle": [],
            "evidence_freshness": [],
            "blocker_graph": [],
            "next_actions": [
                {
                    "id": "findings:PYSEC-A+PYSEC-B",
                    "priority": "P1",
                    "owner": "@release",
                    "authority": "controlled-signing",
                    "action": "Sign <exact> **artifacts**.",
                    "evidence": ["PYSEC-A", "dist/project.whl"],
                    "commands": ["pysec sign-artifacts dist/project.whl"],
                    "service_level": {
                        "target_days": 7,
                        "due_at": "2026-08-16T12:00:00Z",
                        "status": "open",
                    },
                }
            ],
        }

        markdown = render_promotion_markdown(plan)
        html = render_promotion_html(plan)

        self.assertIn("### 1. P1 | @release", markdown)
        self.assertIn("findings:PYSEC-A+PYSEC-B", markdown)
        self.assertIn("controlled-signing", markdown)
        self.assertIn("2026-08-16T12:00:00Z", markdown)
        self.assertIn("PYSEC-A", markdown)
        self.assertIn("pysec sign-artifacts dist/project.whl", markdown)
        self.assertNotIn("<exact>", markdown)
        self.assertNotIn("**artifacts**", markdown)
        self.assertIn('<article class="action">', html)
        self.assertIn("Evidence subjects", html)
        self.assertIn("Suggested commands", html)
        self.assertIn("&lt;exact&gt;", html)
        self.assertNotIn("<exact>", html)

    @patch("py_security_suite.promotion.verify_report")
    def test_digest_bound_readiness_must_bind_to_the_same_report(
        self, verify_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            _write_report(report)
            readiness = root / "readiness.json"
            payload = json.dumps(
                {
                    "report": {"checksums_sha256": "0" * 64},
                    "blockers": [],
                    "decision": "approved",
                },
                sort_keys=True,
            ).encode()
            readiness.write_bytes(payload)
            verify_mock.return_value = {
                "scan_id": "scan-1",
                "checksums_sha256": "f" * 64,
                "file_count": 94,
                "outcome": "pass",
            }

            with self.assertRaisesRegex(ValueError, "not bound"):
                build_promotion_plan(
                    report,
                    release_readiness=readiness,
                    release_readiness_sha256=hashlib.sha256(payload).hexdigest(),
                )


def _write_report(report: Path) -> None:
    finding = {
        "finding_id": "PYSEC-SIGN",
        "status": "new",
        "blocking": True,
        "impact": "Artifact authenticity is unknown.",
        "remediation": "Sign the exact digest.",
        "confidence": "high",
        "classifications": ["COSIGN-BUNDLE-MISSING"],
        "sources": [{"tool": "cosign", "rule_id": "COSIGN-BUNDLE-MISSING"}],
        "locations": [{"path": "dist/project.whl", "start_line": None}],
        "citations": [{"uri": "https://example.invalid/cosign"}],
        "evidence": {
            "artifact_path": "dist/project.whl",
            "artifact_sha256": "a" * 64,
            "owners": ["@release"],
        },
    }
    documents: dict[str, object] = {
        "scan-manifest.json": {
            "scan_id": "scan-1",
            "outcome": "incomplete",
            "inventory": {"source_sha256": "b" * 64},
            "tools": [
                {
                    "tool": "cosign",
                    "status": "completed",
                    "applicable": True,
                    "version": "cosign 3.1.2",
                    "duration_seconds": 1.2,
                    "executable_unchanged": True,
                }
            ],
        },
        "findings.json": {"findings": [finding]},
        "assurance-claims.json": {
            "claims": [
                {
                    "control": "PS.3",
                    "claim": "Archive release provenance",
                    "result": "not_satisfied",
                    "blocking_reasons": ["unsigned artifact"],
                    "evidence": ["security-passport.json"],
                }
            ]
        },
        "portfolio-health.json": {
            "domains": [
                {
                    "domain": "dynamic-threat-modeling",
                    "purpose": "Runtime assurance",
                    "status": "conditional_only",
                }
            ]
        },
        "finding-delta.json": {"schema_version": "1.0", "configured": False},
        "diff-coverage.json": {
            "schema_version": "1.0",
            "diff_name": "approved-base...current",
            "minimum_percent": 80.0,
            "num_changed_lines": 2,
            "src_stats": {"src/tests-incomplete.py": {}, "src/coverage-gap.py": {}},
        },
    }
    for name, document in documents.items():
        (report / name).write_text(json.dumps(document), encoding="utf-8")


def _closure_plan() -> dict[str, object]:
    items = []
    for suffix, alignment, priority in (
        ("A" * 12, "tests-incomplete", "P1"),
        ("B" * 12, "coverage-gap", "P2"),
    ):
        items.append(
            {
                "id": f"PYSEC-ACT-{suffix}",
                "category": "test-assurance",
                "priority": priority,
                "owner": "@team",
                "action": "Regenerate exact passing validation evidence.",
                "details": {
                    "validation_alignment": alignment,
                    "path": f"src/{alignment}.py",
                },
            }
        )
    return {
        "schema_version": "1.2",
        "summary": {
            "validation_alignment_items": 2,
            "codeowner_backed_validation_items": 2,
            "validation_items_with_failing_tests": 0,
            "validation_items_with_coverage_gaps": 1,
        },
        "items": items,
    }


def _operational_trend() -> dict[str, object]:
    return {
        "schema_version": "1.3",
        "summary": {
            "reports": 2,
            "first_scan": "scan-0",
            "last_scan": "scan-1",
            "latest_outcome": "incomplete",
            "latest_validation_alignment_items": 2,
        },
        "delta": {"validation_alignment_items": 1},
        "comparison": {
            "validation_evidence_comparable": True,
            "validation_comparability_reasons": [],
            "new_validation_subject_ids": ["PYSEC-ACT-BBBBBBBBBBBB"],
            "resolved_validation_subject_ids": [],
            "unchanged_validation_subject_ids": ["PYSEC-ACT-AAAAAAAAAAAA"],
            "validation_state_transitions": [],
        },
        "validation_owner_history": [
            {
                "owner": "@team",
                "first_subjects": 1,
                "latest_subjects": 2,
                "delta": 1,
                "comparable": True,
            }
        ],
        "anomalies": [
            {
                "kind": "validation-debt-regression",
                "severity": "block",
                "detail": "validation debt increased by one item",
            }
        ],
        "timeline": [
            {"scan_id": "scan-0", "checksums_sha256": "e" * 64},
            {"scan_id": "scan-1", "checksums_sha256": "f" * 64},
        ],
    }
