from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.baseline_candidate import build_baseline_candidate
from py_security_suite.operational_trend import (
    build_operational_trend,
    render_operational_trend_markdown,
)
from py_security_suite.release_manifest import (
    build_release_evidence_manifest,
    verify_release_evidence_manifest,
)


class ProductClosureTests(unittest.TestCase):
    @patch("py_security_suite.baseline_candidate.verify_report")
    def test_baseline_candidate_requires_revision_identity(self, verify_mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write(report / "findings.json", _findings("a" * 40))
            verify_mock.return_value = _verification("scan-1", "f")
            result = build_baseline_candidate(report)
        self.assertEqual(result["status"], "candidate")
        self.assertFalse(result["authoritative"])
        self.assertEqual(result["baseline"]["vcs_revision"], "a" * 40)
        _validate(result, "baseline-candidate.schema.json")

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write(report / "findings.json", _findings(""))
            verify_mock.return_value = _verification("scan-2", "e")
            result = build_baseline_candidate(report)
        self.assertEqual(result["status"], "ineligible")

    @patch("py_security_suite.operational_trend.verify_report")
    def test_trend_compares_distinct_sealed_reports(self, verify_mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, last = root / "first", root / "last"
            first.mkdir()
            last.mkdir()
            _write_trend_report(first, "2026-01-01T00:00:00Z", findings=2, validation=2)
            _write_trend_report(last, "2026-02-01T00:00:00Z", findings=1, validation=1)
            verify_mock.side_effect = lambda path: (
                _verification("scan-1", "a")
                if Path(path).name == "first"
                else _verification("scan-2", "b")
            )
            result = build_operational_trend([last, first])
        self.assertEqual(result["summary"]["reports"], 2)
        self.assertEqual(result["delta"]["active_findings"], -1)
        self.assertEqual(result["timeline"][0]["scan_id"], "scan-1")
        self.assertEqual(result["schema_version"], "1.3")
        self.assertEqual(result["scanner_history"][0]["completion_percent"], 100.0)
        self.assertEqual(result["delta"]["validation_alignment_items"], -1)
        self.assertTrue(result["comparison"]["validation_evidence_comparable"])
        self.assertEqual(
            result["comparison"]["resolved_validation_subject_ids"],
            ["PYSEC-ACT-VALIDATION-1"],
        )
        self.assertEqual(result["validation_owner_history"][0]["delta"], -1)
        markdown = render_operational_trend_markdown(result)
        self.assertIn("# Operational assurance trend", markdown)
        self.assertIn("## Validation continuity", markdown)
        self.assertIn("### Validation owner queues", markdown)
        self.assertIn("`@runtime-team`", markdown)
        self.assertIn("## Scanner reliability", markdown)
        _validate(result, "operational-trend-1.3.schema.json")

        with self.assertRaisesRegex(ValueError, "between 2 and 100"):
            build_operational_trend([Path("one")])

    @patch("py_security_suite.operational_trend.verify_report")
    def test_trend_reports_absolute_performance_budgets(self, verify_mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, last = root / "first", root / "last"
            first.mkdir()
            last.mkdir()
            _write_trend_report(first, "2026-01-01T00:00:00Z", findings=0)
            _write_trend_report(last, "2026-02-01T00:00:00Z", findings=0)
            verify_mock.side_effect = [
                _verification("scan-1", "a"),
                _verification("scan-2", "b"),
            ]
            result = build_operational_trend(
                [first, last],
                maximum_total_seconds=0.1,
                tool_budgets={"bandit": 0.1},
            )
        kinds = {item["kind"] for item in result["anomalies"]}
        self.assertIn("scan-performance-budget-exceeded", kinds)
        self.assertIn("scanner-performance-budget-exceeded", kinds)

    @patch("py_security_suite.operational_trend.verify_report")
    def test_trend_reports_validation_state_and_ownership_regressions(
        self, verify_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, last = root / "first", root / "last"
            first.mkdir()
            last.mkdir()
            _write_trend_report(
                first,
                "2026-01-01T00:00:00Z",
                findings=0,
                validation=1,
                validation_state="coverage-gap",
                validation_owner="@runtime-team",
            )
            _write_trend_report(
                last,
                "2026-02-01T00:00:00Z",
                findings=0,
                validation=1,
                validation_state="tests-failing",
                validation_owner="quality-engineering",
                ownership_rule_matched=False,
            )
            verify_mock.side_effect = [
                _verification("scan-1", "a"),
                _verification("scan-2", "b"),
            ]
            result = build_operational_trend([first, last])

        transitions = result["comparison"]["validation_state_transitions"]
        self.assertEqual(len(transitions), 1)
        self.assertEqual(transitions[0]["alignment_before"], "coverage-gap")
        self.assertEqual(transitions[0]["alignment_after"], "tests-failing")
        self.assertEqual(transitions[0]["owner_before"], "@runtime-team")
        self.assertEqual(transitions[0]["owner_after"], "quality-engineering")
        kinds = {item["kind"] for item in result["anomalies"]}
        self.assertIn("validation-state-regression", kinds)
        self.assertIn("validation-ownership-regression", kinds)

    @patch("py_security_suite.operational_trend.verify_report")
    def test_trend_does_not_treat_missing_validation_evidence_as_zero_debt(
        self, verify_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, last = root / "first", root / "last"
            first.mkdir()
            last.mkdir()
            _write_trend_report(first, "2026-01-01T00:00:00Z", findings=0)
            _write_trend_report(last, "2026-02-01T00:00:00Z", findings=0)
            (first / "closure-plan.json").unlink()
            verify_mock.side_effect = [
                _verification("scan-1", "a"),
                _verification("scan-2", "b"),
            ]
            result = build_operational_trend([first, last])

        self.assertFalse(result["comparison"]["validation_evidence_comparable"])
        self.assertEqual(result["comparison"]["new_validation_subject_ids"], [])
        self.assertIn(
            "validation-evidence-comparability-gap",
            {item["kind"] for item in result["anomalies"]},
        )

    @patch("py_security_suite.operational_trend.verify_report")
    def test_trend_does_not_treat_missing_change_assessment_as_resolved_debt(
        self, verify_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, last = root / "first", root / "last"
            first.mkdir()
            last.mkdir()
            _write_trend_report(first, "2026-01-01T00:00:00Z", findings=0, validation=2)
            _write_trend_report(last, "2026-02-01T00:00:00Z", findings=0, validation=0)
            (last / "diff-coverage.json").unlink()
            verify_mock.side_effect = [
                _verification("scan-1", "a"),
                _verification("scan-2", "b"),
            ]
            result = build_operational_trend([first, last])

        self.assertFalse(result["comparison"]["validation_evidence_comparable"])
        self.assertEqual(result["comparison"]["resolved_validation_subject_ids"], [])
        self.assertIn(
            "latest report lacks retained diff-coverage change-assessment scope",
            result["comparison"]["validation_comparability_reasons"],
        )
        self.assertFalse(result["validation_owner_history"][0]["comparable"])
        self.assertIsNone(result["validation_owner_history"][0]["delta"])
        markdown = render_operational_trend_markdown(result)
        self.assertIn("no new or resolved debt claim is made", markdown)
        self.assertIn("lacks retained diff-coverage", markdown)

    @patch("py_security_suite.release_manifest.verify_report")
    def test_release_manifest_binds_every_digest_to_report(self, verify_mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            evidence = root / "readiness.json"
            _write(
                evidence,
                {
                    "schema_version": "1.2",
                    "status": "candidate",
                    "decision": "approved",
                    "blockers": [],
                    "report": {"checksums_sha256": "f" * 64},
                },
            )
            digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
            verify_mock.return_value = _verification("scan-1", "f")
            result = build_release_evidence_manifest(
                report, evidence=(("release-readiness", evidence, digest),)
            )
            self.assertTrue(result["closed_set"])
            self.assertFalse(result["authoritative"])
            self.assertEqual(result["evidence"][0]["sha256"], digest)
            _validate(result, "release-evidence-manifest.schema.json")

            verify_mock.return_value = _verification("scan-1", "f")
            with self.assertRaisesRegex(ValueError, "does not match"):
                build_release_evidence_manifest(
                    report, evidence=(("release-readiness", evidence, "0" * 64),)
                )

    @patch("py_security_suite.release_manifest.verify_report")
    def test_release_manifest_verification_rechecks_closed_set(
        self, verify_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            evidence = root / "readiness.json"
            _write(
                evidence,
                {
                    "schema_version": "1.2",
                    "status": "candidate",
                    "decision": "approved",
                    "blockers": [],
                    "report": {"checksums_sha256": "f" * 64},
                },
            )
            digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
            verify_mock.return_value = _verification("scan-1", "f")
            manifest = build_release_evidence_manifest(
                report, evidence=(("release-readiness", evidence, digest),)
            )
            manifest_path = root / "manifest.json"
            _write(manifest_path, manifest)
            manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            receipt = verify_release_evidence_manifest(
                manifest_path,
                manifest_sha256=manifest_digest,
                report=report,
                required_evidence=("release-readiness",),
            )
            self.assertTrue(receipt["verified"])
            self.assertFalse(receipt["authoritative"])
            self.assertEqual(receipt["admission"], "requires_external_approval")
            _validate(receipt, "release-evidence-manifest-verification.schema.json")

            with self.assertRaisesRegex(ValueError, "missing required"):
                verify_release_evidence_manifest(
                    manifest_path,
                    manifest_sha256=manifest_digest,
                    report=report,
                    required_evidence=("passport-verification",),
                )

            with (
                patch.dict(
                    "os.environ", {"PYSEC_REQUIRE_HARDENED_RELEASE_EVIDENCE": "1"}
                ),
                self.assertRaisesRegex(ValueError, "check-manifest"),
            ):
                verify_release_evidence_manifest(
                    manifest_path,
                    manifest_sha256=manifest_digest,
                    report=report,
                )

            verify_mock.return_value = _verification("scan-1", "e")
            with self.assertRaisesRegex(ValueError, "not bound"):
                build_release_evidence_manifest(
                    report, evidence=(("release-readiness", evidence, digest),)
                )

            verify_mock.return_value = _verification("scan-1", "f")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                build_release_evidence_manifest(
                    report,
                    evidence=(
                        ("release-readiness", evidence, digest),
                        ("release-readiness", evidence, digest),
                    ),
                )


def _verification(scan_id: str, digest_character: str) -> dict[str, object]:
    return {
        "scan_id": scan_id,
        "checksums_sha256": digest_character * 64,
        "outcome": "pass",
        "file_count": 10,
    }


def _findings(revision: str) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "profile": "production",
        "selected_tools": ["bandit"],
        "source_sha256": "c" * 64,
        "vcs_revision": revision,
        "findings": [],
    }


def _write_trend_report(
    report: Path,
    finished_at: str,
    *,
    findings: int,
    validation: int = 0,
    validation_state: str = "coverage-gap",
    validation_owner: str = "@runtime-team",
    ownership_rule_matched: bool = True,
) -> None:
    _write(
        report / "scan-manifest.json",
        {
            "finished_at": finished_at,
            "profile": "production",
            "tools": [
                {
                    "tool": "bandit",
                    "applicable": True,
                    "status": "completed",
                    "version": "1.0",
                    "duration_seconds": 1.0,
                    "executable_unchanged": True,
                }
            ],
        },
    )
    _write(
        report / "findings.json",
        {
            "source_sha256": "c" * 64,
            "vcs_revision": "d" * 40,
            "findings": [
                {"status": "new", "blocking": index == 0} for index in range(findings)
            ],
        },
    )
    _write(
        report / "portfolio-health.json",
        {"overall": {"domains_with_execution_gaps": 0}},
    )
    _write(
        report / "closure-plan.json",
        {
            "schema_version": "1.2",
            "summary": {
                "validation_alignment_items": validation,
                "codeowner_backed_validation_items": (
                    validation if ownership_rule_matched else 0
                ),
                "validation_items_with_failing_tests": (
                    validation if validation_state == "tests-failing" else 0
                ),
                "validation_items_with_coverage_gaps": (
                    validation if validation_state == "coverage-gap" else 0
                ),
            },
            "items": [
                {
                    "id": f"PYSEC-ACT-VALIDATION-{index}",
                    "priority": "P1" if validation_state == "tests-failing" else "P2",
                    "owner": validation_owner,
                    "details": {
                        "path": f"src/component_{index}.py",
                        "owners": (
                            [validation_owner] if ownership_rule_matched else []
                        ),
                        "ownership_rule_matched": ownership_rule_matched,
                        "validation_alignment": validation_state,
                    },
                }
                for index in range(validation)
            ],
        },
    )
    _write(
        report / "diff-coverage.json",
        {
            "schema_version": "1.0",
            "diff_name": "approved-base...current",
            "minimum_percent": 80.0,
            "num_changed_lines": validation,
            "src_stats": {
                f"src/component_{index}.py": {} for index in range(validation)
            },
        },
    )


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _validate(document: dict[str, object], resource: str) -> None:
    schema = json.loads(
        files("py_security_suite").joinpath("schemas", resource).read_text("utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
