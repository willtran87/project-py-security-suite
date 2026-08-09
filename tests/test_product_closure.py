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
from py_security_suite.operational_trend import build_operational_trend
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
            _write_trend_report(first, "2026-01-01T00:00:00Z", findings=2)
            _write_trend_report(last, "2026-02-01T00:00:00Z", findings=1)
            verify_mock.side_effect = lambda path: (
                _verification("scan-1", "a")
                if Path(path).name == "first"
                else _verification("scan-2", "b")
            )
            result = build_operational_trend([last, first])
        self.assertEqual(result["summary"]["reports"], 2)
        self.assertEqual(result["delta"]["active_findings"], -1)
        self.assertEqual(result["timeline"][0]["scan_id"], "scan-1")
        self.assertEqual(result["schema_version"], "1.1")
        self.assertEqual(result["scanner_history"][0]["completion_percent"], 100.0)
        _validate(result, "operational-trend-1.1.schema.json")

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
                {"schema_version": "1.2", "report": {"checksums_sha256": "f" * 64}},
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


def _write_trend_report(report: Path, finished_at: str, *, findings: int) -> None:
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


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _validate(document: dict[str, object], resource: str) -> None:
    schema = json.loads(
        files("py_security_suite").joinpath("schemas", resource).read_text("utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
