from __future__ import annotations

import hashlib
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import DEFAULT, patch

from py_security_suite.evidence_pack import (
    create_evidence_pack,
    verify_evidence_pack,
)


class EvidencePackTests(unittest.TestCase):
    def test_pack_round_trip_is_closed_bound_and_replaceable(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _pack_dependencies() as mocks:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            (report / "checksums.sha256").write_text(
                "sealed-report-checksums", encoding="ascii"
            )
            output = root / "evidence"
            created = create_evidence_pack(report, output)
            receipt = verify_evidence_pack(
                output,
                report=report,
                pack_sha256=created["pack"]["sha256"],
            )
            self.assertTrue(receipt["verified"])
            self.assertEqual(receipt["report"]["checksums_sha256"], "a" * 64)
            self.assertTrue((output / "COMPLETE").is_file())
            self.assertTrue((output / "report" / "checksums.sha256").is_file())
            self.assertIn("Promotion status", (output / "README.md").read_text())

            replaced = create_evidence_pack(report, output, overwrite=True)
            self.assertEqual(replaced["pack"]["sha256"], created["pack"]["sha256"])
            self.assertFalse(any(root.glob(".evidence.backup-*")))
            self.assertGreaterEqual(mocks["verify_audit_package"].call_count, 4)

    def test_pack_rejects_tampering_and_unexpected_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _pack_dependencies():
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            output = root / "evidence"
            created = create_evidence_pack(report, output)
            (output / "promotion-plan.md").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                verify_evidence_pack(output, report=report)

            second = root / "second"
            create_evidence_pack(report, second)
            (second / "unexpected.txt").write_text("extra", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "closed manifest"):
                verify_evidence_pack(second, report=report)
            with self.assertRaisesRegex(ValueError, "approved SHA-256"):
                verify_evidence_pack(
                    root / "evidence",
                    pack_sha256="b" * 64,
                )
            self.assertEqual(len(created["pack"]["sha256"]), 64)

    def test_failed_build_is_not_published(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _pack_dependencies() as mocks:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            output = root / "evidence"
            mocks["build_promotion_plan"].side_effect = ValueError("injected failure")
            with self.assertRaisesRegex(ValueError, "injected failure"):
                create_evidence_pack(report, output)
            self.assertFalse(output.exists())
            self.assertFalse(any(root.glob(".evidence.staging-*")))

    def test_output_cannot_modify_the_sealed_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _pack_dependencies():
            report = Path(directory) / "report"
            report.mkdir()
            with self.assertRaisesRegex(ValueError, "outside the sealed report"):
                create_evidence_pack(report, report / "derived")

    def test_optional_history_configuration_and_signing_are_integrated(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _pack_dependencies() as mocks:
            root = Path(directory)
            report = root / "report"
            previous = root / "previous"
            artifacts = root / "dist"
            for path in (report, previous, artifacts):
                path.mkdir()
            (report / "scan-manifest.json").write_text(
                '{"profile":"production"}', encoding="utf-8"
            )
            for path in (report / "reachability.json", previous / "reachability.json"):
                path.write_text("{}", encoding="utf-8")
            effectiveness = root / "effectiveness.json"
            passport = root / "passport.json"
            effectiveness.write_text(
                '{"schema_version":"1.0","verdict":"pass"}', encoding="utf-8"
            )
            passport.write_text(
                '{"schema_version":"1.0","verified":true}', encoding="utf-8"
            )
            effectiveness_digest = hashlib.sha256(
                effectiveness.read_bytes()
            ).hexdigest()
            passport_digest = hashlib.sha256(passport.read_bytes()).hexdigest()
            output = root / "evidence"
            create_evidence_pack(
                report,
                output,
                previous_report=previous,
                artifacts=artifacts,
                repository_config=root / "pysec.toml",
                profile_override="production",
                effectiveness_evaluation=effectiveness,
                effectiveness_sha256=effectiveness_digest,
                minimum_effectiveness_labels=40,
                minimum_effectiveness_positive_labels=20,
                minimum_effectiveness_negative_labels=20,
                minimum_effectiveness_tools=4,
                minimum_effectiveness_labels_per_tool=5,
                required_effectiveness_tools=("bandit", "semgrep"),
                passport_verification=passport,
                passport_verification_sha256=passport_digest,
                require_passport=True,
                performance_regression_percent=25.0,
                maximum_total_seconds=300.0,
                tool_budgets={"bandit": 20.0},
            )
            for name in (
                "previous-finding-register.json",
                "operational-trend.json",
                "reachability-delta.json",
                "config-provenance.json",
                "signing-request.json",
                "signing-request-verification.json",
                "effectiveness-evaluation.json",
                "passport-verification.json",
            ):
                self.assertTrue((output / name).is_file(), name)
            provenance = (output / "config-provenance.json").read_text()
            self.assertNotIn(str(root), provenance)
            self.assertEqual(mocks["build_finding_register"].call_count, 2)
            readiness = mocks["assess_release_readiness"].call_args.kwargs
            self.assertEqual(readiness["minimum_effectiveness_labels"], 40)
            self.assertEqual(
                readiness["required_effectiveness_tools"], ("bandit", "semgrep")
            )
            self.assertTrue(readiness["require_passport"])
            trend = mocks["build_operational_trend"].call_args.kwargs
            self.assertEqual(trend["performance_regression_percent"], 25.0)
            self.assertEqual(trend["maximum_total_seconds"], 300.0)
            self.assertEqual(trend["tool_budgets"], {"bandit": 20.0})
            required = mocks["verify_release_evidence_manifest"].call_args.kwargs[
                "required_evidence"
            ]
            self.assertIn("effectiveness-evaluation", required)
            self.assertIn("passport-verification", required)
            readme = (output / "README.md").read_text(encoding="utf-8")
            self.assertIn("approved labeled-corpus evaluation", readme)
            self.assertIn("approved signed-Passport verification", readme)
            retained_readiness = (output / "release-readiness.json").read_text(
                encoding="utf-8"
            )
            self.assertIn('"effectiveness-evaluation.json"', retained_readiness)
            self.assertIn('"passport-verification.json"', retained_readiness)
            self.assertNotIn(str(effectiveness), retained_readiness)
            self.assertNotIn(str(passport), retained_readiness)

    def test_pack_rejects_unpaired_governed_input_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory, _pack_dependencies():
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            with self.assertRaisesRegex(ValueError, "requires its input file"):
                create_evidence_pack(
                    report,
                    root / "evidence",
                    effectiveness_sha256="a" * 64,
                )
            self.assertFalse((root / "evidence").exists())


@contextmanager
def _pack_dependencies():
    with patch.multiple(
        "py_security_suite.evidence_pack",
        verify_report=DEFAULT,
        inspect_report=DEFAULT,
        verify_inspection=DEFAULT,
        assess_release_readiness=DEFAULT,
        build_governance_evidence_draft=DEFAULT,
        build_promotion_plan=DEFAULT,
        render_promotion_markdown=DEFAULT,
        render_promotion_html=DEFAULT,
        build_finding_register=DEFAULT,
        build_github_annotations=DEFAULT,
        render_github_commands=DEFAULT,
        build_audience_report=DEFAULT,
        render_audience_markdown=DEFAULT,
        build_baseline_candidate=DEFAULT,
        build_config_provenance=DEFAULT,
        build_operational_trend=DEFAULT,
        build_portfolio_dashboard=DEFAULT,
        compare_reachability=DEFAULT,
        prepare_signing_request=DEFAULT,
        verify_signing_request=DEFAULT,
        simulate_policy=DEFAULT,
        build_release_evidence_manifest=DEFAULT,
        verify_release_evidence_manifest=DEFAULT,
        create_audit_package=DEFAULT,
        verify_audit_package=DEFAULT,
    ) as mocks:
        verification = {
            "verified": True,
            "scan_id": "scan-1",
            "checksums_sha256": "a" * 64,
            "outcome": "pass",
            "file_count": 2,
        }
        bound = {
            "schema_version": "1.0",
            "report": {
                "scan_id": "scan-1",
                "checksums_sha256": "a" * 64,
            },
        }
        mocks["verify_report"].return_value = verification
        mocks["inspect_report"].return_value = bound
        mocks["verify_inspection"].return_value = bound
        mocks["assess_release_readiness"].return_value = {
            **bound,
            "controls": [
                {
                    "id": "detection-effectiveness",
                    "evidence": ["C:/outside/effectiveness.json"],
                },
                {
                    "id": "signed-release-passport",
                    "evidence": ["C:/outside/passport.json"],
                },
            ],
        }
        mocks["build_governance_evidence_draft"].return_value = bound
        mocks["build_promotion_plan"].return_value = {
            **bound,
            "schema_version": "1.1",
            "status": "blocked",
            "summary": {
                "active_findings": 1,
                "blocking_findings": 1,
                "release_blockers": 2,
                "evidence_quality_average": 90,
            },
        }
        mocks["render_promotion_markdown"].return_value = "# Plan\n"
        mocks["render_promotion_html"].return_value = "<h1>Plan</h1>\n"
        mocks["build_finding_register"].return_value = {
            **bound,
            "summary": {"open": 1, "overdue": 0},
        }
        mocks["build_github_annotations"].return_value = bound
        mocks["render_github_commands"].return_value = "::error::finding\n"
        mocks["build_audience_report"].side_effect = lambda *args, **kwargs: {
            **bound,
            "audience": kwargs["audience"],
        }
        mocks["render_audience_markdown"].return_value = "# Audience\n"
        for name in (
            "build_baseline_candidate",
            "build_operational_trend",
            "build_portfolio_dashboard",
            "compare_reachability",
            "prepare_signing_request",
            "verify_signing_request",
            "simulate_policy",
            "build_release_evidence_manifest",
            "verify_release_evidence_manifest",
        ):
            mocks[name].return_value = bound
        mocks["build_config_provenance"].return_value = {
            "schema_version": "1.0",
            "sources": {
                "organization": {"configured": False, "path": None},
                "repository": {
                    "configured": True,
                    "path": "C:/private/workspace/pysec.toml",
                },
            },
            "effective": {"profile": "production"},
        }

        def create_audit(_report, output, **_kwargs):
            Path(output).write_bytes(b"portable-audit")
            return {
                **bound,
                "package": {
                    "path": str(output),
                    "sha256": "c" * 64,
                    "files": 3,
                    "size_bytes": 14,
                },
            }

        mocks["create_audit_package"].side_effect = create_audit
        mocks["verify_audit_package"].return_value = {
            **bound,
            "verified": True,
            "package": {"path": "audit-package.zip", "files_verified": 3},
        }
        yield mocks
