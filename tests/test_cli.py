from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from py_security_suite.cli import (
    _append_github_summary,
    _is_suite_report,
    _prepare_output,
    _render_attestation_verification,
    build_parser,
    main,
)
from py_security_suite.models import Outcome


class CliSafetyTests(unittest.TestCase):
    def test_parser_and_list_tools_are_available(self) -> None:
        parser = build_parser()
        parsed = parser.parse_args(["list-tools"])
        self.assertEqual(parsed.command, "list-tools")
        with patch("builtins.print") as output:
            self.assertEqual(main(["list-tools"]), 0)
        self.assertTrue(output.called)
        attest = parser.parse_args(
            ["attest", "report", "--output", "passport", "--unsigned"]
        )
        self.assertEqual(attest.command, "attest")
        connected_attest = parser.parse_args(
            [
                "attest",
                "report",
                "--output",
                "passport",
                "--signing-key",
                "key",
                "--allow-signing-network",
            ]
        )
        self.assertTrue(connected_attest.allow_signing_network)
        verify = parser.parse_args(
            ["verify", "passport", "--allow-unsigned", "--format", "text"]
        )
        self.assertEqual(verify.command, "verify")
        self.assertEqual(verify.format, "text")
        doctor = parser.parse_args(["doctor", ".", "--format", "json"])
        self.assertEqual(doctor.command, "doctor")
        verify_report = parser.parse_args(["verify-report", "report"])
        self.assertEqual(verify_report.command, "verify-report")
        inspect = parser.parse_args(["inspect", "report", "--limit", "3"])
        self.assertEqual(inspect.command, "inspect")

    def test_doctor_uses_readiness_exit_code_and_output_format(self) -> None:
        readiness = {
            "ready": False,
            "profile": "quick",
            "target": "fixture",
            "summary": {
                "ready": 3,
                "not_applicable": 0,
                "disabled": 0,
                "unavailable": 1,
            },
            "blocking_tools": ["semgrep"],
            "context_errors": [],
            "tools": [],
            "scope": "fixture",
        }
        with (
            patch("py_security_suite.cli.load_config"),
            patch("py_security_suite.cli.assess_readiness", return_value=readiness),
            patch("builtins.print") as output,
        ):
            code = main(["doctor", ".", "--profile", "quick", "--format", "json"])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(output.call_args.args[0])["ready"])

    def test_verify_report_has_concise_text_and_json_output(self) -> None:
        verification = {
            "verified": True,
            "file_count": 12,
            "checksums_sha256": "a" * 64,
            "scan_id": "scan-fixture",
            "outcome": "pass",
        }
        with (
            patch("py_security_suite.cli.verify_report", return_value=verification),
            patch("builtins.print") as output,
        ):
            self.assertEqual(main(["verify-report", "report"]), 0)
        self.assertIn("VERIFIED: 12 files", output.call_args.args[0])

        with (
            patch("py_security_suite.cli.verify_report", return_value=verification),
            patch("builtins.print") as output,
        ):
            self.assertEqual(main(["verify-report", "report", "--format", "json"]), 0)
        self.assertTrue(json.loads(output.call_args.args[0])["verified"])

    def test_passport_verification_text_separates_integrity_policy_and_approval(
        self,
    ) -> None:
        verification: dict[str, object] = {
            "verification_scope": "integrity-only",
            "passport_files_verified": 2,
            "report": {"file_count": 88},
            "outcome": "fail",
            "policy_verification_result": "FAILED",
            "release_decision": "not_approved",
            "release_blockers": [
                "signer_authenticity_not_verified",
                "scan_policy_not_satisfied",
            ],
        }
        rendered = _render_attestation_verification(verification)
        self.assertIn("VERIFIED (integrity only)", rendered)
        self.assertIn("Policy: FAIL (FAILED)", rendered)
        self.assertIn("release decision: NOT APPROVED", rendered)
        self.assertIn("signer authenticity not verified", rendered)

        with (
            patch(
                "py_security_suite.cli.verify_attestation",
                return_value=verification,
            ),
            patch("builtins.print") as output,
        ):
            code = main(["verify", "passport", "--format", "text"])
        self.assertEqual(code, 0)
        self.assertEqual(output.call_args.args[0], rendered)

    def test_inspect_report_supports_text_output(self) -> None:
        inspection = {
            "scan": {"outcome": "pass"},
            "findings": {"total": 0},
        }
        with (
            patch("py_security_suite.cli.inspect_report", return_value=inspection),
            patch("py_security_suite.cli.render_inspection", return_value="PASS"),
            patch("builtins.print") as output,
        ):
            self.assertEqual(main(["inspect", "report", "--limit", "3"]), 0)
        self.assertEqual(output.call_args.args[0], "PASS")

    def test_conflicting_isolation_flags_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.mkdir()
            code = main(
                [
                    "scan",
                    str(target),
                    "--output",
                    str(Path(directory) / "report"),
                    "--network-isolated",
                    "--diagnostic-without-isolation",
                ]
            )
        self.assertEqual(code, 3)

    def test_successful_scan_returns_policy_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.mkdir()
            output = Path(directory) / "report"
            result = SimpleNamespace(outcome=Outcome.PASS, findings=[])
            with patch("py_security_suite.cli.scan_project", return_value=result):
                code = main(
                    [
                        "scan",
                        str(target),
                        "--output",
                        str(output),
                        "--profile",
                        "quick",
                        "--network-isolated",
                    ]
                )
        self.assertEqual(code, 0)

    def test_overwrite_rejects_unmarked_nonempty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            output = root / "important"
            output.mkdir()
            (output / "user-data.txt").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                _prepare_output(target=target, output=output, overwrite=True)
            self.assertTrue((output / "user-data.txt").exists())

    def test_output_safety_rejects_target_file_and_unapproved_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            with self.assertRaisesRegex(ValueError, "cannot be the scan target"):
                _prepare_output(target=target, output=target, overwrite=False)

            containing = root / "container"
            nested_target = containing / "target"
            nested_target.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "cannot contain"):
                _prepare_output(
                    target=nested_target, output=containing, overwrite=False
                )

            output_file = root / "report.json"
            output_file.write_text("data", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "is not a directory"):
                _prepare_output(target=target, output=output_file, overwrite=True)

            empty = root / "empty"
            empty.mkdir()
            with self.assertRaisesRegex(ValueError, "use --overwrite"):
                _prepare_output(target=target, output=empty, overwrite=False)

    def test_output_safety_checks_links_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            output = root / "report"
            with patch.object(Path, "is_symlink", return_value=True):
                with self.assertRaisesRegex(ValueError, "symbolic link or junction"):
                    _prepare_output(target=target, output=output, overwrite=False)
            with (
                patch.object(Path, "is_symlink", return_value=False),
                patch.object(Path, "is_junction", return_value=True, create=True),
            ):
                with self.assertRaisesRegex(ValueError, "symbolic link or junction"):
                    _prepare_output(target=target, output=output, overwrite=False)

    def test_marked_report_can_be_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            output = root / "report"
            output.mkdir()
            marker = output / "scan-manifest.json"
            marker.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "suite_version": "0.1.0",
                        "scan_id": "scan-fixture",
                    }
                ),
                encoding="utf-8",
            )
            self.assertTrue(_is_suite_report(marker))
            _prepare_output(target=target, output=output, overwrite=True)
            self.assertFalse(output.exists())

    def test_bad_report_markers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.json"
            self.assertFalse(_is_suite_report(missing))
            invalid = root / "invalid.json"
            invalid.write_text("not-json", encoding="utf-8")
            self.assertFalse(_is_suite_report(invalid))
            wrong = root / "wrong.json"
            wrong.write_text('{"schema_version":"2"}', encoding="utf-8")
            self.assertFalse(_is_suite_report(wrong))

    def test_github_summary_requires_destination_and_appends(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = root / "summary.md"
            summary.write_text("# Result\n", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, "GITHUB_STEP_SUMMARY"):
                    _append_github_summary(summary)

            destination = root / "github-summary.md"
            with patch.dict(
                os.environ, {"GITHUB_STEP_SUMMARY": str(destination)}, clear=True
            ):
                _append_github_summary(summary)
            self.assertEqual(destination.read_text(encoding="utf-8"), "# Result\n\n")


if __name__ == "__main__":
    unittest.main()
