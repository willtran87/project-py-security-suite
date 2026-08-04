from __future__ import annotations

import hashlib
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
    _write_inspection_output,
    build_parser,
    main,
)
from py_security_suite.config import ConfigurationError
from py_security_suite.models import Outcome
from py_security_suite.passport import REQUIRED_REPORT_ARTIFACTS
from py_security_suite.reports import REPORT_FILES
from tests.report_fixtures import write_embedded_statement


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
            [
                "verify",
                "passport",
                "--allow-unsigned",
                "--artifact-root",
                "payload",
                "--format",
                "text",
            ]
        )
        self.assertEqual(verify.command, "verify")
        self.assertEqual(verify.artifact_root, Path("payload"))
        self.assertEqual(verify.format, "text")
        doctor = parser.parse_args(["doctor", ".", "--format", "json"])
        self.assertEqual(doctor.command, "doctor")
        verify_report = parser.parse_args(["verify-report", "report"])
        self.assertEqual(verify_report.command, "verify-report")
        verify_inspection = parser.parse_args(
            [
                "verify-inspection",
                "inspection.json",
                "--report",
                "report",
                "--format",
                "json",
                "--output",
                "verification.json",
                "--overwrite",
            ]
        )
        self.assertEqual(verify_inspection.command, "verify-inspection")
        self.assertEqual(verify_inspection.inspection, Path("inspection.json"))
        self.assertEqual(verify_inspection.report, Path("report"))
        self.assertEqual(verify_inspection.output, Path("verification.json"))
        self.assertTrue(verify_inspection.overwrite)
        inspect = parser.parse_args(
            [
                "inspect",
                "report",
                "--limit",
                "3",
                "--format",
                "json",
                "--output",
                "inspection.json",
                "--overwrite",
            ]
        )
        self.assertEqual(inspect.command, "inspect")
        self.assertEqual(inspect.output, Path("inspection.json"))
        self.assertTrue(inspect.overwrite)
        schema = parser.parse_args(
            [
                "schema",
                "report-inspection-verification-1.0",
                "--output",
                "schema.json",
                "--overwrite",
            ]
        )
        self.assertEqual(schema.command, "schema")
        self.assertEqual(schema.output, Path("schema.json"))
        self.assertTrue(schema.overwrite)

    def test_schema_prints_and_atomically_exports_an_installed_contract(self) -> None:
        schema_name = "report-inspection-1.0"
        with patch("builtins.print") as output:
            self.assertEqual(main(["schema", schema_name]), 0)
        printed = output.call_args.args[0]
        self.assertEqual(
            json.loads(printed)["$id"],
            "urn:project-py-security-suite:schema:report-inspection:1.0",
        )

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "contracts" / "inspection.schema.json"
            with patch("builtins.print") as exported:
                self.assertEqual(
                    main(
                        [
                            "schema",
                            schema_name,
                            "--output",
                            str(destination),
                        ]
                    ),
                    0,
                )
            self.assertEqual(destination.read_text(encoding="utf-8"), printed + "\n")
            self.assertEqual(exported.call_args.args[0], printed)
            self.assertEqual(list(destination.parent.glob("*.tmp")), [])

            original = destination.read_text(encoding="utf-8")
            with patch("builtins.print") as error_output:
                self.assertEqual(
                    main(
                        [
                            "schema",
                            "report-inspection-verification-1.0",
                            "--output",
                            str(destination),
                        ]
                    ),
                    3,
                )
            self.assertEqual(destination.read_text(encoding="utf-8"), original)
            self.assertIn("already exists", error_output.call_args.args[0])

            self.assertEqual(
                main(
                    [
                        "schema",
                        "report-inspection-verification-1.0",
                        "--output",
                        str(destination),
                        "--overwrite",
                    ]
                ),
                0,
            )
            self.assertIn(
                "report-inspection-verification:1.0",
                destination.read_text(encoding="utf-8"),
            )

    def test_schema_overwrite_requires_an_output(self) -> None:
        with patch("builtins.print") as error_output:
            code = main(["schema", "report-inspection-1.0", "--overwrite"])
        self.assertEqual(code, 3)
        self.assertIn("--overwrite requires --output", error_output.call_args.args[0])

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

    def test_verify_inspection_has_text_and_json_output(self) -> None:
        verification = {
            "schema_version": "1.0",
            "verified": True,
            "schema_id": "urn:inspection-verification",
            "inspection_schema_id": "urn:inspection",
            "scan_id": "scan-fixture",
            "inspection_sha256": "a" * 64,
            "report_checksums_sha256": "b" * 64,
            "action_limit": 5,
            "top_actions_verified": 2,
        }
        with (
            patch(
                "py_security_suite.cli.verify_inspection",
                return_value=verification,
            ) as verifier,
            patch("builtins.print") as output,
        ):
            code = main(
                [
                    "verify-inspection",
                    "inspection.json",
                    "--report",
                    "report",
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn(
            "VERIFIED: inspection for scan scan-fixture", output.call_args.args[0]
        )
        verifier.assert_called_once_with(
            Path("inspection.json"),
            report=Path("report"),
            limit=5,
        )

        with (
            patch(
                "py_security_suite.cli.verify_inspection",
                return_value=verification,
            ),
            patch("py_security_suite.cli._write_inspection_output") as writer,
            patch("builtins.print") as output,
        ):
            code = main(
                [
                    "verify-inspection",
                    "inspection.json",
                    "--report",
                    "report",
                    "--format",
                    "json",
                    "--output",
                    "verification.json",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.call_args.args[0]), verification)
        writer.assert_called_once_with(
            report=Path("report"),
            output=Path("verification.json"),
            content=json.dumps(verification, indent=2, sort_keys=True),
            overwrite=False,
        )

        for options, expected in (
            (["--overwrite"], "--overwrite requires --output"),
            (["--output", "verification.json"], "--output requires --format json"),
        ):
            with (
                self.subTest(options=options),
                patch("py_security_suite.cli.verify_inspection") as verifier,
                patch("builtins.print") as error_output,
            ):
                code = main(
                    [
                        "verify-inspection",
                        "inspection.json",
                        "--report",
                        "report",
                        *options,
                    ]
                )
            self.assertEqual(code, 3)
            verifier.assert_not_called()
            self.assertIn(expected, error_output.call_args.args[0])

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
            "release_artifacts_required": True,
            "release_artifacts_verified": False,
            "release_artifacts_verified_count": 0,
            "release_blockers": [
                "signer_authenticity_not_verified",
                "release_artifacts_not_verified",
                "scan_policy_not_satisfied",
            ],
        }
        rendered = _render_attestation_verification(verification)
        self.assertIn("VERIFIED (integrity only)", rendered)
        self.assertIn("Policy: FAIL (FAILED)", rendered)
        self.assertIn("release decision: NOT APPROVED", rendered)
        self.assertIn("release artifacts not supplied", rendered)
        self.assertIn("signer authenticity not verified", rendered)

        with (
            patch(
                "py_security_suite.cli.verify_attestation",
                return_value=verification,
            ) as verifier,
            patch("builtins.print") as output,
        ):
            code = main(
                [
                    "verify",
                    "passport",
                    "--artifact-root",
                    "payload",
                    "--format",
                    "text",
                ]
            )
        self.assertEqual(code, 1)
        self.assertEqual(output.call_args.args[0], rendered)
        self.assertEqual(verifier.call_args.kwargs["artifact_root"], Path("payload"))

        approved = {
            **verification,
            "verification_scope": "authenticity-and-integrity",
            "outcome": "pass",
            "policy_verification_result": "PASSED",
            "release_decision": "approved",
            "release_blockers": [],
        }
        with (
            patch(
                "py_security_suite.cli.verify_attestation",
                return_value=approved,
            ),
            patch("builtins.print"),
        ):
            code = main(["verify", "passport", "--format", "json"])
        self.assertEqual(code, 0)

        for error, expected_code in (
            (ConfigurationError("invalid policy"), "configuration_error"),
            (OSError("unavailable report"), "io_error"),
            (
                ValueError("unsafe\x1b[31m\u202e token=exposed"),
                "validation_error",
            ),
        ):
            with (
                self.subTest(expected_code=expected_code),
                patch("py_security_suite.cli.verify_attestation", side_effect=error),
                patch("builtins.print") as error_output,
            ):
                self.assertEqual(main(["verify", "passport", "--format", "json"]), 3)
            payload = json.loads(error_output.call_args.args[0])
            self.assertEqual(payload["status"], "error")
            self.assertEqual(payload["command"], "verify")
            self.assertEqual(payload["error"]["code"], expected_code)
            self.assertNotIn("exposed", payload["error"]["message"])
            self.assertNotIn("\x1b", payload["error"]["message"])
            self.assertNotIn("\u202e", payload["error"]["message"])

        with (
            patch(
                "py_security_suite.cli.verify_attestation",
                side_effect=ValueError("invalid\npassport"),
            ),
            patch("builtins.print") as text_error,
        ):
            self.assertEqual(main(["verify", "passport", "--format", "text"]), 3)
        self.assertEqual(
            text_error.call_args.args[0],
            "pysec: error [validation_error]: invalid�passport",
        )

        with (
            patch(
                "py_security_suite.cli.create_attestation",
                side_effect=ValueError("invalid report"),
            ),
            patch("builtins.print") as attest_error,
        ):
            self.assertEqual(
                main(["attest", "report", "--output", "passport", "--unsigned"]),
                3,
            )
        self.assertEqual(
            json.loads(attest_error.call_args.args[0])["command"], "attest"
        )

    def test_inspect_report_supports_text_output(self) -> None:
        inspection = {
            "scan": {"outcome": "pass"},
            "findings": {"total": 0},
        }
        with (
            patch("py_security_suite.cli.inspect_report", return_value=inspection),
            patch(
                "py_security_suite.cli.render_inspection", return_value="PASS"
            ) as renderer,
            patch("builtins.print") as output,
        ):
            self.assertEqual(main(["inspect", "report", "--limit", "3"]), 0)
        self.assertEqual(output.call_args.args[0], "PASS")
        renderer.assert_called_once_with(inspection, report_root=Path("report"))

    def test_inspect_can_atomically_publish_a_json_sidecar(self) -> None:
        inspection = {"schema_version": "1.0", "verified": True}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "sealed-report"
            report.mkdir()
            output_path = root / "publication" / "inspection.json"
            with (
                patch(
                    "py_security_suite.cli.inspect_report",
                    return_value=inspection,
                ),
                patch("builtins.print") as output,
            ):
                code = main(
                    [
                        "inspect",
                        str(report),
                        "--format",
                        "json",
                        "--output",
                        str(output_path),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output_path.read_text()), inspection)
            self.assertEqual(json.loads(output.call_args.args[0]), inspection)
            self.assertEqual(list(output_path.parent.glob("*.tmp")), [])

            with (
                patch(
                    "py_security_suite.cli.inspect_report",
                    return_value={"verified": False},
                ),
                patch("builtins.print") as error_output,
            ):
                code = main(
                    [
                        "inspect",
                        str(report),
                        "--format",
                        "json",
                        "--output",
                        str(output_path),
                    ]
                )
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(output_path.read_text()), inspection)
            error = json.loads(error_output.call_args.args[0])
            self.assertEqual(error["error"]["code"], "validation_error")

            with (
                patch(
                    "py_security_suite.cli.inspect_report",
                    return_value={"verified": False},
                ),
                patch("builtins.print"),
            ):
                code = main(
                    [
                        "inspect",
                        str(report),
                        "--format",
                        "json",
                        "--output",
                        str(output_path),
                        "--overwrite",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output_path.read_text()), {"verified": False})

    def test_inspection_output_cannot_modify_the_sealed_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "sealed-report"
            report.mkdir()
            output = report / "inspection.json"
            with self.assertRaisesRegex(ValueError, "outside the sealed report"):
                _write_inspection_output(
                    report=report,
                    output=output,
                    content="{}",
                    overwrite=False,
                )
            self.assertFalse(output.exists())

            existing_directory = Path(directory) / "inspection-output"
            existing_directory.mkdir()
            with self.assertRaisesRegex(ValueError, "is not a file"):
                _write_inspection_output(
                    report=report,
                    output=existing_directory,
                    content="{}",
                    overwrite=True,
                )

    def test_inspection_overwrite_requires_an_output(self) -> None:
        with (
            patch("py_security_suite.cli.inspect_report") as inspect,
            patch("builtins.print") as error_output,
        ):
            code = main(["inspect", "report", "--overwrite"])
        self.assertEqual(code, 3)
        inspect.assert_not_called()
        self.assertIn(
            "--overwrite requires --output",
            error_output.call_args.args[0],
        )

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

    def test_scan_target_link_is_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            with patch.object(Path, "is_junction", return_value=True, create=True):
                code = main(
                    [
                        "scan",
                        str(target),
                        "--output",
                        str(root / "report"),
                        "--profile",
                        "quick",
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

    def test_verified_complete_report_can_be_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            output = root / "report"
            output.mkdir()
            marker = output / "scan-manifest.json"
            manifest = {
                "schema_version": "1.0",
                "suite_version": "0.1.0",
                "scan_id": "scan-fixture",
                "target": "fixture",
                "profile": "standard",
                "outcome": "pass",
                "finished_at": "2026-08-03T00:00:00Z",
                "configuration_sha256": "b" * 64,
                "network_isolation_attested": True,
                "inventory": {
                    "source_sha256": "a" * 64,
                    "source_integrity_verified": True,
                },
                "finding_counts": {},
                "tools": [],
                "risk_acceptance_sha256": "",
                "intelligence": {},
                "baseline": {},
                "artifacts": REQUIRED_REPORT_ARTIFACTS,
            }
            marker.write_text(json.dumps(manifest), encoding="utf-8")
            for name in REPORT_FILES:
                path = output / name
                if path.name in {
                    "checksums.sha256",
                    "scan-manifest.json",
                    "security-passport.json",
                }:
                    continue
                path.write_text("fixture\n", encoding="utf-8")
            write_embedded_statement(output, manifest)
            entries = [
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
                f"{path.relative_to(output).as_posix()}"
                for path in sorted(output.rglob("*"))
                if path.is_file() and path.name != "checksums.sha256"
            ]
            (output / "checksums.sha256").write_text(
                "\n".join(entries) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            self.assertTrue(_is_suite_report(marker))
            summary = output / "summary.md"
            original_summary = summary.read_text(encoding="utf-8")
            summary.write_text("tampered\n", encoding="utf-8")
            self.assertFalse(_is_suite_report(marker))
            summary.write_text(original_summary, encoding="utf-8")
            self.assertTrue(_is_suite_report(marker))
            _prepare_output(target=target, output=output, overwrite=True)
            self.assertTrue(output.is_dir())
            self.assertTrue(_is_suite_report(marker))

    def test_incomplete_report_cannot_be_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            output = root / "report"
            output.mkdir()
            marker = output / "scan-manifest.json"
            marker.write_text(
                '{"schema_version":"1.0","suite_version":"0.1.0",'
                '"scan_id":"scan-fixture"}',
                encoding="utf-8",
            )
            self.assertFalse(_is_suite_report(marker))
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                _prepare_output(target=target, output=output, overwrite=True)
            self.assertTrue(marker.is_file())

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
