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
        help_text = parser.format_help()
        self.assertIn("Start here:", help_text)
        self.assertIn("pysec init PROJECT --template library", help_text)
        self.assertIn("pysec inspect PROJECT/.artifacts/pysec-report", help_text)
        parsed = parser.parse_args(["list-tools"])
        self.assertEqual(parsed.command, "list-tools")
        adapter_check = parser.parse_args(
            ["adapter-check", "--format", "json", "--output", "adapters.json"]
        )
        self.assertEqual(adapter_check.command, "adapter-check")
        self.assertEqual(adapter_check.output, Path("adapters.json"))
        generate_ci = parser.parse_args(
            [
                "generate-ci",
                ".",
                "--checkout-sha",
                "a" * 40,
                "--upload-artifact-sha",
                "b" * 40,
                "--upload-sarif-sha",
                "c" * 40,
            ]
        )
        self.assertEqual(generate_ci.command, "generate-ci")
        self.assertEqual(generate_ci.profile, "production")
        generate_hooks = parser.parse_args(["generate-hooks", "."])
        self.assertEqual(generate_hooks.command, "generate-hooks")
        self.assertEqual(generate_hooks.profile, "quick")
        qualification = parser.parse_args(
            ["qualify-bundle", ".", "--profile", "production"]
        )
        self.assertEqual(qualification.command, "qualify-bundle")
        bundle_verification = parser.parse_args(
            [
                "verify-native-bundle",
                "bundle",
                "--manifest-sha256",
                "a" * 64,
                "--require-wheelhouse-closure",
            ]
        )
        self.assertEqual(bundle_verification.command, "verify-native-bundle")
        self.assertTrue(bundle_verification.require_wheelhouse_closure)
        config_check = parser.parse_args(["config-check", "--config", "pysec.toml"])
        self.assertEqual(config_check.command, "config-check")
        with patch("builtins.print") as output:
            self.assertEqual(main(["list-tools"]), 0)
        self.assertTrue(output.called)
        initialize = parser.parse_args(
            ["init", ".", "--template", "worker", "--profile", "comprehensive"]
        )
        self.assertEqual(initialize.command, "init")
        self.assertEqual(initialize.template, "worker")
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
        prepare_signing = parser.parse_args(
            [
                "prepare-signing",
                "report",
                "dist",
                "--output",
                "signing-request.json",
            ]
        )
        self.assertEqual(prepare_signing.command, "prepare-signing")
        verify_signing = parser.parse_args(
            [
                "verify-signing-request",
                "signing-request.json",
                "dist",
                "--request-sha256",
                "a" * 64,
            ]
        )
        self.assertEqual(verify_signing.command, "verify-signing-request")

    def test_onboarding_generators_and_receipts_publish_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            config = target / "pysec.toml"
            config.write_text(
                'schema_version = "1"\nprofile = "quick"\n', encoding="utf-8"
            )

            hook_output = target / "generated-precommit.yaml"
            with patch("builtins.print") as hook_text:
                self.assertEqual(
                    main(
                        [
                            "generate-hooks",
                            str(target),
                            "--config",
                            "pysec.toml",
                            "--output",
                            str(hook_output),
                        ]
                    ),
                    0,
                )
            self.assertIn("repo: local", hook_output.read_text(encoding="utf-8"))
            self.assertIn("GENERATED:", hook_text.call_args.args[0])

            workflow_output = target / ".github" / "workflows" / "security.yml"
            with patch("builtins.print") as workflow_text:
                self.assertEqual(
                    main(
                        [
                            "generate-ci",
                            str(target),
                            "--output",
                            str(workflow_output),
                            "--checkout-sha",
                            "a" * 40,
                            "--upload-artifact-sha",
                            "b" * 40,
                            "--upload-sarif-sha",
                            "c" * 40,
                        ]
                    ),
                    0,
                )
            self.assertIn(
                "actions/checkout@", workflow_output.read_text(encoding="utf-8")
            )
            self.assertIn("GENERATED:", workflow_text.call_args.args[0])

            advice_output = target / "config-advice.json"
            with patch("builtins.print") as advice_text:
                self.assertEqual(
                    main(
                        [
                            "config-check",
                            "--config",
                            str(config),
                            "--format",
                            "json",
                            "--output",
                            str(advice_output),
                        ]
                    ),
                    0,
                )
            advice = json.loads(advice_output.read_text(encoding="utf-8"))
            self.assertEqual(advice["decision"], "valid")
            self.assertEqual(json.loads(advice_text.call_args.args[0]), advice)

            qualification_output = target / "qualification.json"
            qualification = {
                "decision": {"disposition": "qualify"},
                "schema_version": "1.0",
            }
            with (
                patch(
                    "py_security_suite.cli.qualify_bundle",
                    return_value=qualification,
                ),
                patch("builtins.print") as qualification_text,
            ):
                self.assertEqual(
                    main(
                        [
                            "qualify-bundle",
                            str(target),
                            "--profile",
                            "quick",
                            "--format",
                            "json",
                            "--output",
                            str(qualification_output),
                        ]
                    ),
                    0,
                )
            self.assertEqual(
                json.loads(qualification_output.read_text(encoding="utf-8")),
                qualification,
            )
            self.assertEqual(
                json.loads(qualification_text.call_args.args[0]), qualification
            )
        parser = build_parser()
        promotion = parser.parse_args(
            [
                "promotion-plan",
                "report",
                "--release-readiness",
                "readiness.json",
                "--release-readiness-sha256",
                "b" * 64,
            ]
        )
        self.assertEqual(promotion.command, "promotion-plan")
        closure = parser.parse_args(
            [
                "closure-plan",
                "report",
                "--coverage-target",
                "92",
                "--hotspot-limit",
                "5",
            ]
        )
        self.assertEqual(closure.command, "closure-plan")
        self.assertEqual(closure.coverage_target, 92.0)
        self.assertEqual(closure.hotspot_limit, 5)
        baseline = parser.parse_args(["baseline-candidate", "report"])
        self.assertEqual(baseline.command, "baseline-candidate")
        trend = parser.parse_args(["trend", "before", "after"])
        self.assertEqual(trend.reports, [Path("before"), Path("after")])
        release_manifest = parser.parse_args(
            [
                "release-manifest",
                "report",
                "--evidence",
                f"readiness=readiness.json@{'a' * 64}",
            ]
        )
        self.assertEqual(release_manifest.command, "release-manifest")
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
        doctor_markdown = parser.parse_args(
            [
                "doctor",
                ".",
                "--format",
                "markdown",
                "--explain",
                "--output",
                "preflight.md",
            ]
        )
        self.assertTrue(doctor_markdown.explain)
        self.assertEqual(doctor_markdown.output, Path("preflight.md"))
        provision = parser.parse_args(
            ["provision-plan", ".", "--format", "markdown", "--output", "plan.md"]
        )
        self.assertEqual(provision.command, "provision-plan")
        self.assertEqual(provision.output, Path("plan.md"))
        verify_report = parser.parse_args(
            [
                "verify-report",
                "report",
                "--format",
                "json",
                "--output",
                "verification.json",
                "--overwrite",
            ]
        )
        self.assertEqual(verify_report.command, "verify-report")
        self.assertEqual(verify_report.output, Path("verification.json"))
        self.assertTrue(verify_report.overwrite)
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
                "report-inspection-verification-1.3",
                "--output",
                "schema.json",
                "--overwrite",
            ]
        )
        self.assertEqual(schema.command, "schema")
        self.assertEqual(schema.output, Path("schema.json"))
        self.assertTrue(schema.overwrite)
        reachability = parser.parse_args(
            [
                "reachability",
                ".",
                "--source-root",
                "src",
                "--entry-point",
                "package.cli:main",
                "--minimum-island-loc",
                "250",
                "--no-framework-roots",
            ]
        )
        self.assertEqual(reachability.command, "reachability")
        self.assertEqual(reachability.source_root, ["src"])
        self.assertEqual(reachability.entry_point, ["package.cli:main"])
        self.assertEqual(reachability.minimum_island_loc, 250)
        self.assertTrue(reachability.no_framework_roots)

    def test_reachability_command_emits_machine_readable_graph(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch("builtins.print") as output:
                self.assertEqual(
                    main(["reachability", directory, "--pretty"]),
                    0,
                )
        document = json.loads(output.call_args.args[0])
        self.assertEqual(document["schema_version"], "1.2")
        self.assertFalse(document["analysis"]["target_code_executed"])
        self.assertEqual(document["summary"]["entry_points"], 0)

    def test_schema_prints_and_atomically_exports_an_installed_contract(self) -> None:
        schema_name = "report-inspection-1.3"
        with patch("builtins.print") as output:
            self.assertEqual(main(["schema", schema_name]), 0)
        printed = output.call_args.args[0]
        self.assertEqual(
            json.loads(printed)["$id"],
            "urn:project-py-security-suite:schema:report-inspection:1.3",
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

    def test_doctor_atomically_exports_markdown(self) -> None:
        readiness = {
            "schema_version": "1.1",
            "schema_id": "urn:project-py-security-suite:schema:doctor-readiness:1.1",
            "ready": False,
            "profile": "quick",
            "target": "fixture",
            "summary": {
                "selected": 1,
                "ready": 0,
                "applicable": 1,
                "required_ready": 0,
                "required_applicable": 1,
                "not_applicable": 0,
                "attention": 1,
                "missing_approvals": 0,
            },
            "next_actions": [
                {
                    "priority": "P0",
                    "blocking": True,
                    "subject": "bandit",
                    "category": "unavailable",
                    "reason": "approved executable is missing",
                    "required_action": "Restore the approved executable.",
                }
            ],
            "tools": [
                {
                    "tool": "bandit",
                    "status": "unavailable",
                    "category": "unavailable",
                    "required": True,
                }
            ],
            "scope": "fixture",
        }
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "preflight.md"
            with (
                patch("py_security_suite.cli.load_config"),
                patch("py_security_suite.cli.assess_readiness", return_value=readiness),
                patch("builtins.print") as output,
            ):
                code = main(
                    [
                        "doctor",
                        ".",
                        "--format",
                        "markdown",
                        "--output",
                        str(destination),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertEqual(
                destination.read_text(encoding="utf-8").rstrip(),
                output.call_args.args[0],
            )
            self.assertIn("| P0 | BLOCK | `bandit`", output.call_args.args[0])
            original = destination.read_text(encoding="utf-8")
            with (
                patch("py_security_suite.cli.load_config"),
                patch("py_security_suite.cli.assess_readiness", return_value=readiness),
                patch("builtins.print") as error,
            ):
                self.assertEqual(
                    main(
                        [
                            "doctor",
                            ".",
                            "--format",
                            "markdown",
                            "--output",
                            str(destination),
                        ]
                    ),
                    3,
                )
            self.assertEqual(destination.read_text(encoding="utf-8"), original)
            self.assertIn("already exists", error.call_args.args[0])

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
        receipt = json.loads(output.call_args.args[0])
        self.assertTrue(receipt["verified"])
        self.assertEqual(
            receipt["schema_id"],
            "urn:project-py-security-suite:schema:report-verification:1.0",
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            destination = root / "receipts" / "report-verification.json"
            with (
                patch(
                    "py_security_suite.cli.verify_report",
                    return_value=verification,
                ),
                patch("builtins.print") as output,
            ):
                self.assertEqual(
                    main(
                        [
                            "verify-report",
                            str(report),
                            "--format",
                            "json",
                            "--output",
                            str(destination),
                        ]
                    ),
                    0,
                )
            self.assertEqual(json.loads(destination.read_text()), receipt)
            self.assertEqual(json.loads(output.call_args.args[0]), receipt)

            with (
                patch(
                    "py_security_suite.cli.verify_report",
                    return_value=verification,
                ),
                patch("builtins.print") as error_output,
            ):
                self.assertEqual(
                    main(
                        [
                            "verify-report",
                            str(report),
                            "--format",
                            "json",
                            "--output",
                            str(destination),
                        ]
                    ),
                    3,
                )
            self.assertEqual(json.loads(destination.read_text()), receipt)
            self.assertIn("already exists", error_output.call_args.args[0])

        for options, expected in (
            (["--overwrite"], "--overwrite requires --output"),
            (["--output", "verification.json"], "--output requires --format json"),
        ):
            with (
                self.subTest(options=options),
                patch("py_security_suite.cli.verify_report") as verifier,
                patch("builtins.print") as error_output,
            ):
                code = main(["verify-report", "report", *options])
            self.assertEqual(code, 3)
            verifier.assert_not_called()
            self.assertIn(expected, error_output.call_args.args[0])

    def test_release_check_and_reachability_diff_publish_decisions(self) -> None:
        readiness = {
            "decision": "not_approved",
            "summary": {"passed": 6, "controls": 8},
            "blockers": ["external-isolation", "scanner-trust"],
        }
        delta = {
            "verdict": "regression",
            "counts": {
                "state_regressions": 1,
                "new_disconnected_nodes": 2,
                "new_reportable_islands": 1,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            readiness_output = root / "release-readiness.json"
            delta_output = root / "reachability-delta.json"
            with (
                patch(
                    "py_security_suite.cli.assess_release_readiness",
                    return_value=readiness,
                ) as assessor,
                patch("builtins.print") as output,
            ):
                code = main(
                    [
                        "release-check",
                        "report",
                        "--format",
                        "json",
                        "--output",
                        str(readiness_output),
                    ]
                )
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(readiness_output.read_text()), readiness)
            self.assertEqual(json.loads(output.call_args.args[0]), readiness)
            assessor.assert_called_once()

            with (
                patch(
                    "py_security_suite.cli.compare_reachability", return_value=delta
                ) as comparator,
                patch("builtins.print") as output,
            ):
                code = main(
                    [
                        "reachability-diff",
                        "before.json",
                        "after.json",
                        "--baseline-sha256",
                        "a" * 64,
                        "--current-sha256",
                        "b" * 64,
                        "--format",
                        "json",
                        "--output",
                        str(delta_output),
                    ]
                )
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(delta_output.read_text()), delta)
            self.assertEqual(json.loads(output.call_args.args[0]), delta)
            comparator.assert_called_once()

    def test_evidence_draft_publishes_non_authoritative_handoff(self) -> None:
        draft = {
            "status": "candidate",
            "scanner_trust_candidates": [{"tool": "bandit"}],
            "intelligence_candidates": [{"kind": "kev"}],
            "artifact_signing_candidates": [{"path": "dist/project.whl"}],
        }
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "governance-evidence-draft.json"
            with (
                patch(
                    "py_security_suite.cli.build_governance_evidence_draft",
                    return_value=draft,
                ) as builder,
                patch("builtins.print") as output,
            ):
                code = main(
                    [
                        "evidence-draft",
                        "report",
                        "--format",
                        "json",
                        "--output",
                        str(destination),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(destination.read_text()), draft)
            self.assertEqual(json.loads(output.call_args.args[0]), draft)
            builder.assert_called_once()

    def test_product_closure_commands_publish_machine_outputs(self) -> None:
        baseline = {
            "status": "candidate",
            "baseline": {"sha256": "a" * 64},
        }
        trend = {
            "summary": {"reports": 2, "latest_outcome": "pass"},
            "timeline": [],
        }
        release_manifest = {
            "evidence": [{"name": "readiness"}],
            "manifest_id": "b" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (
                    [
                        "baseline-candidate",
                        "report",
                        "--format",
                        "json",
                        "--output",
                        str(root / "baseline.json"),
                    ],
                    "py_security_suite.cli.build_baseline_candidate",
                    baseline,
                ),
                (
                    [
                        "trend",
                        "before",
                        "after",
                        "--format",
                        "json",
                        "--output",
                        str(root / "trend.json"),
                    ],
                    "py_security_suite.cli.build_operational_trend",
                    trend,
                ),
                (
                    [
                        "release-manifest",
                        "report",
                        "--evidence",
                        f"readiness=readiness.json@{'a' * 64}",
                        "--format",
                        "json",
                        "--output",
                        str(root / "manifest.json"),
                    ],
                    "py_security_suite.cli.build_release_evidence_manifest",
                    release_manifest,
                ),
            )
            for arguments, target, expected in cases:
                with (
                    self.subTest(command=arguments[0]),
                    patch(target, return_value=expected),
                    patch("builtins.print") as output,
                ):
                    self.assertEqual(main(arguments), 0)
                    self.assertEqual(json.loads(output.call_args.args[0]), expected)

        with patch("builtins.print") as output:
            self.assertEqual(
                main(
                    [
                        "release-manifest",
                        "report",
                        "--evidence",
                        "invalid",
                    ]
                ),
                3,
            )
        self.assertIn("NAME=PATH@SHA256", output.call_args.args[0])

    def test_maturity_commands_have_stable_cli_surfaces(self) -> None:
        digest = "a" * 64
        register = {"summary": {"open": 1, "resolved": 2, "overdue": 0}}
        annotations: dict[str, object] = {"annotations": []}
        audit_created = {"package": {"files": 3, "sha256": digest}}
        audit_verified = {"package": {"files_verified": 3}}
        coverage = {
            "pysec_merge": {"scenario_count": 2, "executed_lines": 8},
            "files": {},
        }
        portfolio = {"summary": {"reports": 2, "blocking_findings": 0}}
        provenance = {"summary": {"facts": 4, "security_sensitive_facts": 1}}
        audience = {
            "audience": "developer",
            "status": "ready",
            "report": {"scan_id": "scan-1"},
        }
        evidence_pack = {"pack": {"sha256": digest}}
        evidence_pack_verification = {"verified": True}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "coverage.json"
            cases = (
                (
                    ["finding-register", "report"],
                    "py_security_suite.cli.build_finding_register",
                    register,
                ),
                (
                    [
                        "github-annotations",
                        "plan.json",
                        "--plan-sha256",
                        digest,
                        "--report",
                        "report",
                    ],
                    "py_security_suite.cli.build_github_annotations",
                    annotations,
                ),
                (
                    ["audit-package", "report", "--output", "audit.zip"],
                    "py_security_suite.cli.create_audit_package",
                    audit_created,
                ),
                (
                    [
                        "verify-audit-package",
                        "audit.zip",
                        "--package-sha256",
                        digest,
                    ],
                    "py_security_suite.cli.verify_audit_package",
                    audit_verified,
                ),
                (
                    [
                        "merge-coverage",
                        "--scenario",
                        f"api=api.json@{digest}",
                        "--scenario",
                        f"worker=worker.json@{digest}",
                        "--output",
                        str(output),
                    ],
                    "py_security_suite.cli.merge_coverage_scenarios",
                    coverage,
                ),
                (
                    ["portfolio", "one", "two"],
                    "py_security_suite.cli.build_portfolio_dashboard",
                    portfolio,
                ),
                (
                    ["config-provenance"],
                    "py_security_suite.cli.build_config_provenance",
                    provenance,
                ),
                (
                    [
                        "audience-report",
                        "plan.json",
                        "--plan-sha256",
                        digest,
                        "--report",
                        "report",
                        "--audience",
                        "developer",
                    ],
                    "py_security_suite.cli.build_audience_report",
                    audience,
                ),
                (
                    ["evidence-pack", "report", "--output", "pack"],
                    "py_security_suite.cli.create_evidence_pack",
                    evidence_pack,
                ),
                (
                    ["verify-evidence-pack", "pack"],
                    "py_security_suite.cli.verify_evidence_pack",
                    evidence_pack_verification,
                ),
            )
            for arguments, target, result in cases:
                with (
                    self.subTest(command=arguments[0]),
                    patch(target, return_value=result),
                    patch(
                        "py_security_suite.cli.render_github_commands",
                        return_value="",
                    ),
                    patch("builtins.print"),
                ):
                    self.assertEqual(main(arguments), 0)

    def test_promotion_command_writes_the_requested_human_format(self) -> None:
        plan = {
            "status": "blocked",
            "report": {"scan_id": "scan-1", "checksums_sha256": "a" * 64},
            "summary": {
                "active_findings": 1,
                "blocking_findings": 1,
                "release_blockers": 1,
                "evidence_quality_average": 100.0,
            },
            "lifecycle": [
                {"stage": stage, "status": "blocked", "detail": "review"}
                for stage in (
                    "built",
                    "scanned",
                    "reviewed",
                    "signed",
                    "verified",
                    "approved",
                    "published",
                )
            ],
            "next_actions": [{"owner": "security", "action": "Review."}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for output_format, prefix in (
                ("markdown", "# Release promotion plan"),
                ("html", "<!doctype html>"),
            ):
                destination = root / f"plan.{output_format}"
                with (
                    self.subTest(output_format=output_format),
                    patch(
                        "py_security_suite.cli.build_promotion_plan",
                        return_value=plan,
                    ),
                    patch("builtins.print"),
                ):
                    self.assertEqual(
                        main(
                            [
                                "promotion-plan",
                                "report",
                                "--format",
                                output_format,
                                "--output",
                                str(destination),
                            ]
                        ),
                        1,
                    )
                    self.assertTrue(destination.read_text("utf-8").startswith(prefix))

    def test_closure_plan_exports_machine_and_human_views(self) -> None:
        plan = {
            "scan_id": "scan-1",
            "outcome": "incomplete",
            "summary": {"open_items": 1, "authority_items": 1},
            "items": [
                {
                    "id": "PYSEC-ACT-AAAAAAAAAAAA",
                    "priority": "P1",
                    "authority": "external",
                    "status": "external_required",
                    "owner": "release-engineering",
                    "title": "Sign artifact",
                    "action": "Use controlled signing.",
                    "acceptance_criteria": ["Bundle verifies."],
                    "commands": [["pysec", "prepare-signing"]],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "closure.md"
            with (
                patch("py_security_suite.cli.build_closure_plan", return_value=plan),
                patch("builtins.print"),
            ):
                self.assertEqual(
                    main(
                        [
                            "closure-plan",
                            "report",
                            "--format",
                            "markdown",
                            "--output",
                            str(output),
                        ]
                    ),
                    0,
                )
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("# Findings closure plan", rendered)
            self.assertIn("pysec prepare-signing", rendered)

    def test_evidence_pack_forwards_governed_inputs_and_performance_policy(
        self,
    ) -> None:
        digest = "a" * 64
        with patch(
            "py_security_suite.cli.create_evidence_pack",
            return_value={"status": "candidate"},
        ) as create:
            self.assertEqual(
                main(
                    [
                        "evidence-pack",
                        "report",
                        "--output",
                        "pack",
                        "--effectiveness-evaluation",
                        "effectiveness.json",
                        "--effectiveness-sha256",
                        digest,
                        "--minimum-effectiveness-labels",
                        "40",
                        "--minimum-effectiveness-positive-labels",
                        "20",
                        "--minimum-effectiveness-negative-labels",
                        "20",
                        "--minimum-effectiveness-tools",
                        "4",
                        "--minimum-effectiveness-labels-per-tool",
                        "5",
                        "--required-effectiveness-tool",
                        "bandit",
                        "--passport-verification",
                        "passport.json",
                        "--passport-verification-sha256",
                        digest,
                        "--require-passport",
                        "--performance-regression-percent",
                        "25",
                        "--maximum-total-seconds",
                        "300",
                        "--tool-budget",
                        "bandit=12.5",
                    ]
                ),
                0,
            )
        forwarded = create.call_args.kwargs
        self.assertEqual(forwarded["minimum_effectiveness_labels"], 40)
        self.assertEqual(forwarded["required_effectiveness_tools"], ("bandit",))
        self.assertTrue(forwarded["require_passport"])
        self.assertEqual(forwarded["performance_regression_percent"], 25.0)
        self.assertEqual(forwarded["maximum_total_seconds"], 300.0)
        self.assertEqual(forwarded["tool_budgets"], {"bandit": 12.5})

    def test_verify_can_atomically_publish_passport_receipt(self) -> None:
        verification = {
            "release_decision": "approved",
            "authentic": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "passport-verification.json"
            with (
                patch(
                    "py_security_suite.cli.verify_attestation",
                    return_value=verification,
                ),
                patch("builtins.print") as output,
            ):
                code = main(
                    [
                        "verify",
                        "passport",
                        "--format",
                        "json",
                        "--output",
                        str(destination),
                    ]
                )
            self.assertEqual(json.loads(destination.read_text()), verification)

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.call_args.args[0]), verification)

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
