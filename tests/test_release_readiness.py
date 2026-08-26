from __future__ import annotations

import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.release_readiness import assess_release_readiness


class ReleaseReadinessTests(unittest.TestCase):
    @patch("py_security_suite.release_readiness.verify_report")
    def test_production_requires_effectiveness_evidence_without_cli_opt_in(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report, profile="production")
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(report)
        self.assertEqual(result["decision"], "not_approved")
        self.assertIn("detection-effectiveness", result["blockers"])
        self.assertIn("runtime-trace-correlation", result["blockers"])

    @patch("py_security_suite.release_readiness.verify_report")
    def test_production_rejects_legacy_unsigned_effectiveness_corpus(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            _write_release_evidence(report, profile="production")
            verification = _verification()
            verify_report_mock.return_value = verification
            evaluation = root / "evaluation.json"
            evaluation_digest = _write_json(
                evaluation,
                {
                    "schema_version": "1.0",
                    "verdict": "pass",
                    "report": {"checksums_sha256": verification["checksums_sha256"]},
                    "corpus": {"labels": 25},
                    "label_outcomes": [
                        {
                            "expected": "finding" if index < 13 else "clean",
                            "match": {"tool": "bandit" if index % 2 else "semgrep"},
                        }
                        for index in range(25)
                    ],
                },
            )
            result = assess_release_readiness(
                report,
                effectiveness_evaluation=evaluation,
                effectiveness_sha256=evaluation_digest,
            )
        self.assertIn("detection-effectiveness", result["blockers"])
        control = next(
            item
            for item in result["controls"]
            if item["id"] == "detection-effectiveness"
        )
        self.assertIn("Governed corpus required: True", control["detail"])
        self.assertIn("validated: False", control["detail"])
        self.assertIn("minimums 200 total, 80 positive, 80 negative", control["detail"])

    @patch("py_security_suite.release_readiness.verify_report")
    def test_complete_governed_evidence_is_approved(self, verify_report_mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(report)

        self.assertEqual(result["decision"], "approved")
        self.assertEqual(result["blockers"], [])
        self.assertEqual(result["root_blockers"], [])
        self.assertEqual(result["derived_blockers"], [])
        self.assertEqual(result["remediation"], [])
        self.assertEqual(result["summary"]["validation_remediation_groups"], 0)
        self.assertEqual(result["summary"]["validation_remediation_subjects"], 0)
        _validate_schema(result)

    @patch("py_security_suite.release_readiness.verify_report")
    def test_changed_file_validation_gaps_block_release_with_owned_actions(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            _write_json(
                report / "closure-plan.json",
                {
                    "schema_version": "1.2",
                    "summary": {"validation_alignment_items": 1},
                    "items": [
                        {
                            "id": "PYSEC-ACT-123456789ABC",
                            "priority": "P2",
                            "owner": "@runtime-team",
                            "action": "Cover changed executable lines and rerun focused tests.",
                            "evidence_refs": [
                                "structural-synthesis.json",
                                "src/runtime.py",
                                "tests/test_runtime.py",
                            ],
                            "details": {"validation_alignment": "coverage-gap"},
                        }
                    ],
                },
            )
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(report)

        self.assertEqual(result["decision"], "not_approved")
        self.assertIn("change-validation-alignment", result["root_blockers"])
        action = next(
            item
            for item in result["remediation"]
            if item["blocker"] == "change-validation-alignment"
        )
        self.assertEqual(action["owner"], "@runtime-team")
        self.assertEqual(action["priority"], "P2")
        self.assertIn("src/runtime.py", action["evidence"])
        self.assertIn("closure-plan.json#PYSEC-ACT-123456789ABC", action["evidence"])
        self.assertLessEqual(len(action["evidence"]), 21)
        self.assertEqual(result["summary"]["validation_remediation_groups"], 1)
        self.assertEqual(result["summary"]["validation_remediation_subjects"], 1)
        _validate_schema(result)

    @patch("py_security_suite.release_readiness.verify_report")
    def test_missing_change_assessment_scope_cannot_approve_zero_debt(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            (report / "diff-coverage.json").unlink()
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(report)

        self.assertEqual(result["decision"], "not_approved")
        control = next(
            value
            for value in result["controls"]
            if value["id"] == "change-validation-alignment"
        )
        self.assertEqual(control["status"], "fail")
        self.assertIn("cannot prove alignment", control["detail"])
        action = next(
            value
            for value in result["remediation"]
            if value["id"] == "control:change-validation-alignment"
        )
        self.assertIn("diff-coverage", action["action"])

    @patch("py_security_suite.release_readiness.verify_report")
    def test_groups_shared_validation_causes_without_losing_file_subjects(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            _write_json(
                report / "closure-plan.json",
                {
                    "schema_version": "1.2",
                    "summary": {"validation_alignment_items": 2},
                    "items": [
                        {
                            "id": f"PYSEC-ACT-{suffix}",
                            "priority": "P2",
                            "owner": "@runtime-team",
                            "action": "Cover changed executable lines and rerun focused tests.",
                            "evidence_refs": [
                                "structural-synthesis.json",
                                path,
                                test,
                            ],
                            "details": {
                                "validation_alignment": "coverage-gap",
                                "recommended_test_files": [test],
                            },
                        }
                        for suffix, path, test in (
                            (
                                "111111111111",
                                "src/runtime.py",
                                "tests/test_runtime.py",
                            ),
                            (
                                "222222222222",
                                "src/worker.py",
                                "tests/test_worker.py",
                            ),
                        )
                    ],
                },
            )
            verify_report_mock.return_value = _verification()
            first = assess_release_readiness(report)
            second = assess_release_readiness(report)

        self.assertEqual(first, second)
        actions = [
            item
            for item in first["remediation"]
            if item["blocker"] == "change-validation-alignment"
        ]
        self.assertEqual(len(actions), 1)
        self.assertTrue(actions[0]["id"].startswith("validation-group:"))
        self.assertIn("Resolve 2 validation work items", actions[0]["action"])
        self.assertIn(
            "closure-plan.json#PYSEC-ACT-111111111111", actions[0]["evidence"]
        )
        self.assertIn(
            "closure-plan.json#PYSEC-ACT-222222222222", actions[0]["evidence"]
        )
        self.assertIn("src/runtime.py", actions[0]["evidence"])
        self.assertIn("src/worker.py", actions[0]["evidence"])
        self.assertEqual(first["summary"]["validation_remediation_groups"], 1)
        self.assertEqual(first["summary"]["validation_remediation_subjects"], 2)
        _validate_schema(first)

    @patch("py_security_suite.release_readiness.verify_report")
    def test_policy_trust_isolation_and_approval_gaps_are_explicit(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(
                report,
                outcome="incomplete",
                trusted=False,
                isolated=False,
                intelligence_approved=False,
            )
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(
                report,
                minimum_effectiveness_labels=25,
                require_passport=True,
            )

        self.assertEqual(result["decision"], "not_approved")
        self.assertEqual(
            set(result["blockers"]),
            {
                "scan-policy",
                "external-isolation",
                "scanner-trust",
                "intelligence-approval",
                "detection-effectiveness",
                "signed-release-passport",
            },
        )
        self.assertGreater(result["summary"]["remediation_actions"], 0)
        self.assertNotIn("scan-policy", result["root_blockers"])
        self.assertEqual(result["derived_blockers"], ["scan-policy"])
        self.assertTrue(result["blocker_graph"])
        self.assertTrue(
            any(
                action["authority"] == "organization-security"
                for action in result["remediation"]
            )
        )
        _validate_schema(result)

    @patch("py_security_suite.release_readiness.verify_report")
    def test_release_profile_requires_an_authentic_passport(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report, profile="release")
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(report)

        self.assertIn("signed-release-passport", result["blockers"])

    @patch("py_security_suite.release_readiness.verify_report")
    def test_digest_bound_optional_controls_must_pass_and_bind_to_report(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            _write_release_evidence(report)
            evaluation = root / "evaluation.json"
            passport = root / "passport.json"
            evaluation_digest = _write_json(
                evaluation,
                {
                    "schema_version": "1.0",
                    "verdict": "pass",
                    "report": {"checksums_sha256": "f" * 64},
                    "corpus": {"labels": 25},
                    "label_outcomes": [
                        {
                            "expected": "finding",
                            "match": {"tool": "bandit"},
                        },
                        {
                            "expected": "clean",
                            "match": {"tool": "semgrep"},
                        },
                    ],
                },
            )
            passport_digest = _write_json(
                passport,
                {
                    "release_decision": "approved",
                    "authentic": True,
                    "report": {"checksums_sha256": "f" * 64},
                },
            )
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(
                report,
                effectiveness_evaluation=evaluation,
                effectiveness_sha256=evaluation_digest,
                minimum_effectiveness_labels=25,
                minimum_effectiveness_positive_labels=1,
                minimum_effectiveness_negative_labels=1,
                minimum_effectiveness_tools=2,
                minimum_effectiveness_labels_per_tool=1,
                required_effectiveness_tools=("bandit", "semgrep"),
                passport_verification=passport,
                passport_verification_sha256=passport_digest,
                require_passport=True,
            )

        self.assertEqual(result["decision"], "approved")
        self.assertIn("detection-effectiveness", _control_ids(result))
        self.assertIn("signed-release-passport", _control_ids(result))

    @patch("py_security_suite.release_readiness.verify_report")
    def test_passport_must_be_explicitly_bound_to_the_report(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            _write_release_evidence(report)
            passport = root / "passport.json"
            passport_digest = _write_json(
                passport,
                {"release_decision": "approved", "authentic": True},
            )
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(
                report,
                passport_verification=passport,
                passport_verification_sha256=passport_digest,
                require_passport=True,
            )

        self.assertIn("signed-release-passport", result["blockers"])

    @patch("py_security_suite.release_readiness.verify_report")
    def test_applicable_scanner_without_an_identity_is_untrusted(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            manifest_path = report / "scan-manifest.json"
            manifest = json.loads(manifest_path.read_text("utf-8"))
            manifest["tools"][0].pop("executable_sha256")
            _write_json(manifest_path, manifest)
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(report)

        self.assertIn("scanner-trust", result["blockers"])

    @patch("py_security_suite.release_readiness.verify_report")
    def test_repository_digest_pin_is_not_organization_approval(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            manifest_path = report / "scan-manifest.json"
            manifest = json.loads(manifest_path.read_text("utf-8"))
            manifest["tools"][0]["executable_organization_approved"] = False
            _write_json(manifest_path, manifest)
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(report)

        self.assertIn("scanner-trust", result["blockers"])

    def test_optional_evidence_requires_path_and_digest_together(self) -> None:
        with self.assertRaisesRegex(ValueError, "supplied together"):
            assess_release_readiness(
                Path("report"),
                effectiveness_evaluation=Path("evaluation.json"),
            )

    def test_effectiveness_label_bounds_are_enforced(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 0 and 10000"):
            assess_release_readiness(
                Path("report"), minimum_effectiveness_labels=10_001
            )

    @patch("py_security_suite.release_readiness.verify_report")
    def test_effectiveness_requires_named_tool_perspectives(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            _write_release_evidence(report)
            verification = _verification()
            verify_report_mock.return_value = verification
            evaluation = Path(temporary) / "evaluation.json"
            digest = _write_json(
                evaluation,
                {
                    "schema_version": "1.0",
                    "verdict": "pass",
                    "report": {"checksums_sha256": verification["checksums_sha256"]},
                    "corpus": {"labels": 1},
                    "label_outcomes": [
                        {
                            "expected": "finding",
                            "match": {"tool": "bandit"},
                        }
                    ],
                },
            )
            result = assess_release_readiness(
                report,
                effectiveness_evaluation=evaluation,
                effectiveness_sha256=digest,
                minimum_effectiveness_labels_per_tool=1,
                required_effectiveness_tools=("bandit", "semgrep"),
            )
        control = next(
            item
            for item in result["controls"]
            if item["id"] == "detection-effectiveness"
        )
        self.assertEqual(control["status"], "fail")
        self.assertIn("semgrep", control["detail"])

    @patch("py_security_suite.release_readiness.verify_report")
    def test_verified_report_requires_array_findings_and_claims(
        self, verify_report_mock
    ) -> None:
        verify_report_mock.return_value = _verification()
        for filename, key, message in (
            ("findings.json", "findings", "findings must be an array"),
            ("assurance-claims.json", "claims", "claims must be an array"),
        ):
            with (
                self.subTest(filename=filename),
                tempfile.TemporaryDirectory() as directory,
            ):
                report = Path(directory)
                _write_release_evidence(report)
                _write_json(report / filename, {key: {}})

                with self.assertRaisesRegex(TypeError, message):
                    assess_release_readiness(report)

    @patch("py_security_suite.release_readiness.verify_report")
    def test_blocking_findings_receive_specific_owned_remediation(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            _write_json(
                report / "findings.json",
                {
                    "findings": [
                        None,
                        {"blocking": True, "status": "suppressed"},
                        {
                            "finding_id": "PYSEC-SIGN",
                            "blocking": True,
                            "status": "new",
                            "classifications": ["COSIGN-BUNDLE-MISSING"],
                            "remediation": "Sign the exact digest.",
                            "evidence": {
                                "owners": ["@release"],
                                "artifact_path": "dist/project.whl",
                            },
                        },
                    ]
                },
            )
            verify_report_mock.return_value = _verification()

            result = assess_release_readiness(report)

        action = next(
            item for item in result["remediation"] if item["id"] == "finding:PYSEC-SIGN"
        )
        self.assertEqual(action["owner"], "@release")
        self.assertEqual(action["authority"], "controlled-signing")
        self.assertEqual(action["evidence"][-1], "dist/project.whl")
        self.assertTrue(action["commands"])

    @patch("py_security_suite.release_readiness.verify_report")
    def test_equivalent_finding_remediation_is_consolidated_without_losing_evidence(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            findings = []
            for identifier, artifact in (
                ("PYSEC-WHEEL", "dist/project.whl"),
                ("PYSEC-SDIST", "dist/project.tar.gz"),
            ):
                findings.append(
                    {
                        "finding_id": identifier,
                        "blocking": True,
                        "status": "new",
                        "classifications": ["COSIGN-BUNDLE-MISSING"],
                        "remediation": "Sign every exact release artifact.",
                        "evidence": {
                            "owners": ["@release"],
                            "artifact_path": artifact,
                        },
                    }
                )
            _write_json(report / "findings.json", {"findings": findings})
            verify_report_mock.return_value = _verification()

            result = assess_release_readiness(report)

        signing = [
            item
            for item in result["remediation"]
            if item["authority"] == "controlled-signing"
        ]
        self.assertEqual(len(signing), 1)
        self.assertEqual(signing[0]["id"], "findings:PYSEC-SDIST+PYSEC-WHEEL")
        self.assertEqual(
            signing[0]["evidence"],
            [
                "PYSEC-SDIST",
                "PYSEC-WHEEL",
                "dist/project.tar.gz",
                "dist/project.whl",
            ],
        )
        self.assertEqual(result["summary"]["remediation_actions"], 1)
        _validate_schema(result)

    @patch("py_security_suite.release_readiness.verify_report")
    def test_alias_equivalent_advisories_share_one_operational_action(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            context = {
                "cluster_id": "ADV-ABC123",
                "finding_ids": ["GRYPE-ADV", "OSV-ADV"],
                "dependency_usage": {"import_paths": ["src/client.py"]},
                "remediation_context": {
                    "priority": "P0",
                    "owners": ["@dependency-team"],
                    "recommended_test_files": ["tests/test_client.py"],
                    "recommended_action": "Upgrade demo-lib and rebuild.",
                },
            }
            findings = [
                {
                    "finding_id": finding_id,
                    "blocking": True,
                    "status": "new",
                    "classifications": [classification],
                    "remediation": "Review the native advisory.",
                    "evidence": {"fusion": {"advisory_context": context}},
                }
                for finding_id, classification in (
                    ("OSV-ADV", "GHSA-DEMO"),
                    ("GRYPE-ADV", "CVE-2026-12345"),
                )
            ]
            _write_json(report / "findings.json", {"findings": findings})
            verify_report_mock.return_value = _verification()

            result = assess_release_readiness(report)

        actions = [
            item
            for item in result["remediation"]
            if item["id"] == "advisory:ADV-ABC123"
        ]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["priority"], "P0")
        self.assertEqual(actions[0]["owner"], "@dependency-team")
        self.assertEqual(actions[0]["action"], "Upgrade demo-lib and rebuild.")
        self.assertEqual(
            actions[0]["evidence"],
            [
                "GRYPE-ADV",
                "OSV-ADV",
                "evidence-fusion.json",
                "src/client.py",
                "tests/test_client.py",
            ],
        )
        _validate_schema(result)

    @patch("py_security_suite.release_readiness.verify_report")
    def test_skipped_tools_are_ignored_and_codeql_helper_is_required(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            manifest_path = report / "scan-manifest.json"
            manifest = json.loads(manifest_path.read_text("utf-8"))
            manifest["tools"] = [
                None,
                {"tool": "skip", "applicable": False},
                {
                    "tool": "codeql",
                    "applicable": True,
                    "executable_sha256": "a" * 64,
                    "executable_integrity_verified": True,
                    "executable_organization_approved": True,
                    "executable_unchanged": True,
                },
            ]
            _write_json(manifest_path, manifest)
            verify_report_mock.return_value = _verification()

            result = assess_release_readiness(report)

        self.assertEqual(result["summary"]["scanner_entrypoints"], 2)
        self.assertEqual(result["summary"]["scanner_trust_gaps"], 1)
        self.assertIn("scanner-trust", result["blockers"])

    @patch("py_security_suite.release_readiness.verify_report")
    def test_digest_bound_evidence_rejects_a_digest_mismatch(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            _write_release_evidence(report)
            evaluation = root / "evaluation.json"
            _write_json(evaluation, {"schema_version": "1.0"})
            verify_report_mock.return_value = _verification()

            with self.assertRaisesRegex(ValueError, "approved SHA-256"):
                assess_release_readiness(
                    report,
                    effectiveness_evaluation=evaluation,
                    effectiveness_sha256="0" * 64,
                )


def _verification() -> dict[str, object]:
    return {
        "verified": True,
        "scan_id": "scan-release",
        "checksums_sha256": "f" * 64,
        "file_count": 12,
        "outcome": "pass",
    }


def _write_release_evidence(
    root: Path,
    *,
    outcome: str = "pass",
    trusted: bool = True,
    isolated: bool = True,
    intelligence_approved: bool = True,
    profile: str = "standard",
) -> None:
    documents: dict[str, dict[str, object]] = {
        "scan-manifest.json": {
            "outcome": outcome,
            "profile": profile,
            "network_isolation_attested": isolated,
            "tools": [
                {
                    "tool": "bandit",
                    "applicable": True,
                    "executable_sha256": "a" * 64,
                    "executable_integrity_verified": trusted,
                    "executable_organization_approved": trusted,
                    "executable_unchanged": trusted,
                }
            ],
        },
        "findings.json": {"findings": []},
        "assurance-claims.json": {
            "claims": [{"control": "static-analysis", "result": "satisfied"}]
        },
        "portfolio-health.json": {"overall": {"domains_with_execution_gaps": 0}},
        "isolation-attestation.json": {
            "validated": isolated,
            "organization_approved": isolated,
        },
        "risk-intelligence.json": {"configured": True},
        "intelligence-approval.json": {
            "validated": intelligence_approved,
            "organization_approved": intelligence_approved,
        },
        "closure-plan.json": {
            "schema_version": "1.2",
            "summary": {"validation_alignment_items": 0},
            "items": [],
        },
        "diff-coverage.json": {
            "schema_version": "1.0",
            "diff_name": "approved-base...current",
            "minimum_percent": 80.0,
            "num_changed_lines": 0,
            "src_stats": {},
        },
    }
    for name, document in documents.items():
        _write_json(root / name, document)


def _validate_schema(document: dict[str, object]) -> None:
    schema = json.loads(
        files("py_security_suite")
        .joinpath("schemas", "release-readiness-1.3.schema.json")
        .read_text("utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)


def _write_json(path: Path, document: dict[str, object]) -> str:
    import hashlib

    payload = json.dumps(document, sort_keys=True).encode()
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _control_ids(document: dict[str, object]) -> set[str]:
    controls = document["controls"]
    if not isinstance(controls, list):
        raise TypeError("controls must be a list")
    return {
        str(control["id"])
        for control in controls
        if isinstance(control, dict) and "id" in control
    }
