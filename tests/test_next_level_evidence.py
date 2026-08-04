from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from py_security_suite.config import IntelligenceConfig
from py_security_suite.execution import RawExecution
from py_security_suite.finding_delta import apply_finding_delta
from py_security_suite.models import (
    Confidence,
    Finding,
    FindingStatus,
    Location,
    Severity,
    Source,
)
from py_security_suite.passport import (
    REQUIRED_REPORT_ARTIFACTS,
    _cosign_major_version,
    _prepare_directory,
    _read_json,
    _release_artifact_subjects,
    _read_signing_password,
    _regular_file,
    _safe_relative,
    _statement_subjects,
    _validate_statement,
    _validate_verification_material,
    _verify_checksums,
    _verify_bound_report,
    _verify_passport_authenticity,
    _verify_release_artifact_sets,
    _verify_statement_manifest_binding,
    _verify_statement_subjects,
    _verify_statement_inputs,
    create_attestation,
    verify_attestation,
    verify_report,
)
from py_security_suite.risk_intelligence import enrich_findings
from tests.report_fixtures import write_embedded_statement


def _finding(*, line: int = 10, title: str = "Vulnerable dependency") -> Finding:
    return Finding(
        finding_id=f"PYSEC-{line}",
        fingerprint=f"sha256:{line:064x}",
        title=title,
        description="Dependency is affected by CVE-2026-12345",
        impact="Attackers may exploit the vulnerable dependency.",
        remediation="Upgrade to the fixed version.",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        area="dependency-vulnerability",
        domain="supply-chain",
        classifications=["CVE-2026-12345"],
        locations=[Location(path="src/app.py", start_line=line)],
        sources=[
            Source(
                tool="osv-scanner",
                rule_id="CVE-2026-12345",
                message="CVE-2026-12345",
            )
        ],
    )


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RiskIntelligenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary))
        self.kev = self.root / "kev.json"
        self.kev.write_text(
            json.dumps(
                {
                    "dateReleased": "2026-08-01",
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2026-12345",
                            "dateAdded": "2026-08-01",
                            "dueDate": "2026-08-08",
                            "knownRansomwareCampaignUse": "Known",
                            "requiredAction": "Apply mitigations",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.epss = self.root / "epss.csv"
        self.epss.write_text(
            "#model_version:v4,score_date:2026-08-01\n"
            "cve,epss,percentile\nCVE-2026-12345,0.75,0.99\n",
            encoding="utf-8",
        )
        self.vex = self.root / "vex.json"
        self.vex.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.7",
                    "metadata": {"timestamp": "2026-08-01T00:00:00Z"},
                    "vulnerabilities": [
                        {
                            "id": "CVE-2026-12345",
                            "analysis": {
                                "state": "not_affected",
                                "justification": "code_not_reachable",
                                "detail": "Reviewed by the product security team",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def test_kev_epss_and_vex_enrich_without_suppressing(self) -> None:
        finding = _finding()
        result = enrich_findings(
            [finding],
            IntelligenceConfig(
                kev_path=self.kev,
                kev_sha256=_digest(self.kev),
                epss_path=self.epss,
                epss_sha256=_digest(self.epss),
                vex_path=self.vex,
                vex_sha256=_digest(self.vex),
            ),
        )
        self.assertEqual(result.errors, [])
        self.assertEqual(result.artifact["known_exploited_matches"], 1)
        self.assertIn("CISA-KEV", finding.classifications)
        self.assertIn("EPSS-HIGH", finding.classifications)
        self.assertIn("VEX-NOT-AFFECTED", finding.classifications)
        self.assertEqual(finding.status, FindingStatus.NEW)
        self.assertIn("risk_intelligence", finding.evidence)
        self.assertEqual(len(finding.citations), 3)

    def test_snapshot_digest_mismatch_fails_closed(self) -> None:
        result = enrich_findings(
            [_finding()],
            IntelligenceConfig(kev_path=self.kev, kev_sha256="0" * 64),
        )
        self.assertEqual(len(result.errors), 1)
        self.assertIn("does not match approved digest", result.errors[0])

    def test_malformed_epss_probability_is_rejected(self) -> None:
        self.epss.write_text(
            "cve,epss,percentile\nCVE-2026-12345,2.0,0.99\n",
            encoding="utf-8",
        )
        result = enrich_findings(
            [_finding()],
            IntelligenceConfig(epss_path=self.epss, epss_sha256=_digest(self.epss)),
        )
        self.assertIn("must be between 0 and 1", result.errors[0])


class FindingDeltaTests(unittest.TestCase):
    def test_exact_semantic_resolved_and_ownership_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github").mkdir()
            (root / ".github" / "CODEOWNERS").write_text(
                "src/*.py @security-team\n", encoding="utf-8"
            )
            exact = _finding(line=10, title="Exact")
            moved = _finding(line=20, title="Moved")
            resolved = _finding(line=30, title="Resolved")
            baseline = root / "baseline.json"
            baseline.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "scan_id": "scan-old",
                        "outcome": "warn",
                        "target": root.name,
                        "findings": [
                            _record(exact),
                            _record(moved),
                            _record(resolved),
                        ],
                    }
                ),
                encoding="utf-8",
            )
            current_exact = _finding(line=10, title="Exact")
            current_moved = _finding(line=99, title="Moved")
            result = apply_finding_delta(
                [current_exact, current_moved],
                target=root,
                baseline_path=baseline,
                baseline_sha256=_digest(baseline),
            )
        self.assertEqual(result.errors, [])
        self.assertEqual(current_exact.status, FindingStatus.EXISTING)
        self.assertEqual(current_moved.status, FindingStatus.EXISTING)
        self.assertEqual(
            current_moved.evidence["baseline"]["match_strategy"], "semantic"
        )
        self.assertEqual(current_exact.evidence["owners"], ["@security-team"])
        self.assertEqual(result.artifact["counts"]["resolved"], 1)

    def test_invalid_baseline_digest_is_an_explicit_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.json"
            baseline.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "target": root.name,
                        "findings": [],
                    }
                ),
                encoding="utf-8",
            )
            result = apply_finding_delta(
                [_finding()],
                target=root,
                baseline_path=baseline,
                baseline_sha256="f" * 64,
            )
        self.assertIn("does not match approved digest", result.errors[0])

    def test_baseline_for_another_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.json"
            baseline.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "target": "another-project",
                        "findings": [],
                    }
                ),
                encoding="utf-8",
            )
            result = apply_finding_delta(
                [_finding()],
                target=root,
                baseline_path=baseline,
                baseline_sha256=_digest(baseline),
            )
        self.assertIn("does not match", result.errors[0])


class PassportTests(unittest.TestCase):
    def test_passport_input_binding_rejects_bad_shapes_paths_and_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            evidence = report / "evidence.json"
            evidence.write_text("{}", encoding="utf-8")
            valid = {
                "predicate": {
                    "inputAttestations": [
                        {
                            "uri": "evidence.json",
                            "digest": {"sha256": _digest(evidence)},
                        }
                    ]
                }
            }
            self.assertEqual(_verify_statement_inputs(valid, report), {"evidence.json"})
            self.assertEqual(_verify_statement_inputs({"predicate": []}, report), set())
            invalid: tuple[tuple[dict[str, Any], str], ...] = (
                ({"predicate": {"inputAttestations": {}}}, "must be a list"),
                ({"predicate": {"inputAttestations": [1]}}, "must be an object"),
                (
                    {
                        "predicate": {
                            "inputAttestations": [
                                {"uri": "../escape", "digest": {"sha256": "a" * 64}}
                            ]
                        }
                    },
                    "unsafe evidence path",
                ),
                (
                    {
                        "predicate": {
                            "inputAttestations": [
                                {"uri": "missing.json", "digest": {"sha256": "a" * 64}}
                            ]
                        }
                    },
                    "unavailable",
                ),
                (
                    {
                        "predicate": {
                            "inputAttestations": [
                                {"uri": "evidence.json", "digest": {"sha256": "a" * 64}}
                            ]
                        }
                    },
                    "digest mismatch",
                ),
                (
                    {
                        "predicate": {
                            "inputAttestations": [
                                {"uri": "evidence.json", "digest": []}
                            ]
                        }
                    },
                    "digest mismatch",
                ),
                (
                    {
                        "predicate": {
                            "inputAttestations": [
                                {
                                    "uri": "evidence.json",
                                    "digest": {"sha256": _digest(evidence)},
                                },
                                {
                                    "uri": "evidence.json",
                                    "digest": {"sha256": _digest(evidence)},
                                },
                            ]
                        }
                    },
                    "input is duplicated",
                ),
            )
            for statement, message in invalid:
                with (
                    self.subTest(message=message),
                    self.assertRaisesRegex(ValueError, message),
                ):
                    _verify_statement_inputs(statement, report)

    def test_json_and_output_directory_guards_prevent_unsafe_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.json"
            with self.assertRaisesRegex(ValueError, "bounded regular file"):
                _read_json(missing)
            sequence = root / "sequence.json"
            sequence.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(TypeError, "root must be an object"):
                _read_json(sequence)

            output = root / "passport"
            output.mkdir()
            with self.assertRaisesRegex(ValueError, "already exists"):
                _prepare_directory(output, overwrite=False)
            with self.assertRaisesRegex(ValueError, "not a valid Security Passport"):
                _prepare_directory(output, overwrite=True)
            (output / "verification-material.json").write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "suite_version": "0.1.0",
                        "created_at": "2026-08-04T00:00:00Z",
                        "report": "fixture",
                        "signed": False,
                        "report_checksums_sha256": "a" * 64,
                    }
                ),
                encoding="utf-8",
            )
            (output / "security-passport.json").write_text(
                json.dumps(
                    {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [{"name": "source", "digest": {}}],
                        "predicateType": ("https://slsa.dev/verification_summary/v1"),
                        "predicate": {
                            "verificationResult": "PASSED",
                            "policy": {"digest": {}},
                        },
                    }
                ),
                encoding="utf-8",
            )
            _write_checksums(output)
            _prepare_directory(output, overwrite=True)

            regular_file = root / "not-a-directory"
            regular_file.write_text("fixture", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not a regular directory"):
                _prepare_directory(regular_file, overwrite=True)

    def test_report_validation_rejects_incomplete_scan_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            (report / "scan-manifest.json").write_text(
                '{"schema_version":"1.0"}', encoding="utf-8"
            )
            _write_checksums(report)
            with self.assertRaisesRegex(ValueError, "scan manifest is invalid"):
                verify_report(report)

    def test_report_validation_requires_canonical_artifacts_and_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            summary = report / "summary.md"
            summary.unlink()
            _write_checksums(report)
            with self.assertRaisesRegex(ValueError, "artifact is missing: summary.md"):
                verify_report(report)

            summary.write_text("# Fixture\n", encoding="utf-8")
            manifest_path = report / "scan-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest.pop("artifacts")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _write_checksums(report)
            with self.assertRaisesRegex(ValueError, "artifact manifest is missing"):
                verify_report(report)

            manifest["artifacts"] = dict(REQUIRED_REPORT_ARTIFACTS)
            manifest["artifacts"]["summary"] = "alternate-summary.md"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _write_checksums(report)
            with self.assertRaisesRegex(ValueError, "binding is invalid: summary"):
                verify_report(report)

    def test_report_validation_requires_every_declared_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            manifest_path = report / "scan-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

            evidence = report / "evidence"
            evidence.mkdir()
            (evidence / "scanner.json").write_text("{}", encoding="utf-8")
            manifest["artifacts"]["evidence"] = "evidence/"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            write_embedded_statement(report, manifest)
            _write_checksums(report)
            self.assertTrue(verify_report(report)["verified"])

            valid_artifacts = dict(manifest["artifacts"])
            invalid_maps: tuple[tuple[dict[str, object], str], ...] = (
                ({}, "binding count is invalid"),
                (
                    {**valid_artifacts, "malformed": 7},
                    "binding is malformed",
                ),
            )
            for artifact_map, message in invalid_maps:
                with self.subTest(message=message):
                    manifest["artifacts"] = artifact_map
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    _write_checksums(report)
                    with self.assertRaisesRegex(ValueError, message):
                        verify_report(report)
            manifest["artifacts"] = valid_artifacts

            invalid = (
                ("missing", "missing.json", "artifact is unavailable"),
                ("duplicate", "summary.md", "binding is duplicated"),
                ("unsafe", "../outside.json", "unsafe evidence path"),
            )
            for key, binding, message in invalid:
                with self.subTest(binding=binding):
                    manifest["artifacts"][key] = binding
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    _write_checksums(report)
                    with self.assertRaisesRegex(ValueError, message):
                        verify_report(report)
                    manifest["artifacts"].pop(key)

    def test_report_validation_binds_embedded_security_passport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            statement_path = report / "security-passport.json"
            original = json.loads(statement_path.read_text(encoding="utf-8"))
            manifest = json.loads(
                (report / "scan-manifest.json").read_text(encoding="utf-8")
            )

            incomplete = json.loads(json.dumps(original))
            incomplete["predicate"]["inputAttestations"].pop()
            statement_path.write_text(json.dumps(incomplete), encoding="utf-8")
            _write_checksums(report)
            with self.assertRaisesRegex(ValueError, "input set is incomplete"):
                verify_report(report)

            mismatched = json.loads(json.dumps(original))
            mismatched["predicate"]["resourceUri"] = "urn:pysec:scan:other"
            statement_path.write_text(json.dumps(mismatched), encoding="utf-8")
            _write_checksums(report)
            with self.assertRaisesRegex(ValueError, "does not match scan manifest"):
                verify_report(report)

            manifest["outcome"] = "unexpected"
            with self.assertRaisesRegex(ValueError, "outcome is invalid"):
                _verify_statement_manifest_binding(original, manifest)
            manifest["outcome"] = "pass"
            with self.assertRaisesRegex(ValueError, "manifest binding is invalid"):
                _verify_statement_manifest_binding(
                    {**original, "predicate": []}, manifest
                )
            malformed = json.loads(json.dumps(original))
            malformed["predicate"].pop("verifier")
            with self.assertRaisesRegex(ValueError, "does not match scan manifest"):
                _verify_statement_manifest_binding(malformed, manifest)
            invalid_evidence = json.loads(json.dumps(manifest))
            invalid_evidence["inventory"]["source_sha256"] = ""
            with self.assertRaisesRegex(ValueError, "manifest evidence is invalid"):
                _verify_statement_manifest_binding(original, invalid_evidence)
            invalid_structure = json.loads(json.dumps(manifest))
            invalid_structure["tools"] = {}
            with self.assertRaisesRegex(ValueError, "manifest binding is invalid"):
                _verify_statement_manifest_binding(original, invalid_structure)

    def test_report_validation_binds_exact_artifact_subjects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            artifact_manifest = report / "artifact-manifest.json"
            artifact_manifest.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "algorithm": "sha256",
                        "artifacts": [
                            {
                                "path": "dist/example-1.0-py3-none-any.whl",
                                "sha256": "c" * 64,
                                "size_bytes": 1024,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            manifest = json.loads(
                (report / "scan-manifest.json").read_text(encoding="utf-8")
            )
            write_embedded_statement(report, manifest)
            _write_checksums(report)
            self.assertTrue(verify_report(report)["verified"])

            statement_path = report / "security-passport.json"
            original = json.loads(statement_path.read_text(encoding="utf-8"))
            invalid_subjects = (
                (original["subject"][:1], "subjects do not match report"),
                (
                    [
                        original["subject"][0],
                        {
                            "name": "dist/example-1.0-py3-none-any.whl",
                            "digest": {"sha256": "d" * 64},
                        },
                    ],
                    "subjects do not match report",
                ),
                (
                    original["subject"]
                    + [{"name": "invented.whl", "digest": {"sha256": "e" * 64}}],
                    "subjects do not match report",
                ),
                (
                    original["subject"] + [original["subject"][1]],
                    "subject is duplicated",
                ),
                (
                    [
                        original["subject"][0],
                        {**original["subject"][1], "unexpected": True},
                    ],
                    "subject is malformed",
                ),
                (
                    [
                        original["subject"][0],
                        {
                            "name": "dist/example-1.0-py3-none-any.whl",
                            "digest": {"sha256": "invalid"},
                        },
                    ],
                    "subject is malformed",
                ),
            )
            for subjects, message in invalid_subjects:
                with self.subTest(message=message, subjects=subjects):
                    changed = json.loads(json.dumps(original))
                    changed["subject"] = subjects
                    statement_path.write_text(json.dumps(changed), encoding="utf-8")
                    _write_checksums(report)
                    with self.assertRaisesRegex(ValueError, message):
                        verify_report(report)
            with self.assertRaisesRegex(ValueError, "subject binding is invalid"):
                _verify_statement_subjects(original, report, {})

    def test_artifact_subject_manifest_is_strictly_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            manifest_path = report / "artifact-manifest.json"
            with self.assertRaisesRegex(ValueError, "source subject is invalid"):
                _statement_subjects(report, target="", source_sha256="a" * 64)
            valid_record = {
                "path": "dist/example.whl",
                "sha256": "c" * 64,
                "size_bytes": 7,
            }
            documents: tuple[tuple[dict[str, object], str], ...] = (
                (
                    {"schema_version": "2.0", "algorithm": "sha256", "artifacts": []},
                    "subject manifest is invalid",
                ),
                (
                    {
                        "schema_version": "1.0",
                        "algorithm": "sha256",
                        "artifacts": {},
                    },
                    "subject manifest is invalid",
                ),
                (
                    {
                        "schema_version": "1.0",
                        "algorithm": "sha256",
                        "artifacts": [1],
                    },
                    "subject is malformed",
                ),
                (
                    {
                        "schema_version": "1.0",
                        "algorithm": "sha256",
                        "artifacts": [{**valid_record, "sha256": "invalid"}],
                    },
                    "subject is malformed",
                ),
                (
                    {
                        "schema_version": "1.0",
                        "algorithm": "sha256",
                        "artifacts": [{**valid_record, "size_bytes": True}],
                    },
                    "subject is malformed",
                ),
                (
                    {
                        "schema_version": "1.0",
                        "algorithm": "sha256",
                        "artifacts": [valid_record, valid_record],
                    },
                    "subject is duplicated",
                ),
            )
            for document, message in documents:
                with self.subTest(message=message, document=document):
                    manifest_path.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, message):
                        _statement_subjects(
                            report, target="fixture", source_sha256="a" * 64
                        )

    def test_passport_path_and_statement_validation_rejects_ambiguous_evidence(
        self,
    ) -> None:
        self.assertEqual(
            _safe_relative("nested/evidence.json"), Path("nested/evidence.json")
        )
        for value in (
            "",
            ".",
            "/absolute",
            "../escape",
            "./nested",
            "nested//ambiguous",
            "nested\\windows",
            "C:/windows-drive",
        ):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "unsafe"),
            ):
                _safe_relative(value)

        valid = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/verification_summary/v1",
            "subject": [{"name": "source:test"}],
            "predicate": {
                "verificationResult": "PASSED",
                "policy": {"digest": {"sha256": "a" * 64}},
            },
        }
        _validate_statement(valid)
        invalid = (
            ({**valid, "_type": "wrong"}, "in-toto"),
            ({**valid, "predicateType": "wrong"}, "SLSA"),
            ({**valid, "subject": []}, "subjects"),
            (
                {**valid, "predicate": {"verificationResult": "UNKNOWN"}},
                "verificationResult",
            ),
            (
                {
                    **valid,
                    "predicate": {"verificationResult": "PASSED", "policy": []},
                },
                "policy digest",
            ),
        )
        for document, message in invalid:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                _validate_statement(document)

    def test_checksum_manifest_validation_covers_malformed_and_missing_inputs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "checksum manifest is missing"):
                _verify_checksums(root)
            checksum = root / "checksums.sha256"
            checksum.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "entry count"):
                _verify_checksums(root)
            checksum.write_text("malformed\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line is invalid"):
                _verify_checksums(root)
            checksum.write_text(f"{'x' * 64}  evidence.json\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest or path"):
                _verify_checksums(root)
            checksum.write_text(f"{'a' * 64}  missing.json\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unavailable"):
                _verify_checksums(root)
            evidence = root / "evidence.json"
            evidence.write_text("{}", encoding="utf-8")
            checksum.write_text(f"{'a' * 64}  evidence.json\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                _verify_checksums(root)
            digest = _digest(evidence)
            checksum.write_text(
                f"{digest}  evidence.json\n{digest}  evidence.json\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "digest or path"):
                _verify_checksums(root)
            checksum.write_text(f"{digest}  evidence.json\n", encoding="utf-8")
            self.assertEqual(_verify_checksums(root), 1)
            extra = root / "unchecksummed.json"
            extra.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exact evidence file set"):
                _verify_checksums(root)
            extra.unlink()
            with patch("py_security_suite.passport._MAX_TREE_ENTRIES", 1):
                with self.assertRaisesRegex(ValueError, "tree entry count"):
                    _verify_checksums(root)
            with patch("py_security_suite.passport._MAX_FILE_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "manifest is too large"):
                    _verify_checksums(root)
        with tempfile.NamedTemporaryFile() as temporary:
            with self.assertRaisesRegex(ValueError, "not a regular directory"):
                _verify_checksums(Path(temporary.name))

    def test_signing_password_and_cosign_version_validation_is_bounded(self) -> None:
        self.assertEqual(_read_signing_password(None), "")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            password = root / "password.txt"
            password.write_text("secret\r\n", encoding="utf-8")
            self.assertEqual(_read_signing_password(password), "secret")
            password.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "is empty"):
                _read_signing_password(password)
            password.write_bytes(b"x" * 4097)
            with self.assertRaisesRegex(ValueError, "bounded"):
                _read_signing_password(password)

            cosign = root / "cosign.exe"
            cosign.write_bytes(b"fixture")
            versions = (
                (
                    RawExecution([str(cosign)], 0, '{"gitVersion":"v3.1.0"}', "", 0.01),
                    3,
                ),
                (RawExecution([str(cosign)], 0, "cosign version 2.4.1", "", 0.01), 2),
            )
            for execution, expected in versions:
                with (
                    self.subTest(expected=expected),
                    patch(
                        "py_security_suite.passport.run_command", return_value=execution
                    ),
                ):
                    self.assertEqual(_cosign_major_version(cosign, root), expected)
            failures = (
                RawExecution([str(cosign)], 1, "", "failed", 0.01),
                RawExecution([str(cosign)], 0, "unknown", "", 0.01),
                RawExecution([str(cosign)], None, "", "", 0.01, timed_out=True),
            )
            for execution in failures:
                with (
                    patch(
                        "py_security_suite.passport.run_command", return_value=execution
                    ),
                    self.assertRaisesRegex(ValueError, "major version"),
                ):
                    _cosign_major_version(cosign, root)

    def test_unsigned_passport_requires_explicit_integrity_only_acceptance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            passport = root / "passport"
            create_attestation(report=report, output=passport, signing_key=None)
            with self.assertRaisesRegex(ValueError, "allow-unsigned"):
                verify_attestation(
                    passport=passport,
                    report=None,
                    public_key=None,
                )
            with self.assertRaisesRegex(ValueError, "already exists"):
                create_attestation(report=report, output=passport, signing_key=None)
            unbound = verify_attestation(
                passport=passport,
                report=None,
                public_key=None,
                allow_unsigned=True,
            )
            self.assertIsNone(unbound["report_integrity_verified"])
            self.assertIsNone(unbound["report_statement_verified"])
            self.assertIn("source_report_not_verified", unbound["release_blockers"])
            with self.assertRaisesRegex(ValueError, "does not declare release"):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    artifact_root=root,
                    allow_unsigned=True,
                )

    def test_passport_verifies_presented_release_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact_root = root / "payload"
            artifact = artifact_root / "dist" / "example-1.0-py3-none-any.whl"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"approved release artifact")
            report = _fixture_report(root)
            (report / "artifact-manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "algorithm": "sha256",
                        "artifacts": [
                            {
                                "path": "dist/example-1.0-py3-none-any.whl",
                                "sha256": _digest(artifact),
                                "size_bytes": artifact.stat().st_size,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            manifest = json.loads(
                (report / "scan-manifest.json").read_text(encoding="utf-8")
            )
            write_embedded_statement(report, manifest)
            _write_checksums(report)
            passport = root / "passport"
            create_attestation(report=report, output=passport, signing_key=None)

            missing = verify_attestation(
                passport=passport,
                report=report,
                public_key=None,
                allow_unsigned=True,
            )
            self.assertTrue(missing["release_artifacts_required"])
            self.assertFalse(missing["release_artifacts_verified"])
            self.assertEqual(missing["release_artifacts_verified_count"], 0)
            self.assertEqual(missing["release_artifact_directories_verified_count"], 0)
            self.assertIn("release_artifacts_not_verified", missing["release_blockers"])

            verified = verify_attestation(
                passport=passport,
                report=report,
                public_key=None,
                artifact_root=artifact_root,
                allow_unsigned=True,
            )
            self.assertTrue(verified["release_artifacts_verified"])
            self.assertEqual(verified["release_artifacts_verified_count"], 1)
            self.assertEqual(verified["release_artifact_directories_verified_count"], 1)
            self.assertNotIn(
                "release_artifacts_not_verified", verified["release_blockers"]
            )
            sidecar = artifact.parent / "release-notes.txt"
            sidecar.write_text("allowed non-distribution sidecar", encoding="utf-8")
            self.assertTrue(
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    artifact_root=artifact_root,
                    allow_unsigned=True,
                )["release_artifacts_verified"]
            )
            with (
                patch("py_security_suite.passport._MAX_RELEASE_DIRECTORY_ENTRIES", 1),
                self.assertRaisesRegex(ValueError, "bounded entry count"),
            ):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    artifact_root=artifact_root,
                    allow_unsigned=True,
                )
            extra = artifact.parent / "unbound-1.0-py3-none-any.whl"
            extra.write_bytes(b"unbound release payload")
            with self.assertRaisesRegex(ValueError, "does not match Passport subjects"):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    artifact_root=artifact_root,
                    allow_unsigned=True,
                )
            second_extra = artifact.parent / "unbound-2.0-py3-none-any.whl"
            second_extra.write_bytes(b"second unbound release payload")
            with (
                patch("py_security_suite.passport._MAX_RELEASE_MISMATCH_DETAILS", 1),
                self.assertRaisesRegex(ValueError, r"\.\.\. 1 more"),
            ):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    artifact_root=artifact_root,
                    allow_unsigned=True,
                )
            second_extra.unlink()
            extra.unlink()
            disguised = artifact.parent / "disguised.whl"
            disguised.mkdir()
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    artifact_root=artifact_root,
                    allow_unsigned=True,
                )
            disguised.rmdir()
            with (
                patch("py_security_suite.passport._MAX_RELEASE_ARTIFACT_BYTES", 1),
                self.assertRaisesRegex(ValueError, "artifact is too large"),
            ):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    artifact_root=artifact_root,
                    allow_unsigned=True,
                )
            invalid_root = root / "payload-file"
            invalid_root.write_text("not a directory", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not a regular directory"):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    artifact_root=invalid_root,
                    allow_unsigned=True,
                )

            artifact.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "artifact digest mismatch"):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    artifact_root=artifact_root,
                    allow_unsigned=True,
                )
            artifact.unlink()
            with self.assertRaisesRegex(ValueError, "artifact is unavailable"):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    artifact_root=artifact_root,
                    allow_unsigned=True,
                )

            digest = {"sha256": "a" * 64}
            with self.assertRaisesRegex(ValueError, "subject set is invalid"):
                _release_artifact_subjects({"subject": {}})
            with self.assertRaisesRegex(ValueError, "exactly one source"):
                _release_artifact_subjects(
                    {"subject": [{"name": "dist/example.whl", "digest": digest}]}
                )
            with self.assertRaisesRegex(ValueError, "unsafe evidence path"):
                _release_artifact_subjects(
                    {
                        "subject": [
                            {"name": "source:fixture", "digest": digest},
                            {"name": "../example.whl", "digest": digest},
                        ]
                    }
                )
            with self.assertRaisesRegex(ValueError, "unsupported release artifact"):
                _release_artifact_subjects(
                    {
                        "subject": [
                            {"name": "source:fixture", "digest": digest},
                            {"name": "dist/release-notes.txt", "digest": digest},
                        ]
                    }
                )
            with self.assertRaisesRegex(ValueError, "directory is unavailable"):
                _verify_release_artifact_sets(
                    artifact_root, {"missing/example.whl": "a" * 64}
                )

    def test_unsigned_passport_verifies_report_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            self.assertTrue(verify_report(report)["verified"])
            passport = root / "passport"
            material = create_attestation(
                report=report,
                output=passport,
                signing_key=None,
            )
            self.assertFalse(material["signed"])
            verified = verify_attestation(
                passport=passport,
                report=report,
                public_key=None,
                allow_unsigned=True,
            )
            self.assertTrue(verified["verified"])
            self.assertTrue(verified["integrity_only"])
            self.assertEqual(verified["verification_status"], "verified")
            self.assertEqual(verified["verification_scope"], "integrity-only")
            self.assertTrue(verified["passport_integrity_verified"])
            self.assertTrue(verified["report_integrity_verified"])
            self.assertTrue(verified["report_statement_verified"])
            self.assertEqual(verified["authenticity_status"], "not_verified")
            self.assertTrue(verified["policy_passed"])
            self.assertEqual(verified["policy_verification_result"], "PASSED")
            self.assertEqual(verified["release_decision"], "not_approved")
            self.assertEqual(
                verified["release_blockers"], ["signer_authenticity_not_verified"]
            )
            (passport / "security-passport.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    allow_unsigned=True,
                )

    def test_detached_passport_statement_must_match_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            passport = root / "passport"
            create_attestation(report=report, output=passport, signing_key=None)

            statement_path = report / "security-passport.json"
            embedded = json.loads(statement_path.read_text(encoding="utf-8"))
            embedded["untrusted_transport_claim"] = True
            statement_path.write_text(json.dumps(embedded), encoding="utf-8")
            _write_checksums(report)
            self.assertTrue(verify_report(report)["verified"])

            material_path = passport / "verification-material.json"
            material = json.loads(material_path.read_text(encoding="utf-8"))
            material["report_checksums_sha256"] = _digest(report / "checksums.sha256")
            material_path.write_text(json.dumps(material), encoding="utf-8")
            _write_checksums(passport)
            with self.assertRaisesRegex(ValueError, "does not match report statement"):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    allow_unsigned=True,
                )

            material["schema_version"] = "2.0"
            material_path.write_text(json.dumps(material), encoding="utf-8")
            _write_checksums(passport)
            with self.assertRaisesRegex(ValueError, "verification material is invalid"):
                verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=None,
                    allow_unsigned=True,
                )
            with self.assertRaisesRegex(
                ValueError, "signed Passport verification material is invalid"
            ):
                _validate_verification_material(
                    {
                        "schema_version": "1.0",
                        "suite_version": "0.1.0",
                        "created_at": "2026-08-04T00:00:00Z",
                        "report": "fixture",
                        "report_checksums_sha256": "a" * 64,
                        "signed": True,
                    }
                )

    def test_signed_passport_binds_and_rechecks_cosign_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            cosign = root / "cosign.exe"
            cosign.write_bytes(b"approved cosign fixture")
            key = root / "cosign.key"
            key.write_text("private fixture", encoding="utf-8")
            public = root / "cosign.pub"
            public.write_text("public fixture", encoding="utf-8")

            def fake_sign(command: list[str], **_: object) -> RawExecution:
                signature = Path(command[command.index("--output-signature") + 1])
                signature.write_text("detached-signature", encoding="utf-8")
                return RawExecution(command, 0, "", "", 0.01)

            passport = root / "signed-passport"
            with (
                patch(
                    "py_security_suite.passport.resolve_executable",
                    return_value=str(cosign),
                ),
                patch("py_security_suite.passport.run_command", side_effect=fake_sign),
                patch(
                    "py_security_suite.passport._cosign_major_version",
                    return_value=2,
                ),
            ):
                material = create_attestation(
                    report=report,
                    output=passport,
                    signing_key=key,
                    cosign_executable=str(cosign),
                    cosign_sha256=_digest(cosign),
                )
            self.assertTrue(material["signed"])
            self.assertTrue(material["cosign_integrity_verified"])

            with (
                patch(
                    "py_security_suite.passport.resolve_executable",
                    return_value=str(cosign),
                ),
                patch(
                    "py_security_suite.passport.run_command",
                    return_value=RawExecution(
                        [str(cosign), "verify-blob"], 0, "Verified OK", "", 0.01
                    ),
                ),
            ):
                verified = verify_attestation(
                    passport=passport,
                    report=report,
                    public_key=public,
                    cosign_executable=str(cosign),
                    cosign_sha256=_digest(cosign),
                )
            self.assertTrue(verified["authentic"])
            self.assertFalse(verified["integrity_only"])
            self.assertEqual(
                verified["verification_scope"], "authenticity-and-integrity"
            )
            self.assertEqual(verified["authenticity_status"], "verified")
            self.assertTrue(verified["policy_passed"])
            self.assertEqual(verified["release_decision"], "approved")
            self.assertEqual(verified["release_blockers"], [])

    def test_passport_authenticity_and_report_binding_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            passport = root / "passport"
            passport.mkdir()
            statement = passport / "security-passport.json"
            statement.write_text("{}", encoding="utf-8")
            signature = passport / "security-passport.sig"
            signature.write_text("signature", encoding="utf-8")
            key = root / "cosign.pub"
            key.write_text("public key", encoding="utf-8")
            cosign = root / "cosign.exe"
            cosign.write_bytes(b"approved verifier")
            material = {"signed": True, "signature": signature.name}

            def verify_authenticity(
                public_key: Path | None = key, cosign_sha256: str = ""
            ) -> bool:
                return _verify_passport_authenticity(
                    passport=passport,
                    material=material,
                    public_key=public_key,
                    cosign_executable=str(cosign),
                    cosign_sha256=cosign_sha256,
                    allow_unsigned=False,
                )

            with self.assertRaisesRegex(ValueError, "public key is required"):
                verify_authenticity(public_key=None)
            signature.unlink()
            with self.assertRaisesRegex(ValueError, "signature material"):
                verify_authenticity()
            signature.write_text("signature", encoding="utf-8")
            with (
                patch(
                    "py_security_suite.passport.resolve_executable", return_value=None
                ),
                self.assertRaisesRegex(ValueError, "executable is unavailable"),
            ):
                verify_authenticity()
            with (
                patch(
                    "py_security_suite.passport.resolve_executable",
                    return_value=str(cosign),
                ),
                self.assertRaisesRegex(ValueError, "approved SHA-256"),
            ):
                verify_authenticity(cosign_sha256="0" * 64)
            for execution in (
                RawExecution([str(cosign)], 1, "", "failed", 0.01),
                RawExecution([str(cosign)], None, "", "", 0.01, timed_out=True),
            ):
                with (
                    self.subTest(execution=execution),
                    patch(
                        "py_security_suite.passport.resolve_executable",
                        return_value=str(cosign),
                    ),
                    patch(
                        "py_security_suite.passport.run_command",
                        return_value=execution,
                    ),
                    self.assertRaisesRegex(ValueError, "signature verification failed"),
                ):
                    verify_authenticity()
            with (
                patch(
                    "py_security_suite.passport.resolve_executable",
                    return_value=str(cosign),
                ),
                patch(
                    "py_security_suite.passport.run_command",
                    return_value=RawExecution(
                        [str(cosign)], 0, "Verified OK", "", 0.01
                    ),
                ),
                patch(
                    "py_security_suite.passport.sha256_file",
                    side_effect=["a" * 64, "b" * 64],
                ),
                self.assertRaisesRegex(ValueError, "changed while verifying"),
            ):
                verify_authenticity()

            report = _fixture_report(root)
            report_statement = json.loads(
                (report / "security-passport.json").read_text(encoding="utf-8")
            )
            with self.assertRaisesRegex(ValueError, "does not match the passport"):
                _verify_bound_report(
                    report,
                    {"report_checksums_sha256": "0" * 64},
                    report_statement,
                )

    def test_verified_failed_policy_is_not_mislabeled_as_integrity_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            manifest_path = report / "scan-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["outcome"] = "fail"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            write_embedded_statement(report, manifest)
            _write_checksums(report)
            passport = root / "passport"
            create_attestation(report=report, output=passport, signing_key=None)
            verified = verify_attestation(
                passport=passport,
                report=report,
                public_key=None,
                allow_unsigned=True,
            )
        self.assertTrue(verified["verified"])
        self.assertTrue(verified["report_integrity_verified"])
        self.assertFalse(verified["policy_passed"])
        self.assertEqual(verified["policy_verification_result"], "FAILED")
        self.assertEqual(verified["outcome"], "fail")
        self.assertEqual(verified["release_decision"], "not_approved")
        self.assertEqual(
            verified["release_blockers"],
            ["signer_authenticity_not_verified", "scan_policy_not_satisfied"],
        )

    def test_cosign_v3_signing_fails_closed_without_network_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            cosign = root / "cosign.exe"
            cosign.write_bytes(b"approved cosign fixture")
            key = root / "cosign.key"
            key.write_text("private fixture", encoding="utf-8")
            with (
                patch(
                    "py_security_suite.passport.resolve_executable",
                    return_value=str(cosign),
                ),
                patch(
                    "py_security_suite.passport._cosign_major_version",
                    return_value=3,
                ),
            ):
                with self.assertRaisesRegex(ValueError, "approved signing lane"):
                    passport = root / "passport"
                    create_attestation(
                        report=report,
                        output=passport,
                        signing_key=key,
                        cosign_executable=str(cosign),
                    )
            self.assertFalse(passport.exists())

    def test_unsigned_passport_rejects_signing_only_options(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            with self.assertRaisesRegex(ValueError, "require a signing key"):
                create_attestation(
                    report=report,
                    output=root / "passport",
                    signing_key=None,
                    allow_signing_network=True,
                )

    def test_failed_signing_preserves_existing_passport_and_removes_staging(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            passport = root / "passport"
            create_attestation(report=report, output=passport, signing_key=None)
            original = (passport / "checksums.sha256").read_bytes()
            cosign = root / "cosign.exe"
            cosign.write_bytes(b"approved cosign fixture")
            key = root / "cosign.key"
            key.write_text("private fixture", encoding="utf-8")
            with (
                patch(
                    "py_security_suite.passport.resolve_executable",
                    return_value=str(cosign),
                ),
                patch(
                    "py_security_suite.passport._cosign_major_version",
                    return_value=2,
                ),
                patch(
                    "py_security_suite.passport.run_command",
                    return_value=RawExecution(
                        [str(cosign), "sign-blob"], 1, "", "failed", 0.01
                    ),
                ),
            ):
                with self.assertRaisesRegex(ValueError, "could not sign"):
                    create_attestation(
                        report=report,
                        output=passport,
                        signing_key=key,
                        cosign_executable=str(cosign),
                        overwrite=True,
                    )
            self.assertEqual((passport / "checksums.sha256").read_bytes(), original)
            self.assertEqual(list(root.glob(".passport.staging-*")), [])

    def test_passport_publication_verifies_staging_and_preserves_collisions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            passport = root / "passport"
            original_verify = _verify_checksums

            def verify_and_create_collision(path: Path) -> int:
                count = original_verify(path)
                if path != report:
                    passport.mkdir()
                    (passport / "sentinel.txt").write_text("keep", encoding="utf-8")
                return count

            with (
                patch(
                    "py_security_suite.passport._verify_checksums",
                    side_effect=verify_and_create_collision,
                ),
                self.assertRaisesRegex(ValueError, "already exists"),
            ):
                create_attestation(report=report, output=passport, signing_key=None)
            self.assertEqual(
                (passport / "sentinel.txt").read_text(encoding="utf-8"), "keep"
            )
            self.assertEqual(list(root.glob(".passport.staging-*")), [])

            invalid = root / "invalid-passport"

            def write_invalid_checksums(staging: Path) -> None:
                (staging / "checksums.sha256").write_text(
                    f"{'0' * 64}  security-passport.json\n",
                    encoding="utf-8",
                    newline="\n",
                )

            with (
                patch(
                    "py_security_suite.passport._write_checksums",
                    side_effect=write_invalid_checksums,
                ),
                self.assertRaisesRegex(ValueError, "checksum mismatch"),
            ):
                create_attestation(report=report, output=invalid, signing_key=None)
            self.assertFalse(invalid.exists())
            self.assertEqual(list(root.glob(".invalid-passport.staging-*")), [])

    def test_passport_overwrite_rolls_back_failed_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            passport = root / "passport"
            create_attestation(report=report, output=passport, signing_key=None)
            original = (passport / "checksums.sha256").read_bytes()
            original_replace = Path.replace

            def fail_staging_replace(source: Path, target: Path) -> Path:
                if source.name.startswith(".passport.staging-"):
                    raise OSError("simulated publication failure")
                return original_replace(source, target)

            with (
                patch.object(Path, "replace", fail_staging_replace),
                self.assertRaisesRegex(OSError, "publication failure"),
            ):
                create_attestation(
                    report=report,
                    output=passport,
                    signing_key=None,
                    overwrite=True,
                )
            self.assertEqual((passport / "checksums.sha256").read_bytes(), original)
            self.assertEqual(list(root.glob(".passport.staging-*")), [])
            self.assertEqual(list(root.glob(".passport.backup-*")), [])

    def test_passport_overwrite_publishes_verified_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            passport = root / "passport"
            create_attestation(report=report, output=passport, signing_key=None)
            material = create_attestation(
                report=report,
                output=passport,
                signing_key=None,
                overwrite=True,
            )
            verified = verify_attestation(
                passport=passport,
                report=report,
                public_key=None,
                allow_unsigned=True,
            )
            self.assertFalse(material["signed"])
            self.assertTrue(verified["passport_integrity_verified"])
            self.assertEqual(list(root.glob(".passport.staging-*")), [])
            self.assertEqual(list(root.glob(".passport.backup-*")), [])

    def test_passport_output_link_is_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            with (
                patch.object(Path, "is_junction", return_value=True, create=True),
                self.assertRaisesRegex(ValueError, "symbolic link or junction"),
            ):
                create_attestation(
                    report=report,
                    output=root / "passport-link",
                    signing_key=None,
                )

    def test_evidence_roots_and_trust_files_reject_links_before_resolution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            passport = root / "passport"
            create_attestation(report=report, output=passport, signing_key=None)
            trust_file = root / "release.pub"
            trust_file.write_text("fixture", encoding="utf-8")
            with patch.object(Path, "is_junction", return_value=True, create=True):
                with self.assertRaisesRegex(ValueError, "report cannot be"):
                    verify_report(report)
                with self.assertRaisesRegex(ValueError, "passport cannot be"):
                    verify_attestation(
                        passport=passport,
                        report=None,
                        public_key=None,
                        allow_unsigned=True,
                    )
                with self.assertRaisesRegex(ValueError, "symbolic link or junction"):
                    _regular_file(trust_file, "public key")

    def test_cosign_v3_uses_bundle_after_explicit_network_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _fixture_report(root)
            cosign = root / "cosign.exe"
            cosign.write_bytes(b"approved cosign fixture")
            key = root / "cosign.key"
            key.write_text("private fixture", encoding="utf-8")

            def fake_sign(command: list[str], **_: object) -> RawExecution:
                bundle = Path(command[command.index("--bundle") + 1])
                bundle.write_text("{}", encoding="utf-8")
                return RawExecution(command, 0, "", "", 0.01)

            with (
                patch(
                    "py_security_suite.passport.resolve_executable",
                    return_value=str(cosign),
                ),
                patch(
                    "py_security_suite.passport._cosign_major_version",
                    return_value=3,
                ),
                patch("py_security_suite.passport.run_command", side_effect=fake_sign),
            ):
                material = create_attestation(
                    report=report,
                    output=root / "passport",
                    signing_key=key,
                    cosign_executable=str(cosign),
                    allow_signing_network=True,
                )
            self.assertEqual(material["signature_format"], "sigstore-bundle-v0.3")
            self.assertTrue(material["signing_network_approved"])
            public = root / "cosign.pub"
            public.write_text("public fixture", encoding="utf-8")
            with (
                patch(
                    "py_security_suite.passport.resolve_executable",
                    return_value=str(cosign),
                ),
                patch(
                    "py_security_suite.passport.run_command",
                    return_value=RawExecution(
                        [str(cosign), "verify-blob"], 0, "Verified OK", "", 0.01
                    ),
                ) as execution,
            ):
                verified = verify_attestation(
                    passport=root / "passport",
                    report=report,
                    public_key=public,
                    cosign_executable=str(cosign),
                )
            command = execution.call_args.args[0]
            self.assertIn("--bundle", command)
            self.assertNotIn("--signature", command)
            self.assertTrue(verified["authentic"])


def _record(finding: Finding) -> dict[str, object]:
    return {
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "title": finding.title,
        "severity": finding.severity.value,
        "domain": finding.domain,
        "area": finding.area,
        "status": finding.status.value,
        "locations": [
            {
                "path": finding.locations[0].path,
                "start_line": finding.locations[0].start_line,
            }
        ],
        "sources": [
            {
                "tool": finding.sources[0].tool,
                "rule_id": finding.sources[0].rule_id,
            }
        ],
    }


def _write_checksums(root: Path) -> None:
    lines = [
        f"{_digest(path)}  {path.relative_to(root).as_posix()}"
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "checksums.sha256"
    ]
    (root / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _fixture_report(root: Path) -> Path:
    report = root / "report"
    report.mkdir()
    manifest = {
        "schema_version": "1.0",
        "suite_version": "0.1.0",
        "scan_id": "scan-fixture",
        "target": "test",
        "profile": "standard",
        "outcome": "pass",
        "finished_at": "2026-08-03T00:00:00Z",
        "configuration_sha256": "b" * 64,
        "network_isolation_attested": False,
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
    (report / "scan-manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    for relative in REQUIRED_REPORT_ARTIFACTS.values():
        path = report / relative
        if not path.exists() and relative not in {
            "checksums.sha256",
            "security-passport.json",
        }:
            path.write_text("fixture\n", encoding="utf-8")
    write_embedded_statement(report, manifest)
    _write_checksums(report)
    return report


if __name__ == "__main__":
    unittest.main()
