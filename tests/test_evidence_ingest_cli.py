from __future__ import annotations

import io
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.evidence_ingest import (
    _assurance_document,
    _bind_evidence,
    _branch_list,
    _coverage_document,
    _integer,
    _integer_list,
    _junit_document,
    _junit_paths,
    _scorecard_document,
    _binding_path,
    _consume_replay_service,
    main,
)
from py_security_suite.report_inspection import read_bundled_schema


class EvidenceIngestCliTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary))

    def _run(self, *arguments: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(list(arguments))
        return status, stdout.getvalue(), stderr.getvalue()

    def test_cli_normalizes_each_supported_evidence_family(self) -> None:
        coverage = self.root / "coverage.json"
        coverage.write_text(
            json.dumps(
                {
                    "meta": {"format": 3, "branch_coverage": True},
                    "totals": {},
                    "files": {},
                }
            ),
            encoding="utf-8",
        )
        junit = self.root / "junit.xml"
        junit.write_text(
            '<testsuite><testcase name="ok" time="0.25" /></testsuite>',
            encoding="utf-8",
        )
        scorecard = self.root / "scorecard.json"
        scorecard.write_text(json.dumps({"checks": [], "score": 10}), encoding="utf-8")
        assurance = self.root / "oci.json"
        assurance.write_text(
            json.dumps({"kind": "oci-image", "findings": []}), encoding="utf-8"
        )

        invocations = (
            (("coverage", str(coverage)), "coverage"),
            (("junit", str(junit)), "junit"),
            (("scorecard", str(scorecard)), "scorecard"),
            (("assurance", "oci-image", str(assurance)), "oci-image"),
        )
        for arguments, expected_kind in invocations:
            with self.subTest(kind=expected_kind):
                status, output, error = self._run(*arguments)
                self.assertEqual(status, 0)
                self.assertEqual(json.loads(output)["kind"], expected_kind)
                self.assertEqual(error, "")

    def test_cli_returns_sanitized_error_for_invalid_evidence(self) -> None:
        malformed = self.root / "coverage.json"
        malformed.write_text("[]", encoding="utf-8")
        status, output, error = self._run("coverage", str(malformed))
        self.assertEqual(status, 2)
        self.assertEqual(output, "")
        self.assertIn("invalid coverage evidence", error)

    def test_bind_command_attaches_verified_source_identity_to_runtime_evidence(
        self,
    ) -> None:
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        coverage = self.root / "coverage.json"
        coverage.write_text(
            json.dumps({"meta": {}, "totals": {}, "files": {}}),
            encoding="utf-8",
        )
        junit = self.root / "junit.xml"
        junit.write_text(
            '<testsuite><testcase name="ok" file="tests/test_app.py" /></testsuite>',
            encoding="utf-8",
        )
        assurance = self.root / "iast.json"
        assurance.write_text(
            json.dumps({"kind": "iast", "producer": "test", "findings": []}),
            encoding="utf-8",
        )

        status, output, error = self._run(
            "bind",
            "--source-root",
            str(self.root),
            str(coverage),
            str(junit),
            str(assurance),
        )

        self.assertEqual(status, 0)
        self.assertEqual(error, "")
        receipt = json.loads(output)
        self.assertEqual(receipt["kind"], "evidence-binding")
        self.assertEqual(len(receipt["bindings"]), 3)
        normalized_coverage = _coverage_document(coverage)
        normalized_junit = _junit_document(junit)
        normalized_assurance = _assurance_document(assurance, "iast")
        self.assertEqual(normalized_coverage["source_sha256"], receipt["source_sha256"])
        self.assertEqual(normalized_junit["source_sha256"], receipt["source_sha256"])
        self.assertTrue(normalized_coverage["evidence_binding"]["verified"])
        self.assertTrue(normalized_junit["evidence_binding"]["verified"])
        self.assertEqual(
            normalized_assurance["source_sha256"], receipt["source_sha256"]
        )
        self.assertTrue(normalized_assurance["evidence_binding"]["verified"])
        assurance_schema = json.loads(read_bundled_schema("companion-assurance-1.0"))
        Draft202012Validator.check_schema(assurance_schema)
        Draft202012Validator(assurance_schema).validate(normalized_assurance)
        self.assertTrue(_binding_path(coverage.resolve()).is_file())

        coverage.write_text(
            json.dumps({"meta": {}, "totals": {}, "files": {}, "changed": True}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            _coverage_document(coverage)
        assurance.write_text(
            json.dumps(
                {"kind": "iast", "producer": "test", "findings": [], "changed": True}
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            _assurance_document(assurance, "iast")
        second_status, _, second_error = self._run(
            "bind",
            "--source-root",
            str(self.root),
            str(coverage),
            str(junit),
        )
        self.assertEqual(second_status, 2)
        self.assertIn("already exists", second_error)

    def test_coverage_rejects_invalid_shapes_and_values(self) -> None:
        path = self.root / "coverage.json"
        invalid_documents: tuple[object, ...] = (
            [],
            {"meta": {}, "totals": {}},
            {"meta": {}, "totals": {}, "files": {"x.py": []}},
            {
                "meta": {},
                "totals": {},
                "files": {"x.py": {"summary": {}, "missing_lines": "1"}},
            },
            {
                "meta": {},
                "totals": {},
                "files": {"x.py": {"summary": {}, "missing_branches": [[1, 2, 3]]}},
            },
        )
        for document in invalid_documents:
            with self.subTest(document=document):
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises((TypeError, ValueError)):
                    _coverage_document(path)
        with self.assertRaises(TypeError):
            _integer("not-an-integer")
        with self.assertRaises(TypeError):
            _integer_list("1")
        with self.assertRaises(TypeError):
            _branch_list([[1]])

    def test_v2_assurance_requires_fresh_complete_signed_execution(self) -> None:
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        private = Ed25519PrivateKey.generate()
        private_path = self.root / "signing.pem"
        public_path = self.root / "signing.pub"
        private_path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public_path.write_bytes(
            private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        generated = datetime.now(UTC)
        expected_context = {
            "target_manifest_sha256": "5" * 64,
            "exercised_targets_sha256": "6" * 64,
            "deployment_sha256": "7" * 64,
            "surface_sha256": "8" * 64,
            "challenge_sha256": "9" * 64,
            "trusted_time_sha256": "a" * 64,
            "trusted_time_observed_at": generated.isoformat(),
            "trusted_time_receipt_sha256": "b" * 64,
            "trusted_time_signer_sha256": "c" * 64,
        }
        expected_context_path = self.root / "expected-context.json"
        expected_context_path.write_text("{}", encoding="utf-8")
        context_patcher = patch(
            "py_security_suite.evidence_ingest._expected_assurance_context",
            return_value=("run-1", expected_context),
        )
        context_patcher.start()
        self.addCleanup(context_patcher.stop)
        evidence = self.root / "nuclei.json"
        evidence.write_text(
            json.dumps(
                {
                    "schema_version": "2.0",
                    "kind": "nuclei",
                    "producer": "nuclei",
                    "producer_version": "3.4.0",
                    "producer_sha256": "1" * 64,
                    "revision": "abc123",
                    "generated_at": generated.isoformat(),
                    "expires_at": (generated + timedelta(hours=1)).isoformat(),
                    "run_id": "run-1",
                    "artifact_sha256": "",
                    "ruleset_sha256": "2" * 64,
                    "config_sha256": "3" * 64,
                    "environment": "isolated-loopback",
                    "environment_sha256": "4" * 64,
                    "context": expected_context,
                    "provenance": {
                        "schema_version": "1.0",
                        "builder_id": "github-actions/runtime-assurance",
                        "builder_sha256": "d" * 64,
                        "native_report_sha256": "e" * 64,
                        "normalizer_sha256": "f" * 64,
                        "invocation_sha256": "1" * 64,
                        "materials_sha256": "2" * 64,
                    },
                    "execution": {
                        "status": "completed",
                        "targets_discovered": 4,
                        "targets_exercised": 4,
                        "requests": 120,
                        "coverage_percent": 100.0,
                        "coverage_metric": "approved-template-workflow",
                        "roles": ["anonymous", "user"],
                        "features": ["signed-templates", "approved-workflow"],
                        "skipped_checks": [],
                        "canaries_expected": 2,
                        "canaries_observed": 2,
                    },
                    "findings": [],
                }
            ),
            encoding="utf-8",
        )
        _bind_evidence(
            [evidence],
            source_root=self.root,
            overwrite=False,
            signing_key=private_path,
            run_id="run-1",
            valid_for_hours=0.5,
        )
        document = _assurance_document(
            evidence,
            "nuclei",
            minimum_coverage_percent=90.0,
            require_contract_v2=True,
            public_key=public_path,
            require_signature=True,
            expected_context=expected_context_path,
        )
        self.assertTrue(document["evidence_binding"]["authenticated"])
        self.assertEqual(document["execution"]["targets_exercised"], 4)
        schema = json.loads(read_bundled_schema("companion-assurance-2.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

        profile_path = self.root / "profile-v2.json"
        profile_path.write_text("{}", encoding="utf-8")
        profile_metadata = {
            "profile_id": "production-v2",
            "profile_generation": 8,
            "profile_authority_signers": ["a" * 64, "b" * 64],
            "profile_authority_signer_refs": [
                "ed25519:" + "a" * 64,
                "ecdsa-p256-sha256:" + "b" * 64,
            ],
            "profile_authority_organizations": ["security", "release"],
            "profile_checkpoint_backend": "https-cas-transparency",
            "profile_sha256": "c" * 64,
            "profile_subject_sha256": "d" * 64,
            "profile_checkpoint_sequence": 11,
            "profile_trusted_time_sha256": "e" * 64,
        }
        with (
            patch(
                "py_security_suite.evidence_ingest.load_assurance_profile",
                return_value={"schema_version": "2.0"},
            ) as load_profile,
            patch(
                "py_security_suite.evidence_ingest.enforce_assurance_profile",
                return_value=profile_metadata,
            ),
        ):
            governed = _assurance_document(
                evidence,
                "nuclei",
                require_contract_v2=True,
                public_key=public_path,
                require_signature=True,
                expected_context=expected_context_path,
                assurance_profile=profile_path,
                require_assurance_profile=True,
            )
        load_profile.assert_called_once_with(profile_path, require_checkpoint=True)
        self.assertEqual(governed["assurance_profile"]["profile_sha256"], "c" * 64)
        expected_governed = hashlib.sha256(
            json.dumps(
                {
                    "assurance_profile_sha256": "c" * 64,
                    "evidence_sha256": governed["evidence_binding"]["evidence_sha256"],
                    "source_sha256": governed["source_sha256"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        self.assertEqual(governed["governed_evidence_sha256"], expected_governed)
        with self.assertRaisesRegex(ValueError, "profile is required"):
            _assurance_document(
                evidence,
                "nuclei",
                require_contract_v2=True,
                expected_context=expected_context_path,
                require_assurance_profile=True,
            )

        ledger = self.root / "consumed-evidence.sqlite3"
        consumed = _assurance_document(
            evidence,
            "nuclei",
            require_contract_v2=True,
            public_key=public_path,
            require_signature=True,
            expected_run_id="run-1",
            expected_environment_sha256="4" * 64,
            expected_context=expected_context_path,
            replay_ledger=ledger,
        )
        self.assertEqual(consumed["run_id"], "run-1")
        with self.assertRaisesRegex(ValueError, "replay"):
            _assurance_document(
                evidence,
                "nuclei",
                require_contract_v2=True,
                public_key=public_path,
                require_signature=True,
                expected_context=expected_context_path,
                replay_ledger=ledger,
            )
        with self.assertRaisesRegex(ValueError, "expected run"):
            _assurance_document(
                evidence,
                "nuclei",
                require_contract_v2=True,
                expected_run_id="different-run",
                expected_context=expected_context_path,
            )

        payload = json.loads(evidence.read_text(encoding="utf-8"))
        payload["execution"]["coverage_percent"] = 10
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not match"):
            _assurance_document(
                evidence,
                "nuclei",
                require_contract_v2=True,
                public_key=public_path,
                require_signature=True,
                expected_context=expected_context_path,
            )
        payload["execution"]["canaries_observed"] = 1
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "canary coverage"):
            _assurance_document(
                evidence,
                "nuclei",
                require_contract_v2=True,
                expected_context=expected_context_path,
            )
        payload["execution"]["canaries_observed"] = 2
        payload["execution"]["features"] = ["signed-templates"]
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "approved-workflow"):
            _assurance_document(
                evidence,
                "nuclei",
                require_contract_v2=True,
                expected_context=expected_context_path,
            )

    def test_v2_binding_rejects_unverifiable_custom_key_id(self) -> None:
        evidence = self.root / "evidence.json"
        evidence.write_text(
            json.dumps({"kind": "nuclei", "findings": []}), encoding="utf-8"
        )
        private = Ed25519PrivateKey.generate()
        private_path = self.root / "signing.pem"
        private_path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        with self.assertRaisesRegex(ValueError, "key_id"):
            _bind_evidence(
                [evidence],
                source_root=self.root,
                overwrite=False,
                signing_key=private_path,
                key_id="friendly-but-unverifiable-label",
            )

    def test_keyring_enforces_distinct_multi_signature_threshold(self) -> None:
        evidence = self.root / "evidence.json"
        evidence.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "kind": "nuclei",
                    "producer": "nuclei",
                    "revision": "abc",
                    "generated_at": datetime.now(UTC).isoformat(),
                    "artifact_sha256": "",
                    "environment": "isolated",
                    "findings": [],
                }
            ),
            encoding="utf-8",
        )
        private_paths: list[Path] = []
        key_records: list[dict[str, str]] = []
        for index in range(2):
            private = Ed25519PrivateKey.generate()
            private_path = self.root / f"key-{index}.pem"
            public_path = self.root / f"key-{index}.pub"
            private_path.write_bytes(
                private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            public_path.write_bytes(
                private.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            private_paths.append(private_path)
            key_records.append(
                {
                    "file": public_path.name,
                    "sha256": hashlib.sha256(public_path.read_bytes()).hexdigest(),
                    "not_before": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
                    "not_after": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                    "status": "active",
                }
            )
        keyring = self.root / "keyring.json"
        keyring.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "threshold": 2,
                    "keys": key_records,
                }
            ),
            encoding="utf-8",
        )
        _bind_evidence(
            [evidence],
            source_root=self.root,
            overwrite=False,
            signing_key=private_paths[0],
            additional_signing_keys=[private_paths[1]],
            run_id="multi-signer",
        )

        document = _assurance_document(
            evidence, "nuclei", public_keyring=keyring, require_signature=True
        )

        assert document["evidence_binding"]["attestation"]["signature_count"] == 2

    def test_https_replay_service_requires_signed_receipt(self) -> None:
        document = {
            "run_id": "run-1",
            "kind": "nuclei",
            "source_sha256": "1" * 64,
            "environment_sha256": "2" * 64,
            "context": {"challenge": "3" * 64},
            "provenance": {"native_report_sha256": "4" * 64},
            "evidence_binding": {
                "authenticated": True,
                "evidence_sha256": "5" * 64,
                "attestation": {"key_id": "6" * 64},
            },
        }

        class Response:
            status = 201
            headers = {"Content-Length": "0"}

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

        with (
            patch.dict("os.environ", {"PYSEC_REPLAY_TOKEN": "opaque-token"}),
            patch(
                "py_security_suite.evidence_ingest.urlopen", return_value=Response()
            ) as request,
            self.assertRaisesRegex(ValueError, "deployment-pinned receipt key"),
        ):
            _consume_replay_service(
                document,
                "https://replay.example.test/consume",
                token_env="PYSEC_REPLAY_TOKEN",  # noqa: S106 - environment name only.
                ca_path=None,
            )

        assert request.call_count == 0

    def test_junit_directory_aggregates_failures_errors_and_skips(self) -> None:
        reports = self.root / "reports"
        reports.mkdir()
        (reports / "one.xml").write_text(
            '<testsuite><testcase name="failed" classname="C" file="t.py" '
            'line="7" time="0.1"><failure message="no" type="AssertionError" />'
            "</testcase></testsuite>",
            encoding="utf-8",
        )
        (reports / "two.xml").write_text(
            '<testsuite><testcase name="errored"><error message="boom" /></testcase>'
            '<testcase name="skipped"><skipped /></testcase></testsuite>',
            encoding="utf-8",
        )
        document = _junit_document(reports)
        self.assertEqual(document["report_count"], 2)
        self.assertEqual(document["totals"]["tests"], 3)
        self.assertEqual(document["totals"]["failures"], 1)
        self.assertEqual(document["totals"]["errors"], 1)
        self.assertEqual(document["totals"]["skipped"], 1)
        self.assertEqual(len(document["failures"]), 2)
        self.assertTrue(document["test_case_inventory_complete"])
        self.assertEqual(
            [item["result"] for item in document["test_cases"]],
            ["failure", "error", "skipped"],
        )
        self.assertEqual(document["test_cases"][0]["file"], "t.py")

    def test_junit_rejects_missing_empty_and_symlink_paths(self) -> None:
        missing = self.root / "missing"
        with self.assertRaisesRegex(ValueError, "does not exist"):
            _junit_paths(missing)
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaisesRegex(ValueError, "no JUnit"):
            _junit_paths(empty)

    def test_scorecard_and_assurance_reject_untrusted_shapes(self) -> None:
        path = self.root / "evidence.json"
        invalid_scorecards: tuple[object, ...] = ([], {}, {"checks": ["invalid"]})
        for document in invalid_scorecards:
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises((TypeError, ValueError)):
                _scorecard_document(path)

        path.write_text(json.dumps({"kind": "yara", "findings": []}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "kind"):
            _assurance_document(path, "clamav")
        path.write_text(
            json.dumps({"kind": "clamav", "findings": ["invalid"]}),
            encoding="utf-8",
        )
        with self.assertRaises(TypeError):
            _assurance_document(path, "clamav")
        path.write_text(
            json.dumps(
                {
                    "kind": "clamav",
                    "findings": [{"severity": "catastrophic"}],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "severity"):
            _assurance_document(path, "clamav")


if __name__ == "__main__":
    unittest.main()
