from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.release_payload import (
    prepare_signing_request,
    verify_signing_request,
)
from py_security_suite import release_payload


class ReleasePayloadTests(unittest.TestCase):
    @patch("py_security_suite.release_payload.verify_report")
    def test_request_binds_report_and_exact_artifact_set(self, verify_mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            artifacts = root / "dist"
            report.mkdir()
            artifacts.mkdir()
            (artifacts / "project-1.0.whl").write_bytes(b"wheel")
            (artifacts / "project-1.0.tar.gz").write_bytes(b"sdist")
            (artifacts / "ignored.txt").write_text("not a distribution")
            _write_json(
                report / "scan-manifest.json",
                {"inventory": {"source_sha256": "a" * 64}},
            )
            verify_mock.return_value = {
                "scan_id": "scan-1",
                "checksums_sha256": "b" * 64,
                "outcome": "pass",
            }

            request = prepare_signing_request(report, artifacts)
            request_path = root / "request.json"
            payload = json.dumps(request, sort_keys=True).encode()
            request_path.write_bytes(payload)
            verification = verify_signing_request(
                request_path,
                artifacts,
                request_sha256=hashlib.sha256(payload).hexdigest(),
            )

        self.assertFalse(request["authoritative"])
        self.assertEqual(request["payload"]["artifact_count"], 2)
        self.assertTrue(verification["exact_artifact_set_verified"])
        self.assertEqual(verification["payload_id"], request["payload"]["id"])
        _validate("signing-request.schema.json", request)
        _validate("signing-request-verification.schema.json", verification)

    @patch("py_security_suite.release_payload.verify_report")
    def test_artifact_change_or_extra_distribution_is_rejected(
        self, verify_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            artifacts = root / "dist"
            report.mkdir()
            artifacts.mkdir()
            artifact = artifacts / "project.whl"
            artifact.write_bytes(b"wheel")
            _write_json(
                report / "scan-manifest.json",
                {"inventory": {"source_sha256": "a" * 64}},
            )
            verify_mock.return_value = {
                "scan_id": "scan-1",
                "checksums_sha256": "b" * 64,
                "outcome": "pass",
            }
            request = prepare_signing_request(report, artifacts)
            request_path = root / "request.json"
            payload = json.dumps(request, sort_keys=True).encode()
            request_path.write_bytes(payload)
            artifact.write_bytes(b"changed")

            with self.assertRaisesRegex(ValueError, "does not match"):
                verify_signing_request(
                    request_path,
                    artifacts,
                    request_sha256=hashlib.sha256(payload).hexdigest(),
                )

    @patch("py_security_suite.release_payload.verify_report")
    def test_empty_artifact_directory_is_rejected(self, verify_mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            artifacts = root / "dist"
            report.mkdir()
            artifacts.mkdir()
            _write_json(report / "scan-manifest.json", {})
            verify_mock.return_value = {
                "scan_id": "scan-1",
                "checksums_sha256": "b" * 64,
                "outcome": "pass",
            }
            with self.assertRaisesRegex(ValueError, "contains no"):
                prepare_signing_request(report, artifacts)

    def test_request_digest_and_size_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / "request.json"
            artifacts = root / "dist"
            artifacts.mkdir()
            (artifacts / "project.whl").write_bytes(b"wheel")
            request.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "64 hexadecimal"):
                verify_signing_request(request, artifacts, request_sha256="bad")
            with patch.object(release_payload, "_MAX_REQUEST_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "size limit"):
                    verify_signing_request(
                        request,
                        artifacts,
                        request_sha256=hashlib.sha256(b"{}").hexdigest(),
                    )
            with self.assertRaisesRegex(ValueError, "approved SHA-256"):
                verify_signing_request(request, artifacts, request_sha256="0" * 64)

    def test_artifact_inventory_bounds_and_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "a.whl"
            first.write_bytes(b"ab")
            with patch.object(release_payload, "_MAX_ARTIFACT_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "size limit"):
                    release_payload._artifact_subjects(root)
            first.unlink()
            first.mkdir()
            with self.assertRaisesRegex(ValueError, "regular file"):
                release_payload._artifact_subjects(root)
            first.rmdir()
            (root / "ignored.txt").write_text("ignored", encoding="utf-8")
            (root / "second.txt").write_text("ignored", encoding="utf-8")
            with patch.object(release_payload, "_MAX_ARTIFACTS", 1):
                with self.assertRaisesRegex(ValueError, "entry limit"):
                    release_payload._artifact_subjects(root)

    def test_untrusted_signing_request_shapes_are_rejected(self) -> None:
        valid = {
            "schema_version": "1.0",
            "status": "candidate",
            "authoritative": False,
            "payload": {
                "id": "a" * 64,
                "artifact_count": 1,
                "subjects": [
                    {"name": "project.whl", "sha256": "b" * 64, "size_bytes": 1}
                ],
            },
        }
        cases: list[tuple[str, object, str]] = [
            ("identity", {**valid, "authoritative": True}, "identity"),
            ("payload", {**valid, "payload": []}, "payload must be"),
            (
                "subjects",
                {**valid, "payload": {"subjects": []}},
                "non-empty",
            ),
            (
                "subject object",
                {**valid, "payload": {"subjects": ["bad"]}},
                "must be objects",
            ),
        ]
        for label, document, message in cases:
            with (
                self.subTest(label=label),
                self.assertRaisesRegex((TypeError, ValueError), message),
            ):
                release_payload._validate_request(document)  # type: ignore[arg-type]

        for mutation in (
            {"name": "../project.whl"},
            {"sha256": "bad"},
            {"size_bytes": True},
            {"size_bytes": -1},
        ):
            document = deepcopy(valid)
            document["payload"]["subjects"][0].update(mutation)  # type: ignore[index,union-attr]
            with self.assertRaisesRegex(ValueError, "subject identity"):
                release_payload._validate_request(document)

        document = deepcopy(valid)
        document["payload"]["artifact_count"] = 2  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "artifact count"):
            release_payload._validate_request(document)
        document = deepcopy(valid)
        document["payload"]["id"] = "bad"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "payload digest"):
            release_payload._validate_request(document)

    def test_json_evidence_requires_bounded_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            evidence.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(TypeError, "must be an object"):
                release_payload._read_object(evidence, 100)
            with self.assertRaisesRegex(ValueError, "exceeds"):
                release_payload._read_object(evidence, 1)


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _validate(name: str, document: object) -> None:
    schema = json.loads(
        files("py_security_suite").joinpath("schemas", name).read_text("utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
