from __future__ import annotations

import hashlib
import base64
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import (  # pylint: disable=import-error
    Draft202012Validator,
    ValidationError,
)

from py_security_suite.effectiveness_corpus import (
    _consume_remote_effectiveness_replay,
    evaluate_report_corpus,
)
from py_security_suite.report_inspection import read_bundled_schema
from py_security_suite.strict_json import canonical_bytes


class EffectivenessCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.report = self.root / "report"
        self.report.mkdir()
        (self.report / "findings.json").write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "finding_id": "PYSEC-DETECTED",
                            "sources": [{"tool": "bandit", "rule_id": "B101"}],
                            "locations": [{"path": "src/example.py"}],
                            "classifications": ["CWE-703"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        files = [
            self._file_record("src/clean.py", b"clean = True\n"),
            self._file_record("src/example.py", b"assert value\n"),
        ]
        aggregate = hashlib.sha256()
        for item in files:
            encoded = item["path"].encode("utf-8")
            aggregate.update(len(encoded).to_bytes(8, "big"))
            aggregate.update(encoded)
            aggregate.update(item["size_bytes"].to_bytes(8, "big"))
            aggregate.update(bytes.fromhex(item["sha256"]))
        source_sha256 = aggregate.hexdigest()
        (self.report / "source-inventory.json").write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "scope": "fixture",
                    "source_sha256": source_sha256,
                    "total_files": len(files),
                    "total_bytes": sum(item["size_bytes"] for item in files),
                    "files": files,
                }
            ),
            encoding="utf-8",
        )
        (self.report / "scan-manifest.json").write_text(
            json.dumps(
                {
                    "inventory": {
                        "source_integrity_verified": True,
                        "source_sha256": source_sha256,
                        "hashed_files": len(files),
                        "hashed_bytes": sum(item["size_bytes"] for item in files),
                    }
                }
            ),
            encoding="utf-8",
        )

    def test_remote_replay_receipt_enforces_signature_and_query_budget(self) -> None:
        private = Ed25519PrivateKey.generate()
        public_path = self.root / "replay.pub.pem"
        public_path.write_bytes(
            private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        replay_key = "a" * 64
        signed = {
            "schema_version": "1.0",
            "status": "consumed",
            "replay_key": replay_key,
            "sequence": 7,
            "holdout_uses": 1,
            "request_sha256": hashlib.sha256(
                canonical_bytes(
                    {
                        "schema_version": "1.0",
                        "replay_key": replay_key,
                        "corpus_id": "holdout",
                        "holdout_labels_sha256": "b" * 64,
                        "observed_at": "2026-08-24T00:00:00+00:00",
                        "query_budget": 1,
                    }
                )
            ).hexdigest(),
            "checkpoint_size": 7,
            "checkpoint_root_sha256": "c" * 64,
        }
        receipt = {
            **signed,
            "signature_base64": base64.b64encode(
                private.sign(canonical_bytes(signed))
            ).decode(),
        }

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, _maximum):
                return canonical_bytes(receipt)

        with (
            patch.dict(os.environ, {"PYSEC_REPLAY_TOKEN": "secret"}),
            patch(
                "py_security_suite.effectiveness_corpus.urlopen",
                return_value=Response(),
            ),
        ):
            result = _consume_remote_effectiveness_replay(
                replay_key,
                corpus_id="holdout",
                holdout_sha256="b" * 64,
                observed_at="2026-08-24T00:00:00+00:00",
                service_url="https://replay.example.invalid/consume",
                token_env="PYSEC_REPLAY_TOKEN",  # noqa: S106 - environment name
                receipt_key=public_path,
                receipt_key_sha256=hashlib.sha256(public_path.read_bytes()).hexdigest(),
                query_budget=1,
            )
        self.assertEqual(result["mode"], "remote-signed-checkpoint")
        self.assertEqual(result["sequence"], 7)

    @staticmethod
    def _file_record(path: str, content: bytes) -> dict[str, Any]:
        return {
            "path": path,
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    def _corpus(self, labels: list[dict[str, object]]) -> tuple[Path, str]:
        path = self.root / "corpus.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "corpus_id": "fixture",
                    "revision": "2026-08-06",
                    "labels": labels,
                }
            ),
            encoding="utf-8",
        )
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_measures_precision_recall_and_retains_label_outcomes(self) -> None:
        corpus, digest = self._corpus(
            [
                {
                    "id": "detected-positive",
                    "expected": "finding",
                    "match": {"tool": "bandit", "rule_id": "B101"},
                },
                {
                    "id": "missed-positive",
                    "expected": "finding",
                    "match": {"tool": "semgrep", "rule_id": "python.lang.x"},
                },
                {
                    "id": "unexpected-positive",
                    "expected": "clean",
                    "match": {"classification": "CWE-703"},
                },
                {
                    "id": "confirmed-clean",
                    "expected": "clean",
                    "match": {"path": "src/clean.py"},
                },
            ]
        )
        with patch(
            "py_security_suite.effectiveness_corpus.verify_report",
            return_value={
                "scan_id": "scan-fixture",
                "outcome": "pass",
                "checksums_sha256": "a" * 64,
                "file_count": 10,
            },
        ):
            result = evaluate_report_corpus(
                self.report,
                corpus,
                corpus_sha256=digest,
            )

        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(
            result["confusion_matrix"],
            {
                "true_positive": 1,
                "true_negative": 1,
                "false_positive": 1,
                "false_negative": 1,
            },
        )
        self.assertEqual(result["metrics"]["precision"], 0.5)
        self.assertEqual(result["metrics"]["recall"], 0.5)
        self.assertEqual(len(result["failures"]), 2)
        schema = json.loads(read_bundled_schema("effectiveness-evaluation-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result)
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate({**result, "unexpected": True})

    def test_requires_digest_binding_and_safe_relative_paths(self) -> None:
        corpus, digest = self._corpus(
            [
                {
                    "id": "unsafe",
                    "expected": "clean",
                    "match": {"path": "../escape.py"},
                }
            ]
        )
        verification = {
            "scan_id": "scan-fixture",
            "outcome": "pass",
            "checksums_sha256": "a" * 64,
            "file_count": 10,
        }
        with (
            patch(
                "py_security_suite.effectiveness_corpus.verify_report",
                return_value=verification,
            ),
            self.assertRaisesRegex(ValueError, "repository-relative"),
        ):
            evaluate_report_corpus(self.report, corpus, corpus_sha256=digest)
        with (
            patch(
                "py_security_suite.effectiveness_corpus.verify_report",
                return_value=verification,
            ),
            self.assertRaisesRegex(ValueError, "does not match"),
        ):
            evaluate_report_corpus(self.report, corpus, corpus_sha256="0" * 64)

    def test_clean_path_must_exist_in_bound_source_inventory(self) -> None:
        corpus, digest = self._corpus(
            [
                {
                    "id": "invented-clean-file",
                    "expected": "clean",
                    "match": {"path": "src/not-present.py"},
                }
            ]
        )
        with (
            patch(
                "py_security_suite.effectiveness_corpus.verify_report",
                return_value={
                    "scan_id": "scan-fixture",
                    "outcome": "pass",
                    "checksums_sha256": "a" * 64,
                    "file_count": 10,
                },
            ),
            self.assertRaisesRegex(
                ValueError, "absent from the sealed source inventory"
            ),
        ):
            evaluate_report_corpus(self.report, corpus, corpus_sha256=digest)

    def test_rejects_invalid_corpus_contracts(self) -> None:
        cases = (
            ({"schema_version": "3.0", "labels": []}, "schema_version"),
            ({"schema_version": "1.0", "labels": []}, "non-empty"),
            (
                {
                    "schema_version": "1.0",
                    "labels": [
                        {"id": "x", "expected": "maybe", "match": {"tool": "bandit"}}
                    ],
                },
                "expected",
            ),
            (
                {
                    "schema_version": "1.0",
                    "labels": [{"id": "x", "expected": "clean", "match": {}}],
                },
                "discriminator",
            ),
        )
        verification = {
            "scan_id": "scan-fixture",
            "outcome": "pass",
            "checksums_sha256": "a" * 64,
            "file_count": 10,
        }
        for document, message in cases:
            with self.subTest(message=message):
                path = self.root / f"invalid-{message}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                with (
                    patch(
                        "py_security_suite.effectiveness_corpus.verify_report",
                        return_value=verification,
                    ),
                    self.assertRaisesRegex((TypeError, ValueError), message),
                ):
                    evaluate_report_corpus(self.report, path, corpus_sha256=digest)

    def test_rejects_invalid_digest_and_findings_shape(self) -> None:
        corpus, digest = self._corpus(
            [{"id": "clean", "expected": "clean", "match": {"tool": "bandit"}}]
        )
        with (
            patch(
                "py_security_suite.effectiveness_corpus.verify_report",
                return_value={
                    "scan_id": "scan-fixture",
                    "outcome": "pass",
                    "checksums_sha256": "a" * 64,
                    "file_count": 10,
                },
            ),
            self.assertRaisesRegex(ValueError, "64 hexadecimal"),
        ):
            evaluate_report_corpus(self.report, corpus, corpus_sha256="bad")

        (self.report / "findings.json").write_text(
            json.dumps({"findings": "invalid"}), encoding="utf-8"
        )
        with (
            patch(
                "py_security_suite.effectiveness_corpus.verify_report",
                return_value={
                    "scan_id": "scan-fixture",
                    "outcome": "pass",
                    "checksums_sha256": "a" * 64,
                    "file_count": 10,
                },
            ),
            self.assertRaisesRegex(TypeError, "array of objects"),
        ):
            evaluate_report_corpus(self.report, corpus, corpus_sha256=digest)

    def test_governed_holdout_requires_independent_organization_quorum(self) -> None:
        labels = [
            {
                "id": f"label-{index}",
                "expected": "finding" if index % 2 == 0 else "clean",
                "match": {
                    "tool": "bandit" if index % 2 == 0 else "no-such-tool",
                    "rule_id": "B101" if index % 2 == 0 else f"CLEAN-{index}",
                },
                "cwe": f"cwe-{index % 5}",
                "language": f"language-{index % 2}",
                "parser_variant": f"parser-{index % 2}",
                "boundary_type": f"boundary-{index % 3}",
                "severity": f"severity-{index % 3}",
                "mutation_operator": f"mutation-{index % 2}",
            }
            for index in range(25)
        ]
        now = datetime.now(UTC)
        signed_at = (now - timedelta(hours=1)).isoformat()
        expires_at = (now + timedelta(hours=1)).isoformat()
        subject = {
            "schema_version": "2.0",
            "corpus_id": "governed-holdout",
            "revision": "revision-7",
            "training_corpus_sha256": "a" * 64,
            "holdout_labels_sha256": hashlib.sha256(
                canonical_bytes(labels)
            ).hexdigest(),
        }
        authorities: list[dict[str, object]] = []
        trusted: list[str] = []
        roles: dict[str, list[str]] = {}
        organizations: dict[str, str] = {}
        lifecycle: dict[str, dict[str, object]] = {}
        for index in range(2):
            private = Ed25519PrivateKey.generate()
            public_raw = private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            signer = hashlib.sha256(public_raw).hexdigest()
            key_path = self.root / f"effectiveness-authority-{index}.pem"
            key_path.write_bytes(
                private.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            statement = {
                "schema_version": "1.0",
                "purpose": "effectiveness-corpus",
                "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
                "signer_id": signer,
                "collector_id": f"independent-collector-{index}",
                "signed_at": signed_at,
                "expires_at": expires_at,
            }
            signature = private.sign(canonical_bytes(statement))
            signature_path = self.root / f"effectiveness-authority-{index}.sig"
            signature_path.write_bytes(signature)
            authorities.append(
                {
                    "schema_version": "1.0",
                    "signer_id": signer,
                    "collector_id": statement["collector_id"],
                    "signed_at": signed_at,
                    "expires_at": expires_at,
                    "public_key_file": key_path.name,
                    "public_key_sha256": hashlib.sha256(
                        key_path.read_bytes()
                    ).hexdigest(),
                    "signature_file": signature_path.name,
                    "signature_sha256": hashlib.sha256(signature).hexdigest(),
                }
            )
            trusted.append(signer)
            roles[signer] = ["effectiveness-corpus"]
            organizations[signer] = f"organization-{index}"
            lifecycle[signer] = {
                "not_before": (now - timedelta(days=1)).isoformat(),
                "not_after": (now + timedelta(days=1)).isoformat(),
                "revoked_at": None,
            }
        document = {
            **subject,
            "minimum_authority_signatures": 2,
            "authorities": authorities,
            "labels": labels,
        }
        corpus = self.root / "governed-corpus.json"
        corpus.write_text(json.dumps(document), encoding="utf-8")
        trusted_time = self.root / "effectiveness-time.json"
        trusted_time.write_text(
            json.dumps({"schema_version": "1.0", "trusted_time": {}}),
            encoding="utf-8",
        )
        trusted_time_digest = hashlib.sha256(trusted_time.read_bytes()).hexdigest()
        environment = {
            "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": ",".join(trusted),
            "PYSEC_TRUSTED_AUTHORITY_ROLES": json.dumps(roles),
            "PYSEC_AUTHORITY_ORGANIZATIONS": json.dumps(organizations),
            "PYSEC_AUTHORITY_KEY_LIFECYCLE": json.dumps(lifecycle),
        }
        with (
            patch.dict(os.environ, environment),
            patch(
                "py_security_suite.effectiveness_corpus.verify_report",
                return_value={
                    "scan_id": "scan-fixture",
                    "outcome": "pass",
                    "checksums_sha256": "a" * 64,
                    "file_count": 10,
                },
            ),
            patch(
                "py_security_suite.effectiveness_corpus.verify_rfc3161",
                return_value={
                    "trusted_time_sha256": "b" * 64,
                    "trusted_time_observed_at": now.isoformat(),
                    "trusted_time_receipt_sha256": "c" * 64,
                    "trusted_time_signer_sha256": "d" * 64,
                },
            ),
            patch(
                "py_security_suite.effectiveness_corpus._consume_remote_effectiveness_replay",
                return_value={
                    "mode": "remote-signed-checkpoint",
                    "replay_key": "e" * 64,
                    "request_sha256": "f" * 64,
                    "service_key_sha256": "1" * 64,
                    "sequence": 1,
                    "holdout_uses": 1,
                    "checkpoint_size": 1,
                    "checkpoint_root_sha256": "2" * 64,
                    "signature_base64": "AA==",
                },
            ) as replay_service,
        ):
            result = evaluate_report_corpus(
                self.report,
                corpus,
                corpus_sha256=hashlib.sha256(corpus.read_bytes()).hexdigest(),
                trusted_time=trusted_time,
                trusted_time_sha256=trusted_time_digest,
                replay_service_url="https://replay.example.invalid/consume",
            )
        self.assertTrue(result["corpus"]["authority"]["validated"])
        self.assertTrue(result["time_authority"]["validated"])
        self.assertTrue(result["replay_protected"])
        replay_service.assert_called_once()
        self.assertEqual(
            result["corpus"]["authority"]["authority_organizations"],
            ["organization-0", "organization-1"],
        )
        self.assertEqual(
            result["corpus"]["diversity"],
            {
                "cwe": 5,
                "language": 2,
                "parser_variant": 2,
                "boundary_type": 3,
                "severity": 3,
                "mutation_operator": 2,
            },
        )

    def test_rejects_duplicate_json_properties(self) -> None:
        corpus = self.root / "ambiguous-corpus.json"
        corpus.write_text(
            '{"schema_version":"1.0","schema_version":"2.0","labels":[]}',
            encoding="utf-8",
        )
        with (
            patch(
                "py_security_suite.effectiveness_corpus.verify_report",
                return_value={
                    "scan_id": "scan-fixture",
                    "outcome": "pass",
                    "checksums_sha256": "a" * 64,
                    "file_count": 10,
                },
            ),
            self.assertRaisesRegex(ValueError, "duplicate property"),
        ):
            evaluate_report_corpus(
                self.report,
                corpus,
                corpus_sha256=hashlib.sha256(corpus.read_bytes()).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
