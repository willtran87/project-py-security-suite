from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import (  # pylint: disable=import-error
    Draft202012Validator,
    ValidationError,
)

from py_security_suite.effectiveness_corpus import evaluate_report_corpus
from py_security_suite.report_inspection import read_bundled_schema


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
            ({"schema_version": "2.0", "labels": []}, "schema_version"),
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


if __name__ == "__main__":
    unittest.main()
