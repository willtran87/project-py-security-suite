from __future__ import annotations

import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.evidence_draft import build_governance_evidence_draft


class GovernanceEvidenceDraftTests(unittest.TestCase):
    @patch("py_security_suite.evidence_draft.verify_report")
    def test_draft_binds_observed_scanners_context_and_artifacts(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_json(
                report / "scan-manifest.json",
                {
                    "target": "project",
                    "network_policy": "deny",
                    "inventory": {"source_sha256": "a" * 64},
                    "tools": [
                        {
                            "tool": "bandit",
                            "version": "1.9.0",
                            "applicable": True,
                            "executable_sha256": "b" * 64,
                            "executable_organization_approved": False,
                            "executable_unchanged": True,
                        }
                    ],
                },
            )
            _write_json(
                report / "risk-intelligence.json",
                {"snapshots": {"kev": {"sha256": "c" * 64}}},
            )
            _write_json(
                report / "findings.json",
                {
                    "source_sha256": "a" * 64,
                    "findings": [
                        {
                            "finding_id": "PYSEC-SIGN",
                            "blocking": True,
                            "classifications": ["COSIGN-BUNDLE-MISSING"],
                            "evidence": {
                                "artifact_path": "dist/project.whl",
                                "artifact_sha256": "d" * 64,
                            },
                        }
                    ],
                },
            )
            verify_report_mock.return_value = {
                "scan_id": "scan-1",
                "checksums_sha256": "e" * 64,
            }

            result = build_governance_evidence_draft(report)

        self.assertFalse(result["authoritative"])
        self.assertEqual(result["scanner_trust_candidates"][0]["tool"], "bandit")
        self.assertEqual(result["scanner_digest_groups"][0]["entrypoints"], 1)
        self.assertEqual(result["scanner_digest_groups"][0]["tools"], ["bandit"])
        self.assertEqual(result["intelligence_candidates"][0]["kind"], "kev")
        self.assertEqual(result["artifact_signing_candidates"][0]["sha256"], "d" * 64)
        schema = json.loads(
            files("py_security_suite")
            .joinpath("schemas", "governance-evidence-draft.schema.json")
            .read_text("utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result)

    @patch("py_security_suite.evidence_draft.verify_report")
    def test_draft_rejects_malformed_scanner_and_finding_collections(
        self, verify_report_mock
    ) -> None:
        verify_report_mock.return_value = {
            "scan_id": "scan-1",
            "checksums_sha256": "e" * 64,
        }
        cases: tuple[tuple[str, dict[str, object], str], ...] = (
            ("scan-manifest.json", {"tools": {}}, "tools must be an array"),
            ("findings.json", {"findings": {}}, "findings must be an array"),
        )
        for filename, document, message in cases:
            with (
                self.subTest(filename=filename),
                tempfile.TemporaryDirectory() as directory,
            ):
                report = Path(directory)
                _write_json(
                    report / "scan-manifest.json",
                    {"tools": [], "inventory": {"source_sha256": "a" * 64}},
                )
                _write_json(report / "risk-intelligence.json", {})
                _write_json(report / "findings.json", {"findings": []})
                _write_json(report / filename, document)

                with self.assertRaisesRegex(TypeError, message):
                    build_governance_evidence_draft(report)

    @patch("py_security_suite.evidence_draft.verify_report")
    def test_draft_filters_non_candidates_without_promoting_them(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_json(
                report / "scan-manifest.json",
                {
                    "target": "project",
                    "tools": [None, {"tool": "skip", "applicable": False}],
                    "inventory": {"source_sha256": "a" * 64},
                },
            )
            _write_json(report / "risk-intelligence.json", {"snapshots": []})
            _write_json(
                report / "findings.json",
                {
                    "findings": [
                        None,
                        {"blocking": False},
                        {"blocking": True, "classifications": []},
                        {
                            "blocking": True,
                            "classifications": ["COSIGN-BUNDLE-MISSING"],
                            "evidence": [],
                        },
                    ]
                },
            )
            verify_report_mock.return_value = {
                "scan_id": "scan-1",
                "checksums_sha256": "e" * 64,
            }

            result = build_governance_evidence_draft(report)

        self.assertEqual(result["scanner_trust_candidates"], [])
        self.assertEqual(result["scanner_digest_groups"], [])
        self.assertEqual(result["intelligence_candidates"], [])
        self.assertEqual(result["artifact_signing_candidates"], [])


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
