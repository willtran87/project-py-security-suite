from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.bundle_qualification import (
    qualify_bundle,
    render_bundle_qualification,
    render_bundle_qualification_markdown,
)
from py_security_suite.config import load_config
from py_security_suite.report_inspection import read_bundled_schema


class BundleQualificationTests(unittest.TestCase):
    def test_qualification_joins_contract_readiness_and_portable_identity(self) -> None:
        conformance = _conformance("pass")
        readiness = _readiness(ready=True)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "py_security_suite.bundle_qualification.assess_adapter_conformance",
                return_value=conformance,
            ),
            patch(
                "py_security_suite.bundle_qualification.assess_readiness",
                return_value=readiness,
            ),
        ):
            document = qualify_bundle(
                target=Path(directory), config=load_config(profile_override="quick")
            )

        self.assertEqual(document["decision"]["disposition"], "qualify")
        self.assertFalse(document["decision"]["scanner_execution_performed"])
        self.assertEqual(document["tools"][0]["entrypoint"], "bandit.exe")
        self.assertNotIn("C:\\approved", json.dumps(document))
        self.assertEqual(document["summary"]["observed_digests"], 1)
        self.assertIn("Activation-free", document["scope"])
        self.assertIn("QUALIFY: bundle", render_bundle_qualification(document))
        markdown = render_bundle_qualification_markdown(document)
        self.assertIn("# Scanner bundle qualification", markdown)
        self.assertIn("Per-control identity and readiness", markdown)
        schema = json.loads(read_bundled_schema("bundle-qualification-1.1"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

        readiness["tools"][0]["executable"] = "/approved/bin/bandit"
        with (
            patch(
                "py_security_suite.bundle_qualification.assess_adapter_conformance",
                return_value=conformance,
            ),
            patch(
                "py_security_suite.bundle_qualification.assess_readiness",
                return_value=readiness,
            ),
        ):
            portable = qualify_bundle(
                target=Path("."), config=load_config(profile_override="quick")
            )
        self.assertEqual(portable["tools"][0]["entrypoint"], "bandit")
        self.assertNotIn("/approved", json.dumps(portable))

    def test_adapter_or_readiness_gap_blocks_with_actions(self) -> None:
        conformance = _conformance("fail")
        readiness = _readiness(ready=False)
        readiness["action_groups"] = [
            {
                "priority": "P0",
                "blocking": True,
                "category": "unavailable",
                "subjects": ["bandit"],
                "required_action": "Restore the approved executable.",
            }
        ]
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "py_security_suite.bundle_qualification.assess_adapter_conformance",
                return_value=conformance,
            ),
            patch(
                "py_security_suite.bundle_qualification.assess_readiness",
                return_value=readiness,
            ),
        ):
            document = qualify_bundle(
                target=Path(directory), config=load_config(profile_override="quick")
            )

        self.assertEqual(document["decision"]["disposition"], "block")
        self.assertEqual(len(document["actions"]), 2)
        self.assertEqual(document["actions"][0]["category"], "adapter_contract")
        self.assertIn("Actions:", render_bundle_qualification(document))
        self.assertIn("| P0 | BLOCK |", render_bundle_qualification_markdown(document))

    def test_digest_bound_behavioral_evidence_is_integrated_and_fail_closed(
        self,
    ) -> None:
        conformance = _conformance("pass")
        readiness = _readiness(ready=True)
        with tempfile.TemporaryDirectory() as directory:
            evaluation = Path(directory) / "effectiveness.json"
            evaluation.write_text(json.dumps(_effectiveness()), encoding="utf-8")
            digest = hashlib.sha256(evaluation.read_bytes()).hexdigest()
            report = Path(directory) / "report"
            report.mkdir()
            (report / "scan-manifest.json").write_text(
                json.dumps(
                    {
                        "tools": [
                            {
                                "tool": "bandit",
                                "status": "completed",
                                "applicable": True,
                                "version": "1.9.4",
                                "executable_sha256": "a" * 64,
                                "executable_unchanged": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch(
                    "py_security_suite.bundle_qualification.assess_adapter_conformance",
                    return_value=conformance,
                ),
                patch(
                    "py_security_suite.bundle_qualification.assess_readiness",
                    return_value=readiness,
                ),
                patch(
                    "py_security_suite.bundle_qualification.verify_report",
                    return_value={
                        "scan_id": "scan-fixture",
                        "checksums_sha256": "b" * 64,
                    },
                ),
            ):
                document = qualify_bundle(
                    target=Path(directory),
                    config=load_config(profile_override="quick"),
                    effectiveness_evaluation=evaluation,
                    effectiveness_report=report,
                    effectiveness_sha256=digest,
                    minimum_effectiveness_labels=2,
                    minimum_effectiveness_tools=1,
                    required_effectiveness_tools=("bandit",),
                )
                missing = qualify_bundle(
                    target=Path(directory),
                    config=load_config(profile_override="quick"),
                    effectiveness_evaluation=evaluation,
                    effectiveness_report=report,
                    effectiveness_sha256=digest,
                    required_effectiveness_tools=("semgrep",),
                )

        self.assertEqual(document["decision"]["behavioral_evidence"], "pass")
        self.assertEqual(document["decision"]["disposition"], "qualify")
        self.assertEqual(document["summary"]["effectiveness_labels"], 2)
        self.assertEqual(document["behavioral_evidence"]["tool_names"], ["bandit"])
        self.assertTrue(document["behavioral_evidence"]["tool_bindings"][0]["matched"])
        self.assertEqual(missing["decision"]["disposition"], "block")
        self.assertEqual(
            missing["behavioral_evidence"]["missing_required_tools"], ["semgrep"]
        )
        self.assertEqual(missing["actions"][0]["category"], "behavioral_qualification")

    def test_required_behavioral_evidence_cannot_be_silently_omitted(self) -> None:
        with (
            patch(
                "py_security_suite.bundle_qualification.assess_adapter_conformance",
                return_value=_conformance("pass"),
            ),
            patch(
                "py_security_suite.bundle_qualification.assess_readiness",
                return_value=_readiness(ready=True),
            ),
        ):
            document = qualify_bundle(
                target=Path("."),
                config=load_config(profile_override="quick"),
                minimum_effectiveness_labels=1,
            )
        self.assertEqual(document["decision"]["disposition"], "block")
        self.assertEqual(
            document["decision"]["behavioral_evidence"], "required_missing"
        )

    def test_behavioral_evidence_rejects_stale_identity_and_report_binding(
        self,
    ) -> None:
        conformance = _conformance("pass")
        readiness = _readiness(ready=True)
        readiness["tools"][0]["executable_sha256"] = "c" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evaluation = root / "effectiveness.json"
            evaluation.write_text(json.dumps(_effectiveness()), encoding="utf-8")
            digest = hashlib.sha256(evaluation.read_bytes()).hexdigest()
            report = root / "report"
            report.mkdir()
            (report / "scan-manifest.json").write_text(
                json.dumps(
                    {
                        "tools": [
                            {
                                "tool": "bandit",
                                "status": "completed",
                                "version": "1.9.4",
                                "executable_sha256": "a" * 64,
                                "executable_unchanged": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch(
                    "py_security_suite.bundle_qualification.assess_adapter_conformance",
                    return_value=conformance,
                ),
                patch(
                    "py_security_suite.bundle_qualification.assess_readiness",
                    return_value=readiness,
                ),
                patch(
                    "py_security_suite.bundle_qualification.verify_report",
                    return_value={
                        "scan_id": "scan-fixture",
                        "checksums_sha256": "b" * 64,
                    },
                ),
            ):
                stale = qualify_bundle(
                    target=root,
                    config=load_config(profile_override="quick"),
                    effectiveness_evaluation=evaluation,
                    effectiveness_report=report,
                    effectiveness_sha256=digest,
                )
                with self.assertRaisesRegex(ValueError, "approved SHA-256"):
                    qualify_bundle(
                        target=root,
                        config=load_config(profile_override="quick"),
                        effectiveness_evaluation=evaluation,
                        effectiveness_report=report,
                        effectiveness_sha256="0" * 64,
                    )

        self.assertEqual(stale["decision"]["disposition"], "block")
        self.assertEqual(
            stale["behavioral_evidence"]["identity_mismatches"], ["bandit"]
        )
        self.assertFalse(stale["behavioral_evidence"]["tool_bindings"][0]["matched"])

    def test_production_qualification_requires_representative_calibration(
        self,
    ) -> None:
        with (
            patch(
                "py_security_suite.bundle_qualification.assess_adapter_conformance",
                return_value=_conformance("pass"),
            ),
            patch(
                "py_security_suite.bundle_qualification.assess_readiness",
                return_value=_readiness(ready=True),
            ),
        ):
            document = qualify_bundle(
                target=Path("."),
                config=load_config(profile_override="production"),
            )

        evidence = document["behavioral_evidence"]
        self.assertEqual(evidence["minimum_labels"], 200)
        self.assertEqual(evidence["minimum_tools"], 3)
        self.assertEqual(evidence["required_tools"], ["bandit", "codeql", "semgrep"])
        self.assertEqual(document["decision"]["disposition"], "block")

    def test_effectiveness_limits_are_bounded(self) -> None:
        config = load_config(profile_override="quick")
        with self.assertRaisesRegex(ValueError, "labels must be between"):
            qualify_bundle(
                target=Path("."),
                config=config,
                minimum_effectiveness_labels=10_001,
            )
        with self.assertRaisesRegex(ValueError, "tools must be between"):
            qualify_bundle(
                target=Path("."),
                config=config,
                minimum_effectiveness_tools=-1,
            )


def _conformance(status: str) -> dict[str, object]:
    passed = status == "pass"
    return {
        "status": status,
        "summary": {"adapters": 1, "passed": int(passed), "checks": 5},
        "adapters": [
            {
                "adapter": "bandit",
                "status": status,
                "checks": [
                    {"check": "identity", "passed": passed},
                    {"check": "configuration", "passed": True},
                ],
            }
        ],
    }


def _readiness(*, ready: bool) -> dict[str, Any]:
    status = "ready" if ready else "unavailable"
    return {
        "target": "fixture",
        "profile": "quick",
        "ready": ready,
        "summary": {
            "selected": 1,
            "applicable": 1,
            "ready": int(ready),
            "required_applicable": 1,
            "required_ready": int(ready),
            "not_applicable": 0,
            "attention": int(not ready),
        },
        "action_groups": [],
        "context_errors": [],
        "tools": [
            {
                "tool": "bandit",
                "status": status,
                "category": status,
                "required": True,
                "executable": "C:\\approved\\bandit.exe" if ready else None,
                "executable_sha256": "a" * 64 if ready else None,
                "executable_integrity_verified": True if ready else None,
                "executable_organization_approved": False,
            }
        ],
    }


def _effectiveness() -> dict[str, object]:
    labels = [
        {
            "id": "positive",
            "expected": "finding",
            "match": {
                "tool": "bandit",
                "rule_id": "B101",
                "path": "src/example.py",
                "classification": "CWE-703",
            },
            "outcome": "true_positive",
            "matching_finding_ids": ["PYSEC-1"],
            "matching_findings_omitted": 0,
        },
        {
            "id": "negative",
            "expected": "clean",
            "match": {
                "tool": "bandit",
                "rule_id": "B101",
                "path": "src/clean.py",
                "classification": "",
            },
            "outcome": "true_negative",
            "matching_finding_ids": [],
            "matching_findings_omitted": 0,
        },
    ]
    return {
        "schema_version": "1.0",
        "verdict": "pass",
        "report": {
            "scan_id": "scan-fixture",
            "outcome": "pass",
            "checksums_sha256": "b" * 64,
            "files_verified": 10,
        },
        "corpus": {
            "id": "bundle-calibration",
            "revision": "1",
            "sha256": "a" * 64,
            "labels": 2,
        },
        "confusion_matrix": {
            "true_positive": 1,
            "true_negative": 1,
            "false_positive": 0,
            "false_negative": 0,
        },
        "metrics": {"precision": 1.0, "recall": 1.0, "specificity": 1.0, "f1": 1.0},
        "failures": [],
        "label_outcomes": labels,
    }


if __name__ == "__main__":
    unittest.main()
