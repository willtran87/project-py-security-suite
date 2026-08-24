from __future__ import annotations

import json
import hashlib
import os
import tempfile
import unittest
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from py_security_suite.models import ToolRun, ToolStatus
from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.requirements_coverage import (
    security_requirements_coverage_artifact,
)
from py_security_suite.strict_json import canonical_bytes


class SecurityRequirementsCoverageTests(unittest.TestCase):
    def test_exact_versioned_requirements_are_mapped_without_claiming_conformance(
        self,
    ) -> None:
        artifact = security_requirements_coverage_artifact(
            {
                "languages": {"python": 1, "kotlin": 1},
                "language_file_sets": {},
                "edges": [
                    {
                        "kind": "network-endpoint",
                        "source": "app.py",
                        "target": "https://example.invalid",
                    }
                ],
            },
            [
                ToolRun(
                    tool="semgrep",
                    status=ToolStatus.COMPLETED,
                    command=["semgrep"],
                    duration_seconds=1.0,
                )
            ],
            {
                "semantic-language-coverage.json": {},
                "dependency-surface.json": {},
            },
        )
        identifiers = {item["requirement"] for item in artifact["requirements"]}
        self.assertIn("v5.0.0-1.2.5", identifiers)
        self.assertIn("MASVS-CODE-4", identifiers)
        self.assertTrue(any("not a claim" in item for item in artifact["limitations"]))
        schema = json.loads(
            files("py_security_suite")
            .joinpath("schemas", "security-requirements-coverage-1.0.schema.json")
            .read_text("utf-8")
        )
        Draft202012Validator(schema).validate(artifact)
        artifact["complete"] = not artifact["complete"]
        with self.assertRaisesRegex(ValueError, "crosswalk digest"):
            validate_governed_artifacts(
                {"security-requirements-coverage.json": artifact}
            )

    def test_signed_requirement_level_policy_can_establish_full_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements-policy.json"
            catalogs = [
                {
                    "standard": standard,
                    "version": "1.0.0",
                    "source": f"https://example.invalid/{standard}",
                    "source_revision": str(index) * 40,
                    "catalog_sha256": str(index) * 64,
                    "requirements_in_catalog": 1,
                }
                for index, standard in enumerate(
                    ("OWASP-ASVS", "OWASP-MASVS", "OWASP-TCASVS"), start=1
                )
            ]
            policy = {
                "schema_version": "1.0",
                "applicability": {
                    "web_or_api": True,
                    "mobile": False,
                    "thick_client": False,
                },
                "catalogs": catalogs,
                "requirements": [
                    {
                        "standard": item["standard"],
                        "version": item["version"],
                        "requirement": f"REQ-{index}",
                        "applicable": index == 0,
                        "verification_scope": "approved requirement-level assessment",
                        "evidence": ["semgrep"] if index == 0 else [],
                    }
                    for index, item in enumerate(catalogs)
                ],
                "minimum_authority_signatures": 2,
                "authorities": [{"id": "a"}, {"id": "b"}],
            }
            path.write_text(json.dumps(policy), encoding="utf-8")
            environment = {
                "PYSEC_REQUIREMENTS_POLICY_PATH": str(path),
                "PYSEC_REQUIREMENTS_POLICY_SHA256": hashlib.sha256(
                    path.read_bytes()
                ).hexdigest(),
            }
            with (
                patch.dict(os.environ, environment),
                patch(
                    "py_security_suite.trusted_observation.scan_observed_at",
                    return_value=datetime.now(UTC),
                ),
                patch(
                    "py_security_suite.requirements_coverage.verify_governance_quorum"
                ) as verifier,
            ):
                artifact = security_requirements_coverage_artifact(
                    {"languages": {}, "edges": []},
                    [
                        ToolRun(
                            tool="semgrep",
                            status=ToolStatus.COMPLETED,
                            command=["semgrep"],
                            duration_seconds=1.0,
                        )
                    ],
                    {},
                )
        verifier.assert_called_once()
        self.assertTrue(artifact["full_catalog_coverage"])
        self.assertFalse(artifact["complete"])
        validate_governed_artifacts({"security-requirements-coverage.json": artifact})

    def test_pinned_catalogs_and_replayed_assertions_establish_assessed_coverage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "requirements-policy.json"
            standards = ("OWASP-ASVS", "OWASP-MASVS", "OWASP-TCASVS")
            catalogs = [
                {
                    "standard": standard,
                    "version": "1.0.0",
                    "source": f"https://example.invalid/{standard}",
                    "source_revision": str(index + 1) * 40,
                    "catalog_sha256": str(index + 1) * 64,
                    "requirements_in_catalog": 1,
                }
                for index, standard in enumerate(standards)
            ]
            requirements = [
                {
                    "standard": standard,
                    "version": "1.0.0",
                    "requirement": f"REQ-{index}",
                    "applicable": index == 0,
                    "verification_scope": "replayed requirement assertion",
                    "evidence": ["result.json"] if index == 0 else [],
                }
                for index, standard in enumerate(standards)
            ]
            policy = {
                "schema_version": "1.0",
                "applicability": {
                    "web_or_api": True,
                    "mobile": False,
                    "thick_client": False,
                },
                "catalogs": catalogs,
                "requirements": requirements,
                "minimum_authority_signatures": 2,
                "authorities": [{"id": "policy-a"}, {"id": "policy-b"}],
            }
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            pins: dict[str, str] = {}
            assessment_catalogs = []
            for index, standard in enumerate(standards):
                catalog_path = root / f"catalog-{index}.json"
                catalog_path.write_text(json.dumps([f"REQ-{index}"]), encoding="utf-8")
                digest = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
                pins[f"{standard}@1.0.0"] = digest
                assessment_catalogs.append(
                    {
                        "standard": standard,
                        "version": "1.0.0",
                        "source_revision": str(index + 1) * 40,
                        "requirements_file": catalog_path.name,
                        "requirements_file_sha256": digest,
                    }
                )
            artifact_value = {"passed": True}
            artifact_sha256 = hashlib.sha256(
                canonical_bytes(artifact_value)
            ).hexdigest()
            assessed_at = datetime.now(UTC)
            assessments = [
                {
                    "standard": standard,
                    "version": "1.0.0",
                    "requirement": f"REQ-{index}",
                    "result": "pass" if index == 0 else "not-applicable",
                    "method": "automated replay",
                    "assessor": "security-assessor",
                    "assessed_at": assessed_at.isoformat(),
                    "assertions": (
                        [
                            {
                                "artifact": "result.json",
                                "sha256": artifact_sha256,
                                "pointer": "/passed",
                                "operator": "equals",
                                "expected": True,
                            }
                        ]
                        if index == 0
                        else []
                    ),
                }
                for index, standard in enumerate(standards)
            ]
            assessment_path = root / "requirements-assessment.json"
            assessment_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "catalogs": assessment_catalogs,
                        "assessments": assessments,
                        "minimum_authority_signatures": 2,
                        "authorities": [
                            {"id": "assessment-a"},
                            {"id": "assessment-b"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            evidence_policy_path = root / "requirements-evidence-policy.json"
            evidence_policy_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "requirements": [
                            {
                                "standard": standard,
                                "version": "1.0.0",
                                "requirement": f"REQ-{index}",
                                "allowed_artifacts": ["result.json"],
                                "allowed_methods": ["automated replay"],
                                "allowed_operators": ["equals"],
                                "minimum_assertions": 1 if index == 0 else 0,
                            }
                            for index, standard in enumerate(standards)
                        ],
                    }
                ),
                encoding="utf-8",
            )
            environment = {
                "PYSEC_REQUIREMENTS_POLICY_PATH": str(policy_path),
                "PYSEC_REQUIREMENTS_POLICY_SHA256": hashlib.sha256(
                    policy_path.read_bytes()
                ).hexdigest(),
                "PYSEC_REQUIREMENTS_ASSESSMENT_PATH": str(assessment_path),
                "PYSEC_REQUIREMENTS_ASSESSMENT_SHA256": hashlib.sha256(
                    assessment_path.read_bytes()
                ).hexdigest(),
                "PYSEC_REQUIREMENTS_CATALOG_SHA256": json.dumps(pins),
                "PYSEC_REQUIREMENTS_EVIDENCE_POLICY_PATH": str(evidence_policy_path),
                "PYSEC_REQUIREMENTS_EVIDENCE_POLICY_SHA256": hashlib.sha256(
                    evidence_policy_path.read_bytes()
                ).hexdigest(),
            }
            with (
                patch.dict(os.environ, environment),
                patch(
                    "py_security_suite.trusted_observation.scan_observed_at",
                    return_value=assessed_at,
                ),
                patch(
                    "py_security_suite.requirements_coverage.verify_governance_quorum"
                ) as verifier,
            ):
                artifact = security_requirements_coverage_artifact(
                    {"languages": {}, "edges": []}, [], {"result.json": artifact_value}
                )
        self.assertEqual(verifier.call_count, 2)
        self.assertTrue(artifact["complete"])
        self.assertEqual(artifact["requirements"][0]["status"], "passed")
        validate_governed_artifacts({"security-requirements-coverage.json": artifact})
