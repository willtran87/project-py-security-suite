from __future__ import annotations

import json
import base64
import hashlib
import os
import tempfile
import unittest
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.models import ToolRun, ToolStatus
from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.requirements_coverage import (
    _policy_catalogs,
    _replay_assertion,
    security_requirements_coverage_artifact,
)
from py_security_suite.strict_json import canonical_bytes
from tests.deployment_authority import authority_environment, operation_receipt


class SecurityRequirementsCoverageTests(unittest.TestCase):
    def test_replay_assertion_compares_numeric_threshold(self) -> None:
        artifact = {"coverage": 95}
        assertion = {
            "artifact": "coverage.json",
            "sha256": hashlib.sha256(canonical_bytes(artifact)).hexdigest(),
            "pointer": "/coverage",
            "operator": "gte",
            "expected": 90,
        }

        self.assertTrue(_replay_assertion(assertion, {"coverage.json": artifact}))

    def test_schema_1_1_catalog_registry_accepts_pinned_aisvs_and_future_catalogs(
        self,
    ) -> None:
        standards = (
            "OWASP-ASVS",
            "OWASP-MASVS",
            "OWASP-TCASVS",
            "OWASP-AISVS",
            "ACME-VERIFICATION-STANDARD",
        )
        catalogs = [
            {
                "standard": standard,
                "version": "1.0",
                "source": f"https://example.invalid/{standard}",
                "source_revision": f"{index:x}" * 40,
                "catalog_sha256": f"{index:x}" * 64,
                "requirements_in_catalog": 1,
            }
            for index, standard in enumerate(standards, start=1)
        ]
        self.assertEqual(
            len(_policy_catalogs(catalogs, schema_version="1.1")), len(catalogs)
        )
        with self.assertRaisesRegex(ValueError, "catalogs are invalid"):
            _policy_catalogs(catalogs, schema_version="1.0")

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
        self.assertIn("9.3.1", identifiers)
        self.assertEqual(artifact["schema_version"], "1.1")
        self.assertFalse(artifact["applicability"]["ai_system"])
        self.assertEqual(
            next(
                item["version"]
                for item in artifact["catalogs"]
                if item["standard"] == "OWASP-TCASVS"
            ),
            "5.0.1",
        )
        self.assertTrue(
            any(item["standard"] == "OWASP-AISVS" for item in artifact["catalogs"])
        )
        self.assertTrue(any("not a claim" in item for item in artifact["limitations"]))
        schema = json.loads(
            files("py_security_suite")
            .joinpath("schemas", "security-requirements-coverage-1.1.schema.json")
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
        with patch.dict(
            os.environ,
            {
                "PYSEC_SCAN_TIME_CHALLENGE_SHA256": "c" * 64,
                "PYSEC_SCAN_TIME_CONTEXT_SHA256": "e" * 64,
            },
        ):
            validate_governed_artifacts(
                {"security-requirements-coverage.json": artifact}
            )

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
            argv = ["replay", "--fixture", "fixture.json"]
            environment_record = [
                {
                    "name": "PYTHONHASHSEED",
                    "value_commitment": hashlib.sha256(b"0").hexdigest(),
                    "classification": "public-commitment",
                    "commitment_algorithm": "sha256",
                    "commitment_key_sha256": "",
                    "nonce_sha256": "",
                }
            ]
            executable_bytes = b"deterministic-replay-executable"
            closure_manifest = [
                {
                    "path": "runtime/library.bin",
                    "sha256": hashlib.sha256(b"runtime-library").hexdigest(),
                    "content_base64": base64.b64encode(b"runtime-library").decode(),
                }
            ]
            sbom_bytes = canonical_bytes(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [
                        {
                            "type": "file",
                            "name": "runtime/library.bin",
                            "properties": [
                                {
                                    "name": "pysec:closure-path",
                                    "value": "runtime/library.bin",
                                }
                            ],
                            "hashes": [
                                {
                                    "alg": "SHA-256",
                                    "content": hashlib.sha256(
                                        b"runtime-library"
                                    ).hexdigest(),
                                }
                            ],
                        }
                    ],
                }
            )
            runtime_manifest = {
                "kind": "native",
                "executable_sha256": hashlib.sha256(executable_bytes).hexdigest(),
                "executable_base64": base64.b64encode(executable_bytes).decode(),
                "closure_sha256": hashlib.sha256(
                    canonical_bytes(closure_manifest)
                ).hexdigest(),
                "closure_manifest": closure_manifest,
                "image_digest": "",
                "image_manifest_base64": "",
                "sbom_sha256": hashlib.sha256(sbom_bytes).hexdigest(),
                "sbom_base64": base64.b64encode(sbom_bytes).decode(),
            }
            assets_manifest = [
                {
                    "name": "replay-policy",
                    "sha256": hashlib.sha256(b"strict-policy").hexdigest(),
                    "content_base64": base64.b64encode(b"strict-policy").decode(),
                }
            ]
            sandbox_policy = {
                "network": "deny",
                "filesystem": "read-only",
                "process": "confined",
                "credentials": "isolated",
            }
            fixture = {"passed": True}
            command_sha256 = runtime_manifest["executable_sha256"]
            argv_sha256 = hashlib.sha256(canonical_bytes(argv)).hexdigest()
            fixture_sha256 = hashlib.sha256(canonical_bytes(fixture)).hexdigest()
            procedure_artifacts: dict[str, object] = {}
            execution_assertion_fields: list[dict[str, object]] = []
            execution_private = Ed25519PrivateKey.generate()
            execution_public = execution_private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            execution_authority_sha256 = hashlib.sha256(execution_public).hexdigest()
            previous_execution_receipt_sha256 = ""
            for polarity in ("positive", "negative-control"):
                name = f"procedure-{polarity}.json"
                mutation_operator = (
                    "baseline"
                    if polarity == "positive"
                    else "negative-control-mutation"
                )
                mutation_manifest = {
                    "operator": mutation_operator,
                    "parent_fixture_sha256": fixture_sha256,
                    "mutated_fixture": (
                        fixture if polarity == "positive" else {"passed": False}
                    ),
                }
                mutation_sha256 = hashlib.sha256(
                    canonical_bytes(mutation_manifest)
                ).hexdigest()
                execution_subject = {
                    "schema_version": "1.0",
                    "procedure_id": "artifact-value-replay-v1",
                    "producer_sha256": "a" * 64,
                    "command_sha256": command_sha256,
                    "fixture_sha256": fixture_sha256,
                    "mutation_sha256": mutation_sha256,
                    "exit_code": 0,
                    "stdout_sha256": artifact_sha256,
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                    "result_artifact": "result.json",
                    "result_sha256": artifact_sha256,
                    "started_at": assessed_at.isoformat(),
                    "finished_at": assessed_at.isoformat(),
                    "argv_sha256": argv_sha256,
                    "environment_sha256": hashlib.sha256(
                        canonical_bytes(environment_record)
                    ).hexdigest(),
                    "runtime_sha256": hashlib.sha256(
                        canonical_bytes(runtime_manifest)
                    ).hexdigest(),
                    "assets_sha256": hashlib.sha256(
                        canonical_bytes(assets_manifest)
                    ).hexdigest(),
                    "sandbox_identity_sha256": hashlib.sha256(
                        canonical_bytes(sandbox_policy)
                    ).hexdigest(),
                    "mutation_operator": mutation_operator,
                    "mutation_parent_sha256": fixture_sha256,
                    "argv": argv,
                    "environment": environment_record,
                    "runtime_manifest": runtime_manifest,
                    "assets_manifest": assets_manifest,
                    "sandbox_policy": sandbox_policy,
                    "fixture": fixture,
                    "mutation_manifest": mutation_manifest,
                }
                execution_receipt, _ = operation_receipt(
                    execution_subject,
                    purpose="requirements-procedure-execution",
                    operation_id=f"procedure-{polarity}",
                    private_key=execution_private,
                    previous_operation_sha256=previous_execution_receipt_sha256,
                )
                previous_execution_receipt_sha256 = hashlib.sha256(
                    canonical_bytes(execution_receipt)
                ).hexdigest()
                execution = {
                    **execution_subject,
                    "execution_authority_receipt": execution_receipt,
                }
                procedure_artifacts[name] = execution
                execution_assertion_fields.append(
                    {
                        "execution_artifact": name,
                        "execution_sha256": hashlib.sha256(
                            canonical_bytes(execution)
                        ).hexdigest(),
                        "fixture_sha256": fixture_sha256,
                        "mutation_sha256": mutation_sha256,
                        "command_sha256": command_sha256,
                        "exit_code": 0,
                    }
                )
            assessments = [
                {
                    "standard": standard,
                    "version": "1.0.0",
                    "requirement": f"REQ-{index}",
                    "result": "pass" if index == 0 else "not-applicable",
                    "method": "automated replay",
                    "procedure_id": "artifact-value-replay-v1",
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
                                "polarity": "positive",
                                "observed_at": assessed_at.isoformat(),
                                "producer_sha256": "a" * 64,
                                **execution_assertion_fields[0],
                            },
                            {
                                "artifact": "result.json",
                                "sha256": artifact_sha256,
                                "pointer": "/passed",
                                "operator": "not-equals",
                                "expected": False,
                                "polarity": "negative-control",
                                "observed_at": assessed_at.isoformat(),
                                "producer_sha256": "a" * 64,
                                **execution_assertion_fields[1],
                            },
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
                                "allowed_execution_artifacts": [
                                    "procedure-negative-control.json",
                                    "procedure-positive.json",
                                ],
                                "allowed_methods": ["automated replay"],
                                "allowed_operators": ["equals", "not-equals"],
                                "allowed_producer_sha256": ["a" * 64],
                                "allowed_execution_authority_key_sha256": [
                                    execution_authority_sha256
                                ],
                                "minimum_assertions": 2 if index == 0 else 0,
                                "minimum_negative_assertions": 1 if index == 0 else 0,
                                "maximum_evidence_age_hours": 24,
                                "procedure_id": "artifact-value-replay-v1",
                            }
                            for index, standard in enumerate(standards)
                        ],
                    }
                ),
                encoding="utf-8",
            )
            evidence_policy_authority = authority_environment(
                root,
                json.loads(evidence_policy_path.read_text(encoding="utf-8")),
                purpose="requirements-evidence-policy",
                prefix="PYSEC_REQUIREMENTS_EVIDENCE_POLICY_AUTHORITY",
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
                **evidence_policy_authority,
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
                    [],
                    {"result.json": artifact_value, **procedure_artifacts},
                )
        self.assertEqual(verifier.call_count, 2)
        self.assertTrue(artifact["complete"])
        self.assertEqual(artifact["requirements"][0]["status"], "passed")
        with patch.dict(
            os.environ,
            {
                "PYSEC_SCAN_TIME_CHALLENGE_SHA256": "c" * 64,
                "PYSEC_SCAN_TIME_CONTEXT_SHA256": "e" * 64,
            },
        ):
            validate_governed_artifacts(
                {"security-requirements-coverage.json": artifact}
            )
