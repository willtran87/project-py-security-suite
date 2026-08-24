from __future__ import annotations

import pytest
import json
import hashlib
import base64
import os
import sys
from datetime import UTC, datetime
from unittest.mock import patch
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.adapters.portfolio import PipdeptreeAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.deployment_receipt import verify_deployment_receipt
from py_security_suite.inventory import allowed_signer_fingerprints
from py_security_suite.strict_json import canonical_bytes
from tests.deployment_authority import (
    authority_environment,
    pinned_command_sandbox_environment,
)


@pytest.mark.parametrize(
    "name", ["checkov-iac.json", "git-sizer.json", "pipdeptree-summary.json"]
)
def test_external_artifacts_require_specific_normalized_contracts(name: str) -> None:
    with pytest.raises(ValueError, match="violates"):
        validate_governed_artifacts({name: {}})


def test_malformed_governed_artifact_blocks_publication_validation() -> None:
    with pytest.raises(ValueError, match="semantic-language-coverage.json"):
        validate_governed_artifacts(
            {
                "semantic-language-coverage.json": {
                    "schema_version": "1.0",
                    "analysis": "source-bound-semantic-language-coverage",
                    "languages": [{"language": "typescript", "semantic": True}],
                    "polyglot_evidence_authenticated": True,
                    "uncovered_languages": [],
                    "limitations": ["test"],
                    "complete": True,
                }
            }
        )


def test_retained_git_provenance_reverifies_signers_and_manifest(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    allowed = b"".join(
        f"org-{index} ".encode()
        + key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        + b"\n"
        for index, key in enumerate(keys, start=1)
    )
    fingerprints = sorted(allowed_signer_fingerprints(allowed))
    manifest = {
        "schema_version": "1.0",
        "git_executable_sha256": "c" * 64,
        "allowed_signers_file_sha256": hashlib.sha256(allowed).hexdigest(),
        "allowed_signers_file_base64": base64.b64encode(allowed).decode(),
        "signer_policy": [
            {
                "fingerprint": fingerprint,
                "organization": f"org-{index}",
                "not_before": now.replace(year=now.year - 1).isoformat(),
                "not_after": now.replace(year=now.year + 1).isoformat(),
            }
            for index, fingerprint in enumerate(fingerprints, start=1)
        ],
        "signature_ledger": {
            "commits": [
                {
                    "commit": marker * 64,
                    "fingerprint": fingerprint,
                    "committed_at": now.isoformat(),
                    "organization": f"org-{index}",
                }
                for index, (marker, fingerprint) in enumerate(
                    zip(("a", "b"), fingerprints, strict=True), start=1
                )
            ],
            "tags": [],
        },
        "repository_state": {
            "refs": {"refs/heads/main": "a" * 64},
            "object_format": "sha256",
            "head": "a" * 64,
            "symbolic_head": "refs/heads/main",
            "replace_refs": "",
            "security_config_sha256": "d" * 64,
            "alternates_sha256": "",
            "reachable_objects_sha256": "e" * 64,
        },
    }
    environment = authority_environment(
        tmp_path,
        manifest,
        purpose="git-ref-manifest",
        prefix="PYSEC_GIT_REF_MANIFEST_AUTHORITY",
    )
    verification_time = datetime.now(UTC)
    with (
        patch.dict(os.environ, environment),
        patch(
            "py_security_suite.deployment_receipt._scan_observed_at",
            return_value=verification_time,
        ),
    ):
        receipt = verify_deployment_receipt(
            manifest,
            purpose="git-ref-manifest",
            environment_prefix="PYSEC_GIT_REF_MANIFEST_AUTHORITY",
        )
    inventory = {
        "schema_version": "1.0",
        "scope": "empty retained source fixture",
        "source_sha256": hashlib.sha256(b"").hexdigest(),
        "total_files": 0,
        "total_bytes": 0,
        "files": [],
        "git_provenance": [
            {
                "path": ".",
                "schema_version": "1.0",
                "manifest": manifest,
                "authority_receipt": receipt,
            }
        ],
    }
    validate_governed_artifacts({"source-inventory.json": inventory})
    manifest["allowed_signers_file_base64"] = base64.b64encode(
        allowed + b"#tamper\n"
    ).decode()
    with pytest.raises(ValueError, match="allowed-signers content is detached"):
        validate_governed_artifacts({"source-inventory.json": inventory})


def test_unregistered_artifact_blocks_publication_validation() -> None:
    with pytest.raises(ValueError, match="no registered publication schema"):
        validate_governed_artifacts({"surprise.json": {"schema_version": "1.0"}})


def test_registered_artifact_name_does_not_bypass_its_specific_contract() -> None:
    with pytest.raises(ValueError, match="artifact-sbom.cdx.json"):
        validate_governed_artifacts(
            {
                "artifact-sbom.cdx.json": {
                    "bomFormat": "not-cyclonedx",
                    "specVersion": "1.6",
                    "components": [],
                }
            }
        )
    with pytest.raises(ValueError, match="artifact-manifest.json"):
        validate_governed_artifacts(
            {
                "artifact-manifest.json": {
                    "schema_version": "1.0",
                    "algorithm": "sha256",
                    "artifacts": [
                        {"path": "../escape.whl", "sha256": "0" * 64, "size_bytes": 1}
                    ],
                }
            }
        )


def test_native_report_replay_payload_is_digest_and_normalization_bound() -> None:
    payload = json.dumps(
        {
            "total_packages": 1,
            "direct_dependencies": 1,
            "transitive_dependencies": 0,
            "max_depth": 1,
            "missing_dependencies": 0,
            "cyclic_dependencies": 0,
            "conflicting_dependencies": {"packages": 0, "edges": 0},
        }
    )
    artifact = PipdeptreeAdapter(ToolConfig(), 4096).derived_artifacts(
        payload, Path(".")
    )["pipdeptree-summary.json"]
    validate_governed_artifacts({"pipdeptree-summary.json": artifact})
    artifact["native_report_redacted_utf8"] += " "
    with pytest.raises(ValueError, match="redacted projection commitment"):
        validate_governed_artifacts({"pipdeptree-summary.json": artifact})


def test_native_report_secrets_use_encrypted_content_addressed_storage(
    tmp_path: Path,
) -> None:
    raw_store = tmp_path / "raw"
    raw_store.mkdir()
    key_bytes = b"k" * 32
    wrapped_key = b"w" * 48
    challenge = "c" * 64
    sandbox_environment, command_context, sandbox_asset = (
        pinned_command_sandbox_environment(
            tmp_path,
            prefix="PYSEC_RAW_EVIDENCE_KMS",
            allowed_endpoints=["https://kms.example.invalid:443"],
        )
    )
    request = {
        "schema_version": "1.0",
        "operation": "generate-data-key",
        "store_identity": hashlib.sha256(str(raw_store.resolve()).encode()).hexdigest(),
        "object_plaintext_sha256": hashlib.sha256(
            json.dumps(
                {
                    "total_packages": 0,
                    "direct_dependencies": 0,
                    "transitive_dependencies": 0,
                    "max_depth": 0,
                    "missing_dependencies": 0,
                    "cyclic_dependencies": 0,
                    "conflicting_dependencies": {"packages": 0, "edges": 0},
                    "password": "do-not-publish",
                }
            ).encode()
        ).hexdigest(),
        "challenge_sha256": challenge,
        "command_context": command_context,
    }
    kms_script = tmp_path / "kms.py"
    custody = tmp_path / "custody.json"
    transport_transcript = {
        "endpoint": "https://kms.example.invalid:443",
        "peer_identity_sha256": command_context["mtls_identity_sha256"],
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "session_id": "session-12345678",
    }
    custody.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "provider": "test-kms",
                "key_id": "evidence-key",
                "key_version": "1",
                "store_identity": hashlib.sha256(
                    str(raw_store.resolve()).encode()
                ).hexdigest(),
                "retention_days": 30,
                "plaintext_data_key_sha256": hashlib.sha256(key_bytes).hexdigest(),
                "key_origin": "kms-generated-data-key",
                "wrapping_key_non_exportable": True,
                "hardware_backed": True,
                "wrapped_key_sha256": hashlib.sha256(wrapped_key).hexdigest(),
                "encryption_operation_id": "kms-operation-1",
                "request_sha256": hashlib.sha256(canonical_bytes(request)).hexdigest(),
                "object_plaintext_sha256": request["object_plaintext_sha256"],
                "challenge_sha256": challenge,
                "sandbox_identity_sha256": command_context["sandbox_identity_sha256"],
                "allowed_endpoints_sha256": hashlib.sha256(
                    canonical_bytes(command_context["allowed_endpoints"])
                ).hexdigest(),
                "mtls_peer_identity_sha256": command_context["mtls_identity_sha256"],
                "transport_transcript": transport_transcript,
                "transport_transcript_sha256": hashlib.sha256(
                    canonical_bytes(transport_transcript)
                ).hexdigest(),
                "command_context": command_context,
            }
        ),
        encoding="utf-8",
    )
    custody_authority = authority_environment(
        tmp_path,
        json.loads(custody.read_text(encoding="utf-8")),
        purpose="raw-evidence-custody",
        prefix="PYSEC_RAW_EVIDENCE_CUSTODY_AUTHORITY",
        challenge=challenge,
    )
    with (
        patch.dict(os.environ, custody_authority),
        patch(
            "py_security_suite.deployment_receipt._scan_observed_at",
            return_value=datetime.now(UTC),
        ),
        patch(
            "py_security_suite.trusted_observation.scan_observed_at",
            return_value=datetime.now(UTC),
        ),
    ):
        portable_custody = verify_deployment_receipt(
            json.loads(custody.read_text(encoding="utf-8")),
            purpose="raw-evidence-custody",
            environment_prefix="PYSEC_RAW_EVIDENCE_CUSTODY_AUTHORITY",
        )
    kms_response = {
        "schema_version": "1.0",
        "plaintext_data_key_base64": base64.b64encode(key_bytes).decode(),
        "wrapped_data_key_base64": base64.b64encode(wrapped_key).decode(),
        "encryption_operation_id": "kms-operation-1",
        "custody_receipt": json.loads(custody.read_text(encoding="utf-8")),
        "custody_authority_receipt": portable_custody,
    }
    kms_script.write_text(
        f"print({json.dumps(json.dumps(kms_response))})\n", encoding="utf-8"
    )
    payload = json.dumps(
        {
            "total_packages": 0,
            "direct_dependencies": 0,
            "transitive_dependencies": 0,
            "max_depth": 0,
            "missing_dependencies": 0,
            "cyclic_dependencies": 0,
            "conflicting_dependencies": {"packages": 0, "edges": 0},
            "password": "do-not-publish",
        }
    )
    executable = Path(sys.executable).resolve()
    kms_environment = {
        "PYSEC_RAW_EVIDENCE_KMS_COMMAND_JSON": json.dumps(
            [str(executable), "-I", str(kms_script)]
        ),
        "PYSEC_RAW_EVIDENCE_KMS_EXECUTABLE_SHA256": hashlib.sha256(
            executable.read_bytes()
        ).hexdigest(),
        "PYSEC_RAW_EVIDENCE_KMS_ASSETS_JSON": json.dumps(
            [
                {
                    "path": str(kms_script),
                    "sha256": hashlib.sha256(kms_script.read_bytes()).hexdigest(),
                },
                sandbox_asset,
            ]
        ),
        **sandbox_environment,
    }
    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_RAW_EVIDENCE_DIRECTORY": str(raw_store),
                **kms_environment,
                "PYSEC_SCAN_TIME_CHALLENGE_SHA256": portable_custody["statement"][
                    "challenge_sha256"
                ],
                "PYSEC_RAW_EVIDENCE_CUSTODY_AUTHORITY_KEY_SHA256": portable_custody[
                    "statement"
                ]["signer_key_sha256"],
            },
        ),
        patch(
            "py_security_suite.deployment_receipt._scan_observed_at",
            return_value=datetime.now(UTC),
        ),
        patch(
            "py_security_suite.trusted_observation.scan_observed_at",
            return_value=datetime.now(UTC),
        ),
    ):
        artifact = PipdeptreeAdapter(ToolConfig(), 4096).derived_artifacts(
            payload, tmp_path
        )["pipdeptree-summary.json"]
    assert artifact["native_report_replayable"] is True
    assert "do-not-publish" not in artifact["native_report_redacted_utf8"]
    object_path = raw_store / artifact["native_report_storage"]["object_id"]
    assert object_path.is_file()
    validate_governed_artifacts({"pipdeptree-summary.json": artifact})
    object_path.write_bytes(b"corrupt")
    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_RAW_EVIDENCE_DIRECTORY": str(raw_store),
                **kms_environment,
                "PYSEC_SCAN_TIME_CHALLENGE_SHA256": portable_custody["statement"][
                    "challenge_sha256"
                ],
                "PYSEC_RAW_EVIDENCE_CUSTODY_AUTHORITY_KEY_SHA256": portable_custody[
                    "statement"
                ]["signer_key_sha256"],
            },
        ),
        patch(
            "py_security_suite.deployment_receipt._scan_observed_at",
            return_value=datetime.now(UTC),
        ),
        patch(
            "py_security_suite.trusted_observation.scan_observed_at",
            return_value=datetime.now(UTC),
        ),
        pytest.raises(ValueError, match="truncated"),
    ):
        PipdeptreeAdapter(ToolConfig(), 4096).derived_artifacts(payload, tmp_path)
