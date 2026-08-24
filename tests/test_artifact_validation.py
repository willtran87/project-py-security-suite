from __future__ import annotations

import pytest
import json
import hashlib
from datetime import UTC, datetime
from unittest.mock import patch
from pathlib import Path

from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.adapters.portfolio import PipdeptreeAdapter
from py_security_suite.config import ToolConfig
from tests.deployment_authority import authority_environment


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
    key = tmp_path / "raw.key"
    key.write_bytes(b"k" * 32)
    custody = tmp_path / "custody.json"
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
                "plaintext_data_key_sha256": hashlib.sha256(
                    key.read_bytes()
                ).hexdigest(),
                "key_origin": "kms-generated-data-key",
                "wrapping_key_non_exportable": True,
                "hardware_backed": True,
                "wrapped_key_sha256": "b" * 64,
                "encryption_operation_id": "kms-operation-1",
            }
        ),
        encoding="utf-8",
    )
    custody_authority = authority_environment(
        tmp_path,
        json.loads(custody.read_text(encoding="utf-8")),
        purpose="raw-evidence-custody",
        prefix="PYSEC_RAW_EVIDENCE_CUSTODY_AUTHORITY",
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
    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_RAW_EVIDENCE_DIRECTORY": str(raw_store),
                "PYSEC_RAW_EVIDENCE_KEY_PATH": str(key),
                "PYSEC_RAW_EVIDENCE_KEY_SHA256": hashlib.sha256(
                    key.read_bytes()
                ).hexdigest(),
                "PYSEC_RAW_EVIDENCE_CUSTODY_RECEIPT_PATH": str(custody),
                "PYSEC_RAW_EVIDENCE_CUSTODY_RECEIPT_SHA256": hashlib.sha256(
                    custody.read_bytes()
                ).hexdigest(),
                **custody_authority,
            },
        ),
        patch(
            "py_security_suite.deployment_receipt._scan_observed_at",
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
                "PYSEC_RAW_EVIDENCE_KEY_PATH": str(key),
                "PYSEC_RAW_EVIDENCE_KEY_SHA256": hashlib.sha256(
                    key.read_bytes()
                ).hexdigest(),
                "PYSEC_RAW_EVIDENCE_CUSTODY_RECEIPT_PATH": str(custody),
                "PYSEC_RAW_EVIDENCE_CUSTODY_RECEIPT_SHA256": hashlib.sha256(
                    custody.read_bytes()
                ).hexdigest(),
                **custody_authority,
            },
        ),
        patch(
            "py_security_suite.deployment_receipt._scan_observed_at",
            return_value=datetime.now(UTC),
        ),
        pytest.raises(ValueError, match="truncated"),
    ):
        PipdeptreeAdapter(ToolConfig(), 4096).derived_artifacts(payload, tmp_path)
