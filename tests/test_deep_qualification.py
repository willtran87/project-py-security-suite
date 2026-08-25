from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from jsonschema import Draft202012Validator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from companion.deep_qualification import _consume_remote_replay, _validators, qualify
from companion.evidence_authority import verify_authority
from companion.provenance import compose_provenance
from companion.surface_inventory import _verify_history
from companion.tool_normalizers import _safe_sarif_message, _sarif_semantics
from companion.strict_json import canonical_bytes, dumps as strict_dumps
from py_security_suite.assurance_profile import (
    enforce_assurance_profile,
    load_assurance_profile,
)


def _cases(names: set[str]) -> list[dict[str, object]]:
    return [
        {
            "name": name,
            "status": "passed",
            "case_count": 1,
            "receipt_sha256": hashlib.sha256(name.encode()).hexdigest(),
        }
        for name in sorted(names)
    ]


def _receipts() -> dict[str, dict[str, object]]:
    return {
        "browser": {
            "schema_version": "1.0",
            "engines": ["chromium", "firefox", "webkit"],
            "authenticated_roles": 2,
            "probes": _cases(
                {
                    "csrf",
                    "dom-xss",
                    "postmessage-origin",
                    "session-fixation",
                    "cross-tenant",
                    "service-worker-cache",
                    "websocket-authz",
                }
            ),
        },
        "kafka": {
            "schema_version": "1.0",
            "tls_version": "TLSv1.3",
            "sasl_mechanism": "SCRAM-SHA-512",
            "acl_resources": ["cluster", "group", "topic", "transactional-id"],
            "durability": {
                "acks": "all",
                "min_insync_replicas": 2,
                "replication_factor": 3,
            },
            "tests": _cases(
                {
                    "acl-denial",
                    "consumer-isolation",
                    "failover",
                    "multi-partition-atomicity",
                    "producer-fencing",
                    "restart-deduplication",
                }
            ),
            "schema_formats": ["avro", "json", "protobuf"],
            "key_and_headers_validated": True,
        },
        "postgresql": {
            "schema_version": "1.0",
            "sslmode": "verify-full",
            "channel_binding": "require",
            "audits": [
                "bypassrls",
                "default-privileges",
                "force-row-security",
                "grants",
                "search-path",
                "security-definer",
            ],
            "rls_tests": _cases(
                {
                    "concurrent-policy-race",
                    "covert-channel",
                    "cross-tenant-crud",
                    "owner-bypass",
                    "referential-integrity",
                }
            ),
            "recovery_tests": _cases(
                {
                    "cross-version",
                    "encrypted-backup",
                    "extension-restore",
                    "large-dataset",
                    "logical-restore",
                    "pitr",
                    "wal-replay",
                }
            ),
        },
        "ai": {
            "schema_version": "1.0",
            "independence_dimensions": [
                "hardware",
                "network",
                "organization",
                "process",
            ],
            "attestation_sha256": "1" * 64,
            "inter_rater_kappa": 0.9,
            "adjudication_rate": 0.1,
            "per_control_confusion": {
                "authorization": {"fn": 1, "fp": 1, "tn": 20, "tp": 20}
            },
            "calibration_windows": 3,
        },
        "sarif": {
            "schema_version": "2.1.0",
            "official_schema_sha256": "2" * 64,
            "runs": 1,
            "native_results": 2,
            "normalized_results": 2,
            "exit_status_reconciled": True,
            "preserved_semantics": [
                "automation-details",
                "baseline-state",
                "code-flows",
                "fixes",
                "graphs",
                "related-locations",
                "stacks",
                "suppressions",
                "taxa",
            ],
            "redaction_detectors": [
                "credential-pattern",
                "entropy",
                "known-token-format",
            ],
        },
        "surface": {
            "schema_version": "1.0",
            "server_signed_pages": 2,
            "trusted_time_sha256": "3" * 64,
            "tombstones": 1,
            "history_windows": 2,
            "signed_total_count": True,
            "liveness_probes": 1,
        },
        "supply-chain": {
            "schema_version": "1.0",
            "artifact_sha256": "4" * 64,
            "slsa_level": 3,
            "verifiers": ["dependency-closure", "sigstore", "slsa", "vsa"],
            "container_images": [
                {
                    "digest": "5" * 64,
                    "sbom_sha256": "6" * 64,
                    "signature_bundle_sha256": "7" * 64,
                }
            ],
            "recursive_dependencies": True,
        },
        "trust-state": {
            "schema_version": "1.0",
            "backend": "https-cas-transparency",
            "cas_verified": True,
            "append_only_verified": True,
            "transparency_proof_sha256": "8" * 64,
            "checkpoint_sequence": 5,
            "authority_quorum": 2,
            "rotation_tested": True,
            "algorithms": ["ed25519", "ecdsa-p256"],
        },
        "ci": {
            "schema_version": "1.0",
            "runner_isolation_attested": True,
            "egress_policy_attested": True,
            "image_signatures_verified": True,
            "sboms_verified": True,
            "build_provenance_verified": True,
            "fault_injection_scenarios": [
                "broker-failover",
                "database-restore",
                "network-partition",
                "signer-rotation",
                "stale-policy",
                "tampered-artifact",
            ],
        },
    }


def _authority(
    directory: Path,
    private: Ed25519PrivateKey,
    *,
    name: str,
    purpose: str,
    subject: object,
    collector: str,
) -> dict[str, object]:
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = hashlib.sha256(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).hexdigest()
    key_name = f"{name}.pem"
    signature_name = f"{name}.sig"
    (directory / key_name).write_bytes(public)
    now = datetime.now(UTC)
    result: dict[str, object] = {
        "schema_version": "2.0",
        "algorithm": "ed25519",
        "signer_id": key_id,
        "collector_id": collector,
        "signed_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "public_key_file": key_name,
        "public_key_sha256": hashlib.sha256(public).hexdigest(),
        "signature_file": signature_name,
        "signature_sha256": "",
    }
    statement = {
        "schema_version": "2.0",
        "purpose": purpose,
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "signer_id": key_id,
        "collector_id": collector,
        "signed_at": result["signed_at"],
        "expires_at": result["expires_at"],
        "algorithm": "ed25519",
    }
    signature = private.sign(canonical_bytes(statement))
    (directory / signature_name).write_bytes(signature)
    result["signature_sha256"] = hashlib.sha256(signature).hexdigest()
    return result


def test_every_deep_qualification_area_rejects_a_soft_claim() -> None:
    receipts = _receipts()
    validators = _validators()
    for area, receipt in receipts.items():
        assert validators[area](receipt)

    weakened = dict(receipts["kafka"])
    weakened["tls_version"] = "TLSv1.2"
    with pytest.raises(ValueError, match="TLS 1.3"):
        validators["kafka"](weakened)


def test_deep_assurance_schemas_are_valid() -> None:
    schema_root = Path("src/py_security_suite/schemas")
    for name in (
        "assurance-profile.schema.json",
        "deep-qualification.schema.json",
        "deep-qualification-result.schema.json",
        "qualification-area-receipts.schema.json",
    ):
        Draft202012Validator.check_schema(
            json.loads((schema_root / name).read_text(encoding="utf-8"))
        )


def test_deep_qualification_requires_independent_signed_receipts(
    tmp_path: Path,
) -> None:
    keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    trusted: set[str] = set()
    roles: dict[str, list[str]] = {}
    organizations: dict[str, str] = {}
    lifecycle: dict[str, dict[str, object]] = {}
    entries: list[dict[str, object]] = []
    receipts = _receipts()
    records = [
        {
            "control": "authorization",
            "reviewer_a": expected,
            "reviewer_b": expected,
            "adjudicated": predicted,
            "expected": expected,
        }
        for predicted, expected in (
            (False, True),
            (True, False),
            (False, False),
            (True, True),
        )
    ]
    artifacts: dict[str, object] = {
        "ai-attestation.json": {},
        "ai-adjudication.json": records,
        "ai-calibration.json": [
            {"window_id": f"window-{index}", "records": records} for index in range(3)
        ],
        "sarif-schema.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["version", "runs"],
            "properties": {
                "version": {"const": "2.1.0"},
                "runs": {"type": "array"},
            },
        },
        "sarif-native.json": {
            "version": "2.1.0",
            "runs": [{"results": [{"ruleId": "one"}, {"ruleId": "two"}]}],
        },
        "sarif-normalized.json": {"findings": [{"rule_id": "one"}, {"rule_id": "two"}]},
    }
    for filename, artifact in artifacts.items():
        (tmp_path / filename).write_text(strict_dumps(artifact), encoding="utf-8")
    receipts["ai"].update(
        {
            "attestation_file": "ai-attestation.json",
            "attestation_sha256": hashlib.sha256(
                (tmp_path / "ai-attestation.json").read_bytes()
            ).hexdigest(),
            "adjudication_file": "ai-adjudication.json",
            "adjudication_sha256": hashlib.sha256(
                (tmp_path / "ai-adjudication.json").read_bytes()
            ).hexdigest(),
            "calibration_file": "ai-calibration.json",
            "calibration_sha256": hashlib.sha256(
                (tmp_path / "ai-calibration.json").read_bytes()
            ).hexdigest(),
            "inter_rater_kappa": 1.0,
            "adjudication_rate": 0.0,
            "per_control_confusion": {
                "authorization": {"fn": 1, "fp": 1, "tn": 1, "tp": 1}
            },
        }
    )
    receipts["sarif"].update(
        {
            "official_schema_file": "sarif-schema.json",
            "official_schema_sha256": hashlib.sha256(
                (tmp_path / "sarif-schema.json").read_bytes()
            ).hexdigest(),
            "native_report_file": "sarif-native.json",
            "native_report_sha256": hashlib.sha256(
                (tmp_path / "sarif-native.json").read_bytes()
            ).hexdigest(),
            "normalized_report_file": "sarif-normalized.json",
            "normalized_report_sha256": hashlib.sha256(
                (tmp_path / "sarif-normalized.json").read_bytes()
            ).hexdigest(),
            "process_exit_code": 0,
        }
    )
    now = datetime.now(UTC)
    qualification_context = {
        "run_id": "qualification-run-001",
        "environment_sha256": "a" * 64,
        "target_sha256": "b" * 64,
        "source_sha256": "c" * 64,
        "profile_sha256": "d" * 64,
        "profile_generation": 7,
        "trust_policy_sha256": "f" * 64,
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "nonce": "e" * 64,
    }
    context_sha256 = hashlib.sha256(canonical_bytes(qualification_context)).hexdigest()
    for area, receipt in receipts.items():
        receipt_name = f"{area}.json"
        receipt_path = tmp_path / receipt_name
        receipt_path.write_text(strict_dumps(receipt), encoding="utf-8")
        digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        subject = {
            "area": area,
            "receipt_sha256": digest,
            "feature": {
                "ai": "ai-independent-adjudication",
                "browser": "browser-active-abuse-matrix",
                "ci": "ci-isolated-supply-chain",
                "kafka": "kafka-authz-durability-failover",
                "postgresql": "postgresql-transport-rls-recovery",
                "sarif": "sarif-full-fidelity",
                "supply-chain": "composed-slsa-sigstore-vsa",
                "surface": "surface-server-receipts-history",
                "trust-state": "distributed-transparent-checkpoint",
            }[area],
            "context_sha256": context_sha256,
        }
        authorities = []
        for index, key in enumerate(keys):
            authority = _authority(
                tmp_path,
                key,
                name=f"{area}-{index}",
                purpose=f"deep-qualification:{area}",
                subject=subject,
                collector=f"collector-{area}-{index}",
            )
            signer = str(authority["signer_id"])
            trusted.add(signer)
            roles.setdefault(signer, []).append(f"deep-qualification:{area}")
            organizations[signer] = f"organization-{index}"
            lifecycle[signer] = {
                "not_before": (now - timedelta(days=1)).isoformat(),
                "not_after": (now + timedelta(days=1)).isoformat(),
                "revoked_at": None,
            }
            authorities.append(authority)
        entries.append(
            {
                "area": area,
                "file": receipt_name,
                "sha256": digest,
                "authorities": authorities,
            }
        )
    manifest = tmp_path / "qualification.json"
    manifest.write_text(
        strict_dumps(
            {
                "schema_version": "2.0",
                "context": qualification_context,
                "trusted_time": {},
                "areas": entries,
            }
        ),
        encoding="utf-8",
    )
    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": ",".join(sorted(trusted)),
                "PYSEC_TRUSTED_AUTHORITY_ROLES": strict_dumps(roles),
                "PYSEC_AUTHORITY_ORGANIZATIONS": strict_dumps(organizations),
                "PYSEC_AUTHORITY_KEY_LIFECYCLE": strict_dumps(lifecycle),
                "PYSEC_QUALIFICATION_REPLAY_LEDGER": str(tmp_path / "replay.json"),
            },
        ),
        patch(
            "companion.deep_qualification.verify_rfc3161",
            return_value={
                "trusted_time_observed_at": now.isoformat(),
                "trusted_time_sha256": "f" * 64,
            },
        ),
    ):
        result = qualify(manifest)
        with pytest.raises(ValueError, match="already consumed"):
            qualify(manifest)
    assert result["status"] == "passed"
    assert len(result["features"]) == 9


def test_assurance_profile_blocks_downgrades_and_missing_composition(
    tmp_path: Path,
) -> None:
    keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    now = datetime.now(UTC)
    subject: dict[str, object] = {
        "schema_version": "1.0",
        "profile_id": "production-v1",
        "generation": 7,
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "minimum_contract_versions": {"browser-security": "2.0"},
        "required_features": {"browser-security": ["browser-active-abuse-matrix"]},
        "minimum_slsa_level": 3,
        "required_provenance_verifiers": [
            "dependency-closure",
            "sigstore",
            "slsa",
            "vsa",
        ],
        "minimum_authority_signatures": 2,
        "checkpoint_backend": "https-cas-transparency",
    }
    authorities = [
        _authority(
            tmp_path,
            key,
            name=f"profile-{index}",
            purpose="assurance-profile",
            subject=subject,
            collector=f"policy-office-{index}",
        )
        for index, key in enumerate(keys)
    ]
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(
        strict_dumps({**subject, "authorities": authorities}), encoding="utf-8"
    )
    trusted = ",".join(str(item["signer_id"]) for item in authorities)
    roles = {str(item["signer_id"]): ["assurance-profile"] for item in authorities}
    with patch.dict(
        "os.environ",
        {
            "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": trusted,
            "PYSEC_TRUSTED_AUTHORITY_ROLES": strict_dumps(roles),
            "PYSEC_ASSURANCE_PROFILE_MIN_GENERATION": "7",
        },
    ):
        profile = load_assurance_profile(profile_path)
    document = {
        "schema_version": "2.0",
        "execution": {"features": ["browser-active-abuse-matrix"]},
        "provenance": {
            "slsa_level": "3",
            "verified_by": ["dependency-closure", "sigstore", "slsa", "vsa"],
        },
    }
    assert (
        enforce_assurance_profile(profile, document, kind="browser-security")[
            "profile_generation"
        ]
        == 7
    )
    document["schema_version"] = "1.0"
    with pytest.raises(ValueError, match="below profile minimum"):
        enforce_assurance_profile(profile, document, kind="browser-security")


def test_checkpointed_profile_uses_trusted_time_and_remote_sequence(
    tmp_path: Path,
) -> None:
    keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    now = datetime.now(UTC)
    core: dict[str, object] = {
        "schema_version": "2.0",
        "profile_id": "production-v2",
        "generation": 9,
        "issued_at": (now - timedelta(minutes=2)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "minimum_contract_versions": {"browser-security": "2.0"},
        "required_features": {"browser-security": ["browser-active-abuse-matrix"]},
        "minimum_slsa_level": 3,
        "required_provenance_verifiers": [
            "dependency-closure",
            "sigstore",
            "slsa",
            "vsa",
        ],
        "minimum_authority_signatures": 2,
        "checkpoint_backend": "https-cas-transparency",
    }
    policy_sha256 = hashlib.sha256(canonical_bytes(core)).hexdigest()
    checkpoint_subject = {
        "schema_version": "1.0",
        "backend": "https-cas-transparency",
        "sequence": 21,
        "generation": 9,
        "profile_subject_sha256": policy_sha256,
        "previous_checkpoint_sha256": "0" * 64,
    }
    checkpoint_authorities = [
        _authority(
            tmp_path,
            key,
            name=f"checkpoint-{index}",
            purpose="assurance-profile-checkpoint",
            subject=checkpoint_subject,
            collector=f"checkpoint-office-{index}",
        )
        for index, key in enumerate(keys)
    ]
    profile_authorities = [
        _authority(
            tmp_path,
            key,
            name=f"profile-v2-{index}",
            purpose="assurance-profile",
            subject=core,
            collector=f"profile-office-{index}",
        )
        for index, key in enumerate(keys)
    ]
    profile = {
        **core,
        "checkpoint": {
            **checkpoint_subject,
            "authorities": checkpoint_authorities,
        },
        "trusted_time": {},
        "authorities": profile_authorities,
    }
    profile_path = tmp_path / "profile-v2.json"
    profile_path.write_text(strict_dumps(profile), encoding="utf-8")
    signers = [str(item["signer_id"]) for item in profile_authorities]
    roles = {
        signer: ["assurance-profile", "assurance-profile-checkpoint"]
        for signer in signers
    }
    organizations = {
        signer: f"organization-{index}" for index, signer in enumerate(signers)
    }
    lifecycle = {
        signer: {
            "not_before": (now - timedelta(days=1)).isoformat(),
            "not_after": (now + timedelta(days=1)).isoformat(),
            "revoked_at": None,
        }
        for signer in signers
    }
    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": ",".join(signers),
                "PYSEC_TRUSTED_AUTHORITY_ROLES": strict_dumps(roles),
                "PYSEC_AUTHORITY_ORGANIZATIONS": strict_dumps(organizations),
                "PYSEC_AUTHORITY_KEY_LIFECYCLE": strict_dumps(lifecycle),
                "PYSEC_ASSURANCE_PROFILE_MIN_GENERATION": "9",
                "PYSEC_ASSURANCE_PROFILE_MIN_CHECKPOINT_SEQUENCE": "21",
            },
        ),
        patch(
            "py_security_suite.assurance_profile.verify_rfc3161",
            return_value={
                "trusted_time_observed_at": now.isoformat(),
                "trusted_time_sha256": "a" * 64,
            },
        ),
    ):
        loaded = load_assurance_profile(profile_path, require_checkpoint=True)
    assert loaded["checkpoint"]["sequence"] == 21
    assert (
        loaded["profile_sha256"]
        == hashlib.sha256(profile_path.read_bytes()).hexdigest()
    )
    assert len(loaded["authority_organizations"]) == 2


def test_deep_qualification_consumes_remote_replay_receipt(tmp_path: Path) -> None:
    for name in ("ca.pem", "client.pem", "client.key"):
        (tmp_path / name).write_text("test credential", encoding="utf-8")
    response = Mock()
    response.status = 201
    response.headers = {"Content-Type": "application/json"}
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)

    def open_request(request: object, **_kwargs: object) -> Mock:
        token = request.headers["Idempotency-key"]  # type: ignore[attr-defined]
        response.read.return_value = strict_dumps(
            {"schema_version": "1.0", "token": token, "status": "consumed"}
        ).encode()
        return response

    tls = Mock()
    environment = {
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_TOKEN_ENV": "PYSEC_REPLAY_TOKEN",
        "PYSEC_REPLAY_TOKEN": "test-bearer",
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_CA": str(tmp_path / "ca.pem"),
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_CLIENT_CERT": str(tmp_path / "client.pem"),
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_CLIENT_KEY": str(tmp_path / "client.key"),
    }
    with (
        patch.dict("os.environ", environment),
        patch(
            "companion.deep_qualification.ssl.create_default_context", return_value=tls
        ),
        patch("companion.deep_qualification.urlopen", side_effect=open_request),
    ):
        _consume_remote_replay("a" * 64, "https://replay.example/v1/consume")
    tls.load_cert_chain.assert_called_once()


def test_composed_provenance_binds_all_verification_receipts() -> None:
    base = {
        "schema_version": "2.0",
        "builder_id": "builder",
        "builder_sha256": "1" * 64,
        "builder_environment_sha256": "2" * 64,
        "build_type": "https://example.test/build",
        "source_repository": "https://example.test/repo",
        "source_revision": "3" * 40,
        "native_report_sha256": "4" * 64,
        "normalizer_sha256": "5" * 64,
        "invocation_sha256": "6" * 64,
        "external_parameters_sha256": "7" * 64,
        "materials_sha256": "8" * 64,
        "byproducts_sha256": "9" * 64,
    }
    slsa = {
        "artifact_sha256": "a" * 64,
        "builder_id": "builder",
        "slsa_level": "3",
        "envelope_sha256": "b" * 64,
        "resolved_dependencies_sha256": "c" * 64,
        "dependency_manifest_verified": "true",
    }
    sigstore = {
        "artifact_sha256": "a" * 64,
        "bundle_sha256": "d" * 64,
        "trusted_root_sha256": "e" * 64,
        "cosign_sha256": "f" * 64,
        "transparency_log_verified": "true",
    }
    vsa = {
        "artifact_sha256": "a" * 64,
        "envelope_sha256": "1" * 64,
        "policy_sha256": "2" * 64,
        "signer_key_id": "3" * 64,
        "dependency_closure_verified": "true",
        "dependency_levels_sha256": "4" * 64,
    }
    result = compose_provenance(base=base, slsa=slsa, sigstore=sigstore, vsa=vsa)
    assert result["schema_version"] == "3.0"
    assert result["verified_by"] == [
        "dependency-closure",
        "sigstore",
        "slsa",
        "vsa",
    ]


def test_authority_v2_supports_p256_algorithm_agility(tmp_path: Path) -> None:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = hashlib.sha256(
        private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    (tmp_path / "authority.pem").write_bytes(public)
    now = datetime.now(UTC)
    subject = {"checkpoint": "a" * 64}
    authority: dict[str, object] = {
        "schema_version": "2.0",
        "algorithm": "ecdsa-p256-sha256",
        "signer_id": key_id,
        "collector_id": "independent-policy-office",
        "signed_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=10)).isoformat(),
        "public_key_file": "authority.pem",
        "public_key_sha256": hashlib.sha256(public).hexdigest(),
        "signature_file": "authority.sig",
        "signature_sha256": "",
    }
    statement = {
        "schema_version": "2.0",
        "purpose": "checkpoint-rotation",
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "signer_id": key_id,
        "collector_id": authority["collector_id"],
        "signed_at": authority["signed_at"],
        "expires_at": authority["expires_at"],
        "algorithm": "ecdsa-p256-sha256",
    }
    signature = private.sign(canonical_bytes(statement), ec.ECDSA(hashes.SHA256()))
    (tmp_path / "authority.sig").write_bytes(signature)
    authority["signature_sha256"] = hashlib.sha256(signature).hexdigest()
    context = tmp_path / "context.json"
    context.write_text("{}", encoding="utf-8")
    with patch.dict(
        "os.environ",
        {
            "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": key_id,
            "PYSEC_TRUSTED_AUTHORITY_ROLES": strict_dumps(
                {key_id: ["checkpoint-rotation"]}
            ),
            "PYSEC_AUTHORITY_ORGANIZATIONS": strict_dumps(
                {key_id: "independent-policy-office"}
            ),
            "PYSEC_AUTHORITY_KEY_LIFECYCLE": strict_dumps(
                {
                    key_id: {
                        "not_before": (now - timedelta(days=1)).isoformat(),
                        "not_after": (now + timedelta(days=1)).isoformat(),
                        "revoked_at": None,
                    }
                }
            ),
        },
    ):
        result = verify_authority(
            context,
            authority,
            purpose="checkpoint-rotation",
            subject=subject,
        )
    assert result["algorithm"] == "ecdsa-p256-sha256"


def test_surface_history_and_sarif_extended_semantics_are_verified() -> None:
    history = [
        {
            "observed_at": "2026-01-01T00:00:00+00:00",
            "snapshot_sha256": hashlib.sha256(
                strict_dumps(["one", "two"]).encode()
            ).hexdigest(),
            "record_ids": ["one", "two"],
            "tombstone_ids": [],
            "total_records": 2,
            "previous_window_sha256": "0" * 64,
        }
    ]
    history.append(
        {
            "observed_at": "2026-01-02T00:00:00+00:00",
            "snapshot_sha256": hashlib.sha256(
                strict_dumps(["two"]).encode()
            ).hexdigest(),
            "record_ids": ["two"],
            "tombstone_ids": ["one"],
            "total_records": 1,
            "previous_window_sha256": hashlib.sha256(
                strict_dumps(history[0]).encode()
            ).hexdigest(),
        }
    )
    _verify_history(history)
    history[1]["previous_window_sha256"] = "1" * 64
    with pytest.raises(ValueError, match="hash chain"):
        _verify_history(history)

    semantics = _sarif_semantics(
        {
            "relatedLocations": [{"id": 1}],
            "stacks": [{"message": {"text": "bounded"}}],
            "graphs": [{"description": {"text": "flow"}}],
            "suppressions": [{"kind": "external"}],
            "baselineState": "new",
        },
        run={"automationDetails": {"id": "ci/security"}},
    )
    assert semantics["related_locations_count"] == 1
    assert semantics["suppressions_count"] == 1
    assert semantics["baseline_state"] == "new"
    redacted, changed = _safe_sarif_message("token 9Z0Yx8Wv7Uu6Tt5Ss4Rr3Qq2Pp1Oo0Nn")
    assert changed is True
    assert redacted.startswith("Sensitive native message redacted")
