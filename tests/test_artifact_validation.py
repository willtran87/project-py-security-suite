from __future__ import annotations

import pytest
import json
import hashlib
import base64
import os
import sys
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.artifact_validation import (
    _validate_git_signature_ledger,
    validate_governed_artifacts,
)
from py_security_suite.adapters.portfolio import PipdeptreeAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.deployment_receipt import verify_deployment_receipt
from py_security_suite.inventory import allowed_signer_fingerprints
from py_security_suite.strict_json import canonical_bytes
from tests.deployment_authority import (
    authority_environment,
    effective_policy_attestation,
    operation_receipt,
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


def test_runtime_surface_binding_has_a_governed_publication_contract() -> None:
    digest = "a" * 64
    context = {
        "surface_sha256": digest,
        "deployment_sha256": "b" * 64,
        "target_manifest_sha256": "c" * 64,
    }
    artifact = {
        "schema_version": "1.0",
        "analysis": "canonical-runtime-surface-and-truth-diversity",
        "complete": True,
        "canonical_context": context,
        "applicable_lanes": ["surface-inventory"],
        "bound_lanes": ["surface-inventory"],
        "missing_lanes": [],
        "invalid_context_lanes": [],
        "mismatched_context_lanes": [],
        "truth_diversity_gaps": [],
        "lane_contexts": {"surface-inventory": context},
    }
    validated = validate_governed_artifacts({"runtime-surface-binding.json": artifact})
    assert "runtime-surface-binding.json" in validated


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
    commit_payloads = [
        f"tree {'1' * 64}\nauthor test <test@example.invalid> 1 +0000\ncommitter test <test@example.invalid> 1 +0000\n\ncommit {index}\n".encode()
        for index in (1, 2)
    ]
    commit_ids = [
        hashlib.sha256(
            b"commit " + str(len(payload)).encode() + b"\0" + payload
        ).hexdigest()
        for payload in commit_payloads
    ]
    security_config = b"gpg.format\nssh\x00"
    manifest = {
        "schema_version": "1.0",
        "git_executable_sha256": "c" * 64,
        "allowed_signers_file_sha256": hashlib.sha256(allowed).hexdigest(),
        "allowed_signers_file_base64": base64.b64encode(allowed).decode(),
        "git_runtime_manifest": {
            "version": "git version 2.51.0",
            "executable_sha256": "c" * 64,
            "runtime_closure_sha256": "f" * 64,
        },
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
                    "commit": commit_id,
                    "fingerprint": fingerprint,
                    "committed_at": now.isoformat(),
                    "organization": f"org-{index}",
                    "object_base64": base64.b64encode(payload).decode(),
                    "object_sha256": hashlib.sha256(payload).hexdigest(),
                }
                for index, (commit_id, payload, fingerprint) in enumerate(
                    zip(commit_ids, commit_payloads, fingerprints, strict=True), start=1
                )
            ],
            "tags": [],
        },
        "repository_state": {
            "refs": {"refs/heads/main": commit_ids[0]},
            "object_format": "sha256",
            "head": commit_ids[0],
            "symbolic_head": "refs/heads/main",
            "replace_refs": "",
            "security_config_sha256": hashlib.sha256(security_config).hexdigest(),
            "security_config_base64": base64.b64encode(security_config).decode(),
            "alternates_sha256": "",
            "reachable_objects_sha256": "e" * 64,
        },
    }
    manifest["clean_replay"] = {
        "schema_version": "1.0",
        "bundle_sha256": "d" * 64,
        "reachable_objects_sha256": "e" * 64,
        "signature_ledger_sha256": hashlib.sha256(
            canonical_bytes(manifest["signature_ledger"])
        ).hexdigest(),
        "git_executable_sha256": "c" * 64,
        "git_runtime_closure_sha256": "f" * 64,
        "verified_commits": 2,
        "verified_tags": 0,
    }
    replay = manifest["clean_replay"]
    domains = [
        {
            "organization": f"git-domain-{index}",
            "host_identity_sha256": f"{index}" * 64,
            "control_plane_sha256": f"{index + 3}" * 64,
            "implementation_sha256": f"{index + 6}" * 64,
        }
        for index in (1, 2, 3)
    ]
    replay["primary_failure_domain"] = domains[0]
    replay_base = {
        "schema_version": "1.0",
        "bundle_sha256": replay["bundle_sha256"],
        "bundle_size_bytes": 1024,
        "reachable_objects_sha256": replay["reachable_objects_sha256"],
        "signature_ledger_sha256": replay["signature_ledger_sha256"],
        "allowed_signers_sha256": manifest["allowed_signers_file_sha256"],
        "verified_commits": 2,
        "verified_tags": 0,
    }
    storage_key = Ed25519PrivateKey.generate()
    storage_subject = {
        **replay_base,
        "object_id": f"sha256:{replay['bundle_sha256']}",
        "object_version": "version-1",
        "immutable_uri": f"cas://git/{replay['bundle_sha256']}",
        "retention_until": (now + timedelta(days=365)).isoformat(),
        "execution_nonce": "fixture-execution-nonce",
        "failure_domain": domains[1],
    }
    storage_receipt, storage_key_sha256 = operation_receipt(
        storage_subject,
        purpose="git-bundle-cas-publish",
        operation_id="git-cas-1",
        private_key=storage_key,
    )
    storage_attested_request = {
        **replay_base,
        "bundle_path": "C:/sealed/git.bundle",
        "command_context": {},
    }
    storage_attestation = effective_policy_attestation(
        domains[1], attested_request=storage_attested_request
    )
    replay["bundle_storage"] = {
        "schema_version": "1.0",
        "object_id": storage_subject["object_id"],
        "object_version": storage_subject["object_version"],
        "immutable_uri": storage_subject["immutable_uri"],
        "retention_until": storage_subject["retention_until"],
        "bundle_sha256": replay["bundle_sha256"],
        "bundle_size_bytes": 1024,
        "authority_key_sha256": storage_key_sha256,
        "execution_nonce": "fixture-execution-nonce",
        "failure_domain": domains[1],
        "operation_receipt": storage_receipt,
        "effective_policy_attestation": storage_attestation,
        "attested_request": storage_attested_request,
    }
    verifier_key = Ed25519PrivateKey.generate()
    verifier_subject = {
        **replay_base,
        "cas_object_id": storage_subject["object_id"],
        "cas_object_version": storage_subject["object_version"],
        "cas_immutable_uri": storage_subject["immutable_uri"],
        "cas_authority_key_sha256": storage_key_sha256,
        "cas_operation_receipt_sha256": hashlib.sha256(
            canonical_bytes(storage_receipt)
        ).hexdigest(),
        "cas_effective_policy_attestation_sha256": hashlib.sha256(
            canonical_bytes(storage_attestation)
        ).hexdigest(),
        "cas_bundle_read_sha256": replay["bundle_sha256"],
        "execution_nonce": "fixture-execution-nonce",
        "failure_domain": domains[2],
    }
    verifier_receipt, verifier_key_sha256 = operation_receipt(
        verifier_subject,
        purpose="git-bundle-secondary-verification",
        operation_id="git-secondary-1",
        private_key=verifier_key,
    )
    secondary_attested_request = {
        **replay_base,
        "cas_object_id": storage_subject["object_id"],
        "cas_object_version": storage_subject["object_version"],
        "cas_immutable_uri": storage_subject["immutable_uri"],
        "cas_authority_key_sha256": storage_key_sha256,
        "cas_operation_receipt_sha256": hashlib.sha256(
            canonical_bytes(storage_receipt)
        ).hexdigest(),
        "cas_effective_policy_attestation_sha256": hashlib.sha256(
            canonical_bytes(storage_attestation)
        ).hexdigest(),
        "command_context": {},
    }
    secondary_attestation = effective_policy_attestation(
        domains[2], attested_request=secondary_attested_request
    )
    replay["secondary_verification"] = {
        **replay_base,
        "cas_object_id": storage_subject["object_id"],
        "cas_object_version": storage_subject["object_version"],
        "cas_bundle_read_sha256": replay["bundle_sha256"],
        "authority_key_sha256": verifier_key_sha256,
        "execution_nonce": "fixture-execution-nonce",
        "failure_domain": domains[2],
        "operation_receipt": verifier_receipt,
        "effective_policy_attestation": secondary_attestation,
        "attested_request": secondary_attested_request,
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
    with patch.dict(
        os.environ,
        {
            "PYSEC_SCAN_TIME_CHALLENGE_SHA256": "c" * 64,
            "PYSEC_SCAN_TIME_CONTEXT_SHA256": "e" * 64,
        },
    ):
        validate_governed_artifacts({"source-inventory.json": inventory})
        manifest["clean_replay"]["secondary_verification"]["cas_bundle_read_sha256"] = (
            "0" * 64
        )
        with pytest.raises(ValueError, match="external Git replay evidence"):
            validate_governed_artifacts({"source-inventory.json": inventory})
        manifest["clean_replay"]["secondary_verification"]["cas_bundle_read_sha256"] = (
            manifest["clean_replay"]["bundle_sha256"]
        )
    original_object = manifest["signature_ledger"]["commits"][0]["object_base64"]
    manifest["signature_ledger"]["commits"][0]["object_base64"] = base64.b64encode(
        b"tampered commit object"
    ).decode()
    with pytest.raises(ValueError, match="object replay failed"):
        _validate_git_signature_ledger(manifest, set(fingerprints))
    manifest["signature_ledger"]["commits"][0]["object_base64"] = original_object
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
    with patch.dict(
        os.environ,
        {
            "PYSEC_SCAN_TIME_CHALLENGE_SHA256": "c" * 64,
            "PYSEC_SCAN_TIME_CONTEXT_SHA256": "e" * 64,
        },
    ):
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
    recovery_private = Ed25519PrivateKey.generate()
    recovery_private_pem = recovery_private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    recovery_public = recovery_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    recovery_key_sha256 = hashlib.sha256(recovery_public).hexdigest()
    audit_private = Ed25519PrivateKey.generate()
    audit_private_pem = audit_private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    audit_public = audit_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    audit_key_sha256 = hashlib.sha256(audit_public).hexdigest()
    recovery_script = tmp_path / "recover.py"
    cryptography_site_packages = Path(serialization.__file__).resolve().parents[4]
    recovery_script.write_text(
        "import base64,hashlib,json,os,pathlib,sys\n"
        "from datetime import UTC,datetime,timedelta\n"
        f"sys.path.insert(0,{str(cryptography_site_packages)!r})\n"
        "from cryptography.hazmat.primitives import hashes,serialization\n"
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "from cryptography.hazmat.primitives.kdf.hkdf import HKDF\n"
        f"ROOT=pathlib.Path({str(raw_store.resolve())!r})\n"
        f"KEY=base64.b64decode({base64.b64encode(key_bytes).decode()!r})\n"
        f"PRIVATE=base64.b64decode({base64.b64encode(recovery_private_pem).decode()!r})\n"
        f"AUDIT_PRIVATE=base64.b64decode({base64.b64encode(audit_private_pem).decode()!r})\n"
        "canonical=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()\n"
        "request=json.loads(base64.b64decode(sys.argv[-1]));execution_subject=json.loads(base64.b64decode(os.environ['PYSEC_PINNED_ATTESTATION_SUBJECT_BASE64']));stored=(ROOT/request['object_id']).read_bytes()\n"
        "object_key=HKDF(algorithm=hashes.SHA256(),length=32,salt=bytes.fromhex(request['expected_plaintext_sha256']),info=b'pysec-native-evidence-object-v1').derive(KEY)\n"
        "plaintext=AESGCM(object_key).decrypt(stored[:12],stored[12:],request['expected_plaintext_sha256'].encode())\n"
        "private=serialization.load_pem_private_key(PRIVATE,password=None);public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)\n"
        "subject={'schema_version':'1.0','request_sha256':hashlib.sha256(canonical(request)).hexdigest(),'object_id':request['object_id'],'ciphertext_sha256':hashlib.sha256(stored).hexdigest(),'recovered_plaintext_sha256':hashlib.sha256(plaintext).hexdigest(),'replica_identity_sha256':hashlib.sha256(b'independent-test-replica').hexdigest(),'kms_unwrap_operation_id':'unwrap-test-1','execution_nonce':execution_subject['execution_nonce']}\n"
        "now=datetime.now(UTC);statement={'schema_version':'1.0','purpose':'raw-evidence-clean-host-recovery','subject_sha256':hashlib.sha256(canonical(subject)).hexdigest(),'operation_id':'recovery-test-1','previous_operation_sha256':'','challenge_sha256':request['challenge_sha256'],'trusted_time_sha256':os.environ['PYSEC_SCAN_TIME_CONTEXT_SHA256'],'issued_at':now.isoformat(),'expires_at':(now+timedelta(minutes=5)).isoformat(),'signer_key_sha256':hashlib.sha256(public).hexdigest()}\n"
        "receipt={'schema_version':'1.0','statement':statement,'signature_base64':base64.b64encode(private.sign(canonical(statement))).decode(),'public_key_pem_base64':base64.b64encode(public).decode()}\n"
        "audit_private=serialization.load_pem_private_key(AUDIT_PRIVATE,password=None);audit_public=audit_private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)\n"
        "audit_subject={'schema_version':'1.0','provider':'test-kms','audit_event_id':'audit-test-1','object_id':subject['object_id'],'ciphertext_sha256':subject['ciphertext_sha256'],'recovered_plaintext_sha256':subject['recovered_plaintext_sha256'],'wrapped_key_sha256':request['wrapped_key_sha256'],'kms_unwrap_operation_id':subject['kms_unwrap_operation_id'],'hardware_backed':True,'failure_domain':{'organization':'external-test-kms-provider','host_identity_sha256':'a'*64,'control_plane_sha256':'b'*64,'implementation_sha256':'d'*64}}\n"
        "audit_statement={'schema_version':'1.0','purpose':'kms-unwrap-provider-audit','subject_sha256':hashlib.sha256(canonical(audit_subject)).hexdigest(),'operation_id':'audit-test-1','previous_operation_sha256':'','challenge_sha256':request['challenge_sha256'],'trusted_time_sha256':os.environ['PYSEC_SCAN_TIME_CONTEXT_SHA256'],'issued_at':now.isoformat(),'expires_at':(now+timedelta(minutes=5)).isoformat(),'signer_key_sha256':hashlib.sha256(audit_public).hexdigest()}\n"
        "audit_receipt={'schema_version':'1.0','statement':audit_statement,'signature_base64':base64.b64encode(audit_private.sign(canonical(audit_statement))).decode(),'public_key_pem_base64':base64.b64encode(audit_public).decode()}\n"
        "audit_event={**audit_subject,'operation_receipt':audit_receipt}\n"
        "print(json.dumps({'schema_version':'1.0','object_id':subject['object_id'],'ciphertext_sha256':subject['ciphertext_sha256'],'recovered_plaintext_sha256':subject['recovered_plaintext_sha256'],'replica_identity_sha256':subject['replica_identity_sha256'],'kms_unwrap_operation_id':subject['kms_unwrap_operation_id'],'execution_nonce':subject['execution_nonce'],'recovery_operation_id':'recovery-test-1','recovery_authority_key_sha256':hashlib.sha256(public).hexdigest(),'recovery_operation_receipt':receipt,'provider_audit_authority_key_sha256':hashlib.sha256(audit_public).hexdigest(),'provider_audit_event':audit_event}))\n",
        encoding="utf-8",
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
    recovery_sandbox, _, recovery_sandbox_asset = pinned_command_sandbox_environment(
        tmp_path,
        prefix="PYSEC_RAW_EVIDENCE_RECOVERY",
        allowed_endpoints=["https://kms-recovery.example.invalid:443"],
    )
    recovery_environment = {
        "PYSEC_RAW_EVIDENCE_RECOVERY_COMMAND_JSON": json.dumps(
            [str(executable), "-I", str(recovery_script)]
        ),
        "PYSEC_RAW_EVIDENCE_RECOVERY_EXECUTABLE_SHA256": hashlib.sha256(
            executable.read_bytes()
        ).hexdigest(),
        "PYSEC_RAW_EVIDENCE_RECOVERY_ASSETS_JSON": json.dumps(
            [
                {
                    "path": str(recovery_script),
                    "sha256": hashlib.sha256(recovery_script.read_bytes()).hexdigest(),
                },
                recovery_sandbox_asset,
            ]
        ),
        "PYSEC_RAW_EVIDENCE_RECOVERY_AUTHORITY_KEY_SHA256": recovery_key_sha256,
        "PYSEC_RAW_EVIDENCE_RECOVERY_PROVIDER_AUDIT_KEY_SHA256": audit_key_sha256,
        **recovery_sandbox,
    }
    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_RAW_EVIDENCE_DIRECTORY": str(raw_store),
                **kms_environment,
                **recovery_environment,
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
    with patch.dict(
        os.environ,
        {
            "PYSEC_SCAN_TIME_CHALLENGE_SHA256": "c" * 64,
            "PYSEC_SCAN_TIME_CONTEXT_SHA256": "e" * 64,
        },
    ):
        validate_governed_artifacts({"pipdeptree-summary.json": artifact})
    object_path.write_bytes(b"corrupt")
    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_RAW_EVIDENCE_DIRECTORY": str(raw_store),
                **kms_environment,
                **recovery_environment,
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
