from __future__ import annotations

import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from companion.database_security import _case as database_case
from companion.database_security import _verify_negotiated_connection
from companion.evidence_authority import verify_authority, verify_portable_authority
from companion.provenance import (
    DSSE_PAYLOAD_TYPE,
    IN_TOTO_STATEMENT_V1,
    SLSA_PROVENANCE_V1,
    _dsse_pae,
    slsa_provenance,
    verify_slsa_dsse,
)
from companion.strict_json import canonical_bytes, dumps as strict_dumps
from companion.surface_inventory import reconcile
from companion.tool_normalizers import _sarif_findings, _sarif_semantics
from py_security_suite.evidence_ingest import (
    _assurance_provenance,
    _bind_evidence,
    _consume_replay_service,
    _advance_replay_receipt_state,
    _signed_binding,
)
from py_security_suite.inventory import source_snapshot


def _write_authority(
    directory: Path, *, name: str, purpose: str, subject: object, collector: str
) -> dict[str, object]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_name = f"{name}.pub.pem"
    signature_name = f"{name}.sig"
    (directory / key_name).write_bytes(public)
    now = datetime.now(UTC)
    value: dict[str, object] = {
        "schema_version": "1.0",
        "signer_id": hashlib.sha256(
            private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).hexdigest(),
        "collector_id": collector,
        "signed_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "public_key_file": key_name,
        "public_key_sha256": hashlib.sha256(public).hexdigest(),
        "signature_file": signature_name,
        "signature_sha256": "",
    }
    statement = {
        "schema_version": "1.0",
        "purpose": purpose,
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "signer_id": value["signer_id"],
        "collector_id": collector,
        "signed_at": value["signed_at"],
        "expires_at": value["expires_at"],
    }
    signature = private.sign(canonical_bytes(statement))
    (directory / signature_name).write_bytes(signature)
    value["signature_sha256"] = hashlib.sha256(signature).hexdigest()
    return value


def test_surface_v2_requires_distinct_signed_collectors(tmp_path: Path) -> None:
    declared = [{"id": "api-v1", "version": "1", "owner": "team", "status": "active"}]
    runtime = [{"id": "api-v1", "version": "1", "owner": "team"}]
    gateway = [
        {"id": "api-v1", "version": "1", "owner": "team"},
        {"id": "shadow", "version": "1", "owner": "unknown"},
    ]
    for name, value in (
        ("declared.json", declared),
        ("runtime.json", runtime),
        ("gateway.json", gateway),
    ):
        (tmp_path / name).write_text(strict_dumps(value), encoding="utf-8")
    sources = []
    for kind, filename, collector in (
        ("runtime", "runtime.json", "runtime-adapter"),
        ("gateway", "gateway.json", "gateway-adapter"),
    ):
        digest = hashlib.sha256((tmp_path / filename).read_bytes()).hexdigest()
        sources.append(
            {
                "kind": kind,
                "file": filename,
                "sha256": digest,
                "authority": _write_authority(
                    tmp_path,
                    name=kind,
                    purpose=f"surface-inventory:{kind}",
                    subject={"kind": kind, "sha256": digest},
                    collector=collector,
                ),
            }
        )
    contract = {
        "schema_version": "2.0",
        "declared_file": "declared.json",
        "declared_sha256": hashlib.sha256(
            (tmp_path / "declared.json").read_bytes()
        ).hexdigest(),
        "observed_sources": sources,
        "canary_id": "api-v1",
        "observed_at": datetime.now(UTC).isoformat(),
    }
    path = tmp_path / "contract.json"
    path.write_text(strict_dumps(contract), encoding="utf-8")

    trusted = ",".join(str(source["authority"]["signer_id"]) for source in sources)
    roles = {
        str(source["authority"]["signer_id"]): [f"surface-inventory:{source['kind']}"]
        for source in sources
    }
    with patch.dict(
        "os.environ",
        {
            "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": trusted,
            "PYSEC_TRUSTED_AUTHORITY_ROLES": strict_dumps(roles),
        },
    ):
        result = reconcile(path)

    assert "independent-signers" in result["execution"]["features"]


def test_authority_rejects_self_authenticated_unpinned_key(tmp_path: Path) -> None:
    subject = {"kind": "runtime", "sha256": "1" * 64}
    authority = _write_authority(
        tmp_path,
        name="untrusted",
        purpose="surface-inventory:runtime",
        subject=subject,
        collector="collector",
    )
    context = tmp_path / "contract.json"
    context.write_text("{}", encoding="utf-8")
    with (
        patch.dict("os.environ", {}, clear=True),
        pytest.raises(ValueError, match="trust anchors"),
    ):
        verify_authority(
            context,
            authority,
            purpose="surface-inventory:runtime",
            subject=subject,
        )


def test_portable_authority_receipt_is_cryptographically_reverified(
    tmp_path: Path,
) -> None:
    subject = {"kind": "semantic", "sha256": "1" * 64}
    purpose = "independent-semantic-validation"
    authority = _write_authority(
        tmp_path,
        name="portable",
        purpose=purpose,
        subject=subject,
        collector="collector-a",
    )
    signer = str(authority["signer_id"])
    context = tmp_path / "context.json"
    context.write_text("{}", encoding="utf-8")
    now = datetime.now(UTC)
    with patch.dict(
        "os.environ",
        {
            "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": signer,
            "PYSEC_TRUSTED_AUTHORITY_ROLES": strict_dumps({signer: [purpose]}),
        },
    ):
        verified = verify_authority(
            context, authority, purpose=purpose, subject=subject, at=now
        )
        replayed = verify_portable_authority(
            verified["portable_receipt"], purpose=purpose, subject=subject, at=now
        )
    assert replayed["signer_id"] == signer
    tampered = dict(verified["portable_receipt"])
    tampered["signature_base64"] = "AA=="
    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": signer,
                "PYSEC_TRUSTED_AUTHORITY_ROLES": strict_dumps({signer: [purpose]}),
            },
        ),
        pytest.raises(ValueError, match="commitment"),
    ):
        verify_portable_authority(tampered, purpose=purpose, subject=subject, at=now)


def test_replay_service_verifies_signed_hash_chained_receipt(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_path = tmp_path / "receipt.pub.pem"
    public_path.write_bytes(public)
    ca_path = tmp_path / "replay-ca.pem"
    cert_path = tmp_path / "replay-client.pem"
    key_path = tmp_path / "replay-client.key"
    for path in (ca_path, cert_path, key_path):
        path.write_text("test credential", encoding="utf-8")
    document = {
        "run_id": "run-1",
        "kind": "nuclei",
        "source_sha256": "1" * 64,
        "environment_sha256": "2" * 64,
        "context": {"challenge": "3" * 64},
        "provenance": {"native_report_sha256": "4" * 64},
        "evidence_binding": {
            "authenticated": True,
            "evidence_sha256": "5" * 64,
            "attestation": {"key_id": "6" * 64},
        },
    }
    from py_security_suite.evidence_ingest import _replay_identity

    _, token = _replay_identity(document)
    receipt = {
        "schema_version": "1.0",
        "token": token,
        "sequence": 7,
        "consumed_at": datetime.now(UTC).isoformat(),
        "previous_receipt_sha256": "7" * 64,
        "key_id": hashlib.sha256(
            private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).hexdigest(),
    }
    receipt["signature"] = base64.b64encode(
        private.sign(canonical_bytes(receipt))
    ).decode()
    body = strict_dumps(receipt).encode()

    class Response:
        status = 201
        headers = {
            "Content-Length": str(len(body)),
            "Content-Type": "application/json",
        }

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _maximum: int) -> bytes:
            return body

    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_REPLAY_TOKEN": "opaque",
                "PYSEC_REPLAY_RECEIPT_KEY_SHA256": receipt["key_id"],
            },
        ),
        patch("py_security_suite.evidence_ingest.ssl.create_default_context") as tls,
        patch("py_security_suite.evidence_ingest.urlopen", return_value=Response()),
    ):
        _consume_replay_service(
            document,
            "https://replay.example.test/consume",
            token_env="PYSEC_REPLAY_TOKEN",  # noqa: S106
            ca_path=ca_path,
            receipt_public_key=public_path,
            client_cert=cert_path,
            client_key=key_path,
        )
    tls.return_value.load_cert_chain.assert_called_once()


def test_replay_receipt_state_rejects_forks_and_rollbacks(tmp_path: Path) -> None:
    state = tmp_path / "replay-state.json"
    first = {
        "sequence": 4,
        "receipt_sha256": "1" * 64,
        "previous_receipt_sha256": "0" * 64,
        "key_id": "2" * 64,
    }
    _advance_replay_receipt_state(state, first)
    second = {
        "sequence": 5,
        "receipt_sha256": "3" * 64,
        "previous_receipt_sha256": "1" * 64,
        "key_id": "2" * 64,
    }
    _advance_replay_receipt_state(state, second)
    with pytest.raises(ValueError, match="monotonic"):
        _advance_replay_receipt_state(state, second)


def test_replay_receipt_state_serializes_concurrent_first_writers(
    tmp_path: Path,
) -> None:
    state = tmp_path / "concurrent-replay-state.json"
    receipts = [
        {
            "sequence": 1,
            "receipt_sha256": digit * 64,
            "previous_receipt_sha256": "",
            "key_id": "a" * 64,
        }
        for digit in ("1", "2")
    ]

    def advance(receipt: dict[str, object]) -> str:
        try:
            _advance_replay_receipt_state(state, receipt)
        except ValueError:
            return "rejected"
        return "accepted"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(advance, receipts))

    assert sorted(outcomes) == ["accepted", "rejected"]


def test_slsa_provenance_binds_builder_source_parameters_and_byproducts(
    tmp_path: Path,
) -> None:
    files = {}
    for name in (
        "report",
        "normalizer",
        "builder",
        "environment",
        "invocation",
        "parameters",
        "materials",
        "byproducts",
    ):
        path = tmp_path / name
        path.write_text(name, encoding="utf-8")
        files[name] = path
    value = slsa_provenance(
        native_report=files["report"],
        normalizer=files["normalizer"],
        builder_id="https://github.com/example/builder@v1",
        builder=files["builder"],
        builder_environment=files["environment"],
        build_type="https://slsa.dev/build-type/v1",
        source_repository="https://github.com/example/repository",
        source_revision="a" * 40,
        invocation=files["invocation"],
        external_parameters=files["parameters"],
        materials=files["materials"],
        byproducts=files["byproducts"],
    )

    assert _assurance_provenance(value) == value


def test_standard_slsa_dsse_verifies_signature_subject_and_policy(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"release")
    parameters = {"revision": "a" * 40, "target": "wheel"}
    statement = {
        "_type": IN_TOTO_STATEMENT_V1,
        "subject": [
            {
                "name": "artifact.bin",
                "digest": {"sha256": hashlib.sha256(b"release").hexdigest()},
            }
        ],
        "predicateType": SLSA_PROVENANCE_V1,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://example.test/build/v1",
                "externalParameters": parameters,
                "internalParameters": {},
                "resolvedDependencies": [
                    {
                        "uri": "https://github.com/example/repository",
                        "digest": {"sha256": "a" * 40},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": "https://example.test/builder/v1"},
                "metadata": {},
                "byproducts": [],
            },
        },
    }
    payload = canonical_bytes(statement)
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_path = tmp_path / "builder.pub.pem"
    key_path.write_bytes(public)
    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "keyid": hashlib.sha256(
                    private.public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    )
                ).hexdigest(),
                "sig": base64.b64encode(
                    private.sign(_dsse_pae(DSSE_PAYLOAD_TYPE, payload))
                ).decode(),
            }
        ],
    }
    envelope_path = tmp_path / "provenance.dsse.json"
    envelope_path.write_text(strict_dumps(envelope), encoding="utf-8")

    key_id = hashlib.sha256(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).hexdigest()
    with patch.dict(
        "os.environ",
        {
            "PYSEC_SLSA_BUILDER_POLICY": strict_dumps(
                {
                    "https://example.test/builder/v1": {
                        "key_sha256": key_id,
                        "maximum_slsa_level": 3,
                    }
                }
            )
        },
    ):
        result = verify_slsa_dsse(
            envelope=envelope_path,
            artifact=artifact,
            trusted_public_key=key_path,
            expected_builder_id="https://example.test/builder/v1",
            expected_build_type="https://example.test/build/v1",
            expected_source_repository="https://github.com/example/repository",
            expected_source_revision="a" * 40,
            expected_external_parameters=parameters,
            expected_public_key_sha256=key_id,
        )

    assert result["artifact_sha256"] == hashlib.sha256(b"release").hexdigest()


def test_external_dsse_binding_does_not_load_private_key(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('safe')\n", encoding="utf-8")
    evidence = source / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    envelopes = source / "external"
    envelopes.mkdir()
    source_digest, _, _ = source_snapshot(source, excluded_paths=(evidence, envelopes))
    private = Ed25519PrivateKey.generate()
    binding = _signed_binding(
        [private],
        evidence_name=evidence.name,
        evidence_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),
        source_sha256=source_digest,
        key_id="",
        valid_for_hours=1,
        run_id="external-run",
    )
    (envelopes / f"{evidence.name}.dsse.json").write_text(
        strict_dumps(binding["envelope"]), encoding="utf-8"
    )

    result = _bind_evidence(
        [evidence],
        source_root=source,
        overwrite=False,
        external_envelope_dir=envelopes,
    )

    assert result["externally_signed"] is True
    assert result["run_id"] == "external-run"


def test_database_block_oracle_requires_exact_sqlstate() -> None:
    value = {
        "id": "rls",
        "target_id": "table",
        "role": "reader",
        "control": "row-level-security",
        "sql": "SELECT 1",
        "parameters_env": "",
        "expected": "block",
        "expected_sqlstate": "",
        "severity": "high",
        "classification": "CWE-284",
    }
    with pytest.raises(ValueError, match="exact expected SQLSTATE"):
        database_case(value)


def test_sarif_preserves_bounded_flow_and_taxonomy_semantics() -> None:
    payload = {
        "tool": "eslint-sarif",
        "report": {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "eslint", "version": "10"}},
                    "invocations": [{"executionSuccessful": True}],
                    "results": [
                        {
                            "ruleId": "security/detect-eval-with-expression",
                            "level": "error",
                            "message": {"text": "dynamic code"},
                            "fingerprints": {"primary": "opaque"},
                            "taxa": [{"id": "CWE-95"}],
                            "fixes": [{}],
                            "properties": {"precision": "high"},
                            "codeFlows": [
                                {
                                    "threadFlows": [
                                        {
                                            "locations": [
                                                {
                                                    "location": {
                                                        "physicalLocation": {
                                                            "artifactLocation": {
                                                                "uri": "src/app.js"
                                                            },
                                                            "region": {"startLine": 4},
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    ],
                }
            ],
        },
        "canary_report": {},
    }

    finding = _sarif_findings(payload, "eslint-sarif")[0]

    assert finding["evidence"]["thread_flow_step_count"] == 1
    assert finding["evidence"]["taxa"] == "CWE-95"
    assert finding["evidence"]["source_content_retained"] is False


def test_sarif_discloses_flow_truncation() -> None:
    evidence = _sarif_semantics(
        {"codeFlows": [{"threadFlows": [{"locations": []}]} for _ in range(65)]}
    )
    assert evidence["code_flow_count"] == 65
    assert evidence["code_flows_truncated"] is True


def test_database_transport_attests_negotiated_tls() -> None:
    class PGconn:
        ssl_in_use = True

    class Cursor:
        @staticmethod
        def fetchone() -> tuple[bool, str, str, int]:
            return True, "TLSv1.3", "TLS_AES_256_GCM_SHA384", 256

    class Connection:
        pgconn = PGconn()

        @staticmethod
        def execute(statement: str) -> Cursor:
            assert "pg_catalog.pg_stat_ssl" in statement
            return Cursor()

    _verify_negotiated_connection(Connection())
    Connection.pgconn.ssl_in_use = False
    with pytest.raises(ValueError, match="did not negotiate TLS"):
        _verify_negotiated_connection(Connection())
