from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.runtime_trace import runtime_trace_artifact
from py_security_suite.strict_json import canonical_bytes
from tests.deployment_authority import authority_environment, operation_receipt


def test_runtime_trace_must_correlate_to_static_edge(tmp_path: Path) -> None:
    evidence = tmp_path / "traces.json"
    graph = {"edges": [{"source": "api.py", "target": "db.py"}]}
    graph_sha256 = hashlib.sha256(canonical_bytes(graph["edges"])).hexdigest()
    edge_sha256 = hashlib.sha256(canonical_bytes(graph["edges"][0])).hexdigest()
    observed_at = datetime.now(UTC).isoformat()
    requirement = {
        "entry": "POST /transfer",
        "authorization_decision": "allow",
        "operation": "approve",
        "sink": "database",
        "source": "api.py",
        "target": "db.py",
    }
    traces = [
        {
            "trace_id": "1" * 32,
            "request_id": "request-1",
            "entry": "POST /transfer",
            "authorization_decision": "allow",
            "operation": "approve",
            "sink": "database",
            "sink_observed": True,
            "source": "api.py",
            "target": "db.py",
            "span_count": 4,
            "edge_sha256": edge_sha256,
            "started_at": observed_at,
            "ended_at": observed_at,
        }
    ]
    metrics = {
        "accepted_spans": 4,
        "refused_spans": 0,
        "sent_spans": 4,
        "failed_spans": 0,
        "canary_expected": 1,
        "canary_observed": 1,
    }
    collector_subject = {
        "schema_version": "1.0",
        "deployment_sha256": "a" * 64,
        "boundary_graph_sha256": graph_sha256,
        "collector_identity_sha256": "b" * 64,
        "metrics": metrics,
        "traces_sha256": hashlib.sha256(canonical_bytes(traces)).hexdigest(),
    }
    collector_receipt, collector_key = operation_receipt(
        collector_subject,
        purpose="runtime-collector-accounting",
        operation_id="collector-run-1",
    )
    evidence_document = {
        "schema_version": "1.0",
        "deployment_sha256": "a" * 64,
        "boundary_graph_sha256": graph_sha256,
        "collector_identity_sha256": "b" * 64,
        "instrumented_build_sha256": "d" * 64,
        "instrumentation_sha256": "e" * 64,
        "sampling_rate": 1.0,
        "coverage_requirements": [requirement],
        "collector_metrics": metrics,
        "collector_operation_receipt": collector_receipt,
        "traces": traces,
    }
    evidence_value = json.dumps(evidence_document)
    evidence.write_text(
        evidence_value,
        encoding="utf-8",
    )
    subject = evidence_document
    authority = authority_environment(
        tmp_path,
        subject,
        purpose="runtime-trace-evidence",
        prefix="PYSEC_RUNTIME_TRACE_AUTHORITY",
    )
    inventory_keys: dict[str, str] = {}
    inventories = []
    for index, kind in enumerate(
        ("api-contract", "deployment-route", "authorization-policy"), start=1
    ):
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        inventory_keys[kind] = hashlib.sha256(public).hexdigest()
        inventory_subject = {
            "schema_version": "1.0",
            "kind": kind,
            "artifact_sha256": str(index) * 64,
            "producer_identity_sha256": str(index + 3) * 64,
            "requirements": [requirement],
        }
        inventory_receipt, _ = operation_receipt(
            inventory_subject,
            purpose=f"runtime-route-inventory:{kind}",
            operation_id=f"inventory-{index}",
            private_key=private,
        )
        inventories.append(
            {**inventory_subject, "operation_receipt": inventory_receipt}
        )
    coverage_policy_value = {
        "schema_version": "1.0",
        "deployment_sha256": "a" * 64,
        "boundary_graph_sha256": graph_sha256,
        "producer_identity_sha256": "f" * 64,
        "requirements": [requirement],
        "source_inventories": inventories,
    }
    coverage_policy = tmp_path / "runtime-coverage-policy.json"
    coverage_policy.write_text(json.dumps(coverage_policy_value), encoding="utf-8")
    coverage_authority = authority_environment(
        tmp_path,
        coverage_policy_value,
        purpose="runtime-coverage-policy",
        prefix="PYSEC_RUNTIME_COVERAGE_AUTHORITY",
    )
    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_RUNTIME_TRACE_EVIDENCE_PATH": str(evidence),
                "PYSEC_RUNTIME_TRACE_EVIDENCE_SHA256": hashlib.sha256(
                    evidence.read_bytes()
                ).hexdigest(),
                "PYSEC_RUNTIME_DEPLOYMENT_SHA256": "a" * 64,
                "PYSEC_RUNTIME_TRACE_COLLECTOR_SHA256": "b" * 64,
                "PYSEC_RUNTIME_TRACE_BUILD_SHA256": "d" * 64,
                "PYSEC_RUNTIME_TRACE_INSTRUMENTATION_SHA256": "e" * 64,
                "PYSEC_RUNTIME_COVERAGE_POLICY_PATH": str(coverage_policy),
                "PYSEC_RUNTIME_COVERAGE_POLICY_SHA256": hashlib.sha256(
                    coverage_policy.read_bytes()
                ).hexdigest(),
                "PYSEC_RUNTIME_COVERAGE_POLICY_PRODUCER_SHA256": "f" * 64,
                "PYSEC_RUNTIME_INVENTORY_KEYS_JSON": json.dumps(inventory_keys),
                "PYSEC_RUNTIME_COLLECTOR_AUTHORITY_KEY_SHA256": collector_key,
                **authority,
                **coverage_authority,
            },
        ),
        patch(
            "py_security_suite.deployment_receipt._scan_observed_at",
            return_value=datetime.now(UTC),
        ),
    ):
        artifact = runtime_trace_artifact(graph)
    assert artifact["complete"] is True
    assert artifact["allow_count"] == 1
    validate_governed_artifacts({"runtime-trace-correlation.json": artifact})
