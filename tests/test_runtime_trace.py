from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.runtime_trace import runtime_trace_artifact
from py_security_suite.strict_json import canonical_bytes
from tests.deployment_authority import authority_environment


def test_runtime_trace_must_correlate_to_static_edge(tmp_path: Path) -> None:
    evidence = tmp_path / "traces.json"
    graph = {"edges": [{"source": "api.py", "target": "db.py"}]}
    graph_sha256 = hashlib.sha256(canonical_bytes(graph["edges"])).hexdigest()
    evidence_value = json.dumps(
        {
            "schema_version": "1.0",
            "deployment_sha256": "a" * 64,
            "boundary_graph_sha256": graph_sha256,
            "traces": [
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
                }
            ],
        }
    )
    evidence.write_text(
        evidence_value,
        encoding="utf-8",
    )
    subject = json.loads(evidence_value)
    authority = authority_environment(
        tmp_path,
        subject,
        purpose="runtime-trace-evidence",
        prefix="PYSEC_RUNTIME_TRACE_AUTHORITY",
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
                **authority,
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
