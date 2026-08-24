from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.runtime_trace import runtime_trace_artifact


def test_runtime_trace_must_correlate_to_static_edge(tmp_path: Path) -> None:
    evidence = tmp_path / "traces.json"
    evidence.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "deployment_sha256": "a" * 64,
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
        ),
        encoding="utf-8",
    )
    with patch.dict(
        "os.environ",
        {
            "PYSEC_RUNTIME_TRACE_EVIDENCE_PATH": str(evidence),
            "PYSEC_RUNTIME_TRACE_EVIDENCE_SHA256": hashlib.sha256(
                evidence.read_bytes()
            ).hexdigest(),
        },
    ):
        artifact = runtime_trace_artifact(
            {"edges": [{"source": "api.py", "target": "db.py"}]}
        )
    assert artifact["complete"] is True
    assert artifact["allow_count"] == 1
    validate_governed_artifacts({"runtime-trace-correlation.json": artifact})
