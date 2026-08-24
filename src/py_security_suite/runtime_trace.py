from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from .path_safety import read_regular_file
from .strict_json import loads as strict_loads


def runtime_trace_artifact(boundary_graph: dict[str, Any]) -> dict[str, Any]:
    """Correlate deployment-pinned request traces with retained static edges."""

    raw_path = os.environ.get("PYSEC_RUNTIME_TRACE_EVIDENCE_PATH", "").strip()
    expected = (
        os.environ.get("PYSEC_RUNTIME_TRACE_EVIDENCE_SHA256", "").strip().casefold()
    )
    if not raw_path and not expected:
        return _artifact([], "", False)
    if not raw_path or not _digest(expected):
        raise ValueError("runtime trace evidence configuration is incomplete")
    path = Path(raw_path).expanduser().resolve()
    _, payload = read_regular_file(
        path, "runtime trace evidence", maximum_bytes=32 * 1024 * 1024
    )
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError("runtime trace evidence does not match its deployment pin")
    value = strict_loads(payload)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "deployment_sha256", "traces"}
        or value.get("schema_version") != "1.0"
        or not _digest(str(value.get("deployment_sha256") or ""))
        or not isinstance(value.get("traces"), list)
        or not 1 <= len(value["traces"]) <= 100_000
    ):
        raise ValueError("runtime trace evidence fields do not match")
    static_edges = {
        (str(edge.get("source") or ""), str(edge.get("target") or ""))
        for edge in boundary_graph.get("edges", [])
        if isinstance(edge, dict)
    }
    traces: list[dict[str, Any]] = []
    identities: set[str] = set()
    fields = {
        "trace_id",
        "request_id",
        "entry",
        "authorization_decision",
        "operation",
        "sink",
        "sink_observed",
        "source",
        "target",
        "span_count",
    }
    for item in value["traces"]:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("runtime trace record fields do not match")
        trace_id = str(item["trace_id"])
        source, target = str(item["source"]), str(item["target"])
        if (
            trace_id in identities
            or not 16 <= len(trace_id) <= 64
            or item["authorization_decision"] not in {"allow", "deny"}
            or not isinstance(item["sink_observed"], bool)
            or (
                item["authorization_decision"] == "deny"
                and item["sink_observed"] is not False
            )
            or (source, target) not in static_edges
            or isinstance(item["span_count"], bool)
            or not isinstance(item["span_count"], int)
            or not 1 <= item["span_count"] <= 100_000
            or any(
                not str(item[name]).strip()
                for name in ("request_id", "entry", "operation", "sink")
            )
        ):
            raise ValueError("runtime trace record is not bound to the static graph")
        identities.add(trace_id)
        traces.append(dict(item))
    return _artifact(
        sorted(traces, key=lambda item: str(item["trace_id"])), expected, True
    )


def _artifact(
    traces: list[dict[str, Any]], evidence_sha256: str, complete: bool
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "analysis": "deployment-pinned-request-to-sink-runtime-correlation",
        "complete": complete,
        "evidence_sha256": evidence_sha256,
        "trace_count": len(traces),
        "allow_count": sum(
            item["authorization_decision"] == "allow" for item in traces
        ),
        "deny_count": sum(item["authorization_decision"] == "deny" for item in traces),
        "traces": traces,
        "limitations": []
        if complete
        else ["Deployment-pinned runtime trace evidence was not supplied."],
    }


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
