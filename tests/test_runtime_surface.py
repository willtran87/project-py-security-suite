from __future__ import annotations

import hashlib

from py_security_suite.models import ToolRun, ToolStatus
from py_security_suite.runtime_reachability import apply_runtime_trace_observations
from py_security_suite.runtime_surface import runtime_surface_binding_artifact
from py_security_suite.strict_json import canonical_bytes


def _run(tool: str) -> ToolRun:
    return ToolRun(
        tool=tool,
        status=ToolStatus.COMPLETED,
        command=[tool],
        duration_seconds=0.1,
    )


def _evidence(tool: str, producer: str, *, independent: bool = False) -> dict:
    digest = "a" * 64
    return {
        "kind": tool,
        "producer": producer,
        "findings": [],
        "context": {
            "surface_sha256": digest,
            "deployment_sha256": "b" * 64,
            "target_manifest_sha256": "c" * 64,
        },
        "execution": {
            "features": ["independent-collectors"] if independent else [],
            "canaries_expected": 1,
            "canaries_observed": 1,
        },
    }


def test_runtime_lanes_share_surface_and_independent_truth() -> None:
    runs = [_run("surface-inventory"), _run("zap"), _run("nuclei")]
    artifacts = {
        "surface-inventory-summary.json": _evidence(
            "surface-inventory", "inventory", independent=True
        ),
        "zap-summary.json": _evidence("zap", "zaproxy"),
        "nuclei-summary.json": _evidence("nuclei", "nuclei"),
    }
    result = runtime_surface_binding_artifact(runs, artifacts)
    assert result["complete"] is True
    assert result["truth_diversity_gaps"] == []


def test_runtime_surface_mismatch_and_single_producer_fail_closed() -> None:
    runs = [_run("surface-inventory"), _run("zap")]
    artifacts = {
        "surface-inventory-summary.json": _evidence(
            "surface-inventory", "inventory", independent=True
        ),
        "zap-summary.json": _evidence("zap", "inventory"),
    }
    artifacts["zap-summary.json"]["context"]["surface_sha256"] = "d" * 64
    result = runtime_surface_binding_artifact(runs, artifacts)
    assert result["complete"] is False
    assert result["mismatched_context_lanes"] == ["zap"]
    assert result["truth_diversity_gaps"] == ["zap"]


def test_authenticated_runtime_edge_marks_exact_reachability_node_observed() -> None:
    edge = {
        "source": "src/app.py",
        "line": 8,
        "kind": "network-endpoint",
        "target": "https://example.invalid",
    }
    edge_sha256 = hashlib.sha256(canonical_bytes(edge)).hexdigest()
    reachability = {
        "nodes": [
            {
                "id": "symbol:src.app:handler",
                "path": "src/app.py",
                "start_line": 4,
                "end_line": 12,
                "state": "executable",
                "runtime_observation": "not-measured",
            }
        ],
        "summary": {},
    }
    trace = {
        "complete": True,
        "traces": [{"edge_sha256": edge_sha256}],
    }
    result = apply_runtime_trace_observations(reachability, trace, {"edges": [edge]})
    assert result["complete"] is True
    assert result["matched_trace_count"] == 1
    assert reachability["nodes"][0]["runtime_observation"] == "observed"
    assert reachability["summary"]["observed_executable_nodes"] == 1
