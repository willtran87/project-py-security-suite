from __future__ import annotations

import base64
import hashlib
import os
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from .path_safety import read_regular_file
from .strict_json import canonical_bytes, loads as strict_loads
from .deployment_receipt import verify_deployment_receipt
from .operation_receipt import verify_operation_receipt
from .failure_domain import (
    require_independent_failure_domains,
    verify_registered_failure_domain,
)


def runtime_trace_artifact(boundary_graph: dict[str, Any]) -> dict[str, Any]:
    """Correlate deployment-pinned request traces with retained static edges."""

    raw_path = os.environ.get("PYSEC_RUNTIME_TRACE_EVIDENCE_PATH", "").strip()
    expected = (
        os.environ.get("PYSEC_RUNTIME_TRACE_EVIDENCE_SHA256", "").strip().casefold()
    )
    if not raw_path and not expected:
        return _artifact([], "", "", "", None, None, None, None, [], False)
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
        or set(value)
        != {
            "schema_version",
            "deployment_sha256",
            "boundary_graph_sha256",
            "collector_identity_sha256",
            "collector_failure_domain",
            "instrumented_build_sha256",
            "instrumentation_sha256",
            "sampling_rate",
            "coverage_requirements",
            "collector_metrics",
            "collector_operation_receipt",
            "collector_authority_key_sha256",
            "collector_config",
            "collector_config_sha256",
            "instrumentation_manifest",
            "instrumentation_manifest_sha256",
            "raw_spans",
            "raw_spans_sha256",
            "independent_observer_identity_sha256",
            "independent_failure_domain",
            "independent_observations",
            "independent_raw_spans",
            "independent_raw_spans_sha256",
            "independent_observer_config",
            "independent_observer_config_sha256",
            "independent_operation_receipt",
            "independent_authority_key_sha256",
            "traces",
        }
        or value.get("schema_version") != "1.0"
        or not _digest(str(value.get("deployment_sha256") or ""))
        or not isinstance(value.get("traces"), list)
        or not 1 <= len(value["traces"]) <= 100_000
        or value.get("sampling_rate") != 1.0
        or not isinstance(value.get("coverage_requirements"), list)
        or not 1 <= len(value["coverage_requirements"]) <= 100_000
        or not isinstance(value.get("collector_metrics"), dict)
        or value.get("collector_config_sha256")
        != hashlib.sha256(canonical_bytes(value.get("collector_config"))).hexdigest()
        or value.get("instrumentation_manifest_sha256")
        != hashlib.sha256(
            canonical_bytes(value.get("instrumentation_manifest"))
        ).hexdigest()
        or value.get("raw_spans_sha256")
        != hashlib.sha256(canonical_bytes(value.get("raw_spans"))).hexdigest()
        or not isinstance(value.get("raw_spans"), list)
        or not isinstance(value.get("independent_observations"), list)
        or value.get("independent_raw_spans_sha256")
        != hashlib.sha256(
            canonical_bytes(value.get("independent_raw_spans"))
        ).hexdigest()
        or value.get("independent_observer_config_sha256")
        != hashlib.sha256(
            canonical_bytes(value.get("independent_observer_config"))
        ).hexdigest()
    ):
        raise ValueError("runtime trace evidence fields do not match")
    deployment = (
        os.environ.get("PYSEC_RUNTIME_DEPLOYMENT_SHA256", "").strip().casefold()
    )
    graph_digest = str(boundary_graph.get("graph_sha256") or "")
    if not graph_digest:
        graph_digest = hashlib.sha256(
            canonical_bytes(boundary_graph.get("edges") or [])
        ).hexdigest()
    if (
        not _digest(deployment)
        or value["deployment_sha256"] != deployment
        or value["boundary_graph_sha256"] != graph_digest
    ):
        raise ValueError("runtime trace evidence is not bound to this deployment graph")
    for field, environment in (
        ("collector_identity_sha256", "PYSEC_RUNTIME_TRACE_COLLECTOR_SHA256"),
        ("instrumented_build_sha256", "PYSEC_RUNTIME_TRACE_BUILD_SHA256"),
        ("instrumentation_sha256", "PYSEC_RUNTIME_TRACE_INSTRUMENTATION_SHA256"),
    ):
        expected_identity = os.environ.get(environment, "").strip().casefold()
        if not _digest(expected_identity) or value[field] != expected_identity:
            raise ValueError("runtime trace producer identity is not deployment-pinned")
    authority = verify_deployment_receipt(
        value,
        purpose="runtime-trace-evidence",
        environment_prefix="PYSEC_RUNTIME_TRACE_AUTHORITY",
    )
    coverage_policy, coverage_authority = _coverage_policy(deployment, graph_digest)
    if value["coverage_requirements"] != coverage_policy["requirements"]:
        raise ValueError(
            "runtime trace route denominator differs from independent policy"
        )
    authority_issued = _timestamp(
        str(authority["statement"]["issued_at"]), "runtime authority issued_at"
    )
    static_edges = {
        hashlib.sha256(canonical_bytes(edge)).hexdigest(): edge
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
        "edge_sha256",
        "started_at",
        "ended_at",
    }
    for item in value["traces"]:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("runtime trace record fields do not match")
        trace_id = str(item["trace_id"])
        source, target = str(item["source"]), str(item["target"])
        edge = static_edges.get(str(item["edge_sha256"]))
        started = _timestamp(str(item["started_at"]), "runtime trace started_at")
        ended = _timestamp(str(item["ended_at"]), "runtime trace ended_at")
        if (
            trace_id in identities
            or not 16 <= len(trace_id) <= 64
            or item["authorization_decision"] not in {"allow", "deny"}
            or not isinstance(item["sink_observed"], bool)
            or (
                item["authorization_decision"] == "deny"
                and item["sink_observed"] is not False
            )
            or (
                item["authorization_decision"] == "allow"
                and item["sink_observed"] is not True
            )
            or not isinstance(edge, dict)
            or edge.get("source") != source
            or edge.get("target") != target
            or started > ended
            or ended - started > timedelta(hours=24)
            or ended > authority_issued
            or authority_issued - started > timedelta(hours=24)
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
    requirement_fields = {
        "entry",
        "authorization_decision",
        "operation",
        "sink",
        "source",
        "target",
    }
    requirements: list[dict[str, str]] = []
    for item in value["coverage_requirements"]:
        if (
            not isinstance(item, dict)
            or set(item) != requirement_fields
            or item["authorization_decision"] not in {"allow", "deny"}
            or any(not isinstance(item[name], str) or not item[name] for name in item)
        ):
            raise ValueError("runtime trace coverage requirement is invalid")
        requirements.append(dict(item))
    if requirements != sorted(
        requirements,
        key=lambda item: tuple(item[name] for name in sorted(requirement_fields)),
    ) or len({canonical_bytes(item) for item in requirements}) != len(requirements):
        raise ValueError("runtime trace coverage requirements are not canonical")
    observed = {
        canonical_bytes({name: trace[name] for name in requirement_fields})
        for trace in traces
    }
    missing = [item for item in requirements if canonical_bytes(item) not in observed]
    if missing:
        raise ValueError("runtime trace evidence does not cover every required route")
    _verify_raw_spans(value["raw_spans"], traces)
    span_total = sum(int(item["span_count"]) for item in traces)
    metrics = value["collector_metrics"]
    if (
        set(metrics)
        != {
            "accepted_spans",
            "refused_spans",
            "sent_spans",
            "failed_spans",
            "canary_expected",
            "canary_observed",
        }
        or any(
            isinstance(metrics[name], bool)
            or not isinstance(metrics[name], int)
            or metrics[name] < 0
            for name in metrics
        )
        or metrics["accepted_spans"] != span_total
        or metrics["sent_spans"] != span_total
        or metrics["refused_spans"] != 0
        or metrics["failed_spans"] != 0
        or metrics["canary_expected"] < 1
        or metrics["canary_observed"] != metrics["canary_expected"]
    ):
        raise ValueError("runtime collector loss and canary accounting is incomplete")
    challenge = (
        os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    )
    collector_key = (
        os.environ.get("PYSEC_RUNTIME_COLLECTOR_AUTHORITY_KEY_SHA256", "")
        .strip()
        .casefold()
    )
    if value["collector_authority_key_sha256"] != collector_key:
        raise ValueError("runtime collector authority key is detached from evidence")
    collector_subject = {
        "schema_version": "1.0",
        "deployment_sha256": deployment,
        "boundary_graph_sha256": graph_digest,
        "collector_identity_sha256": value["collector_identity_sha256"],
        "failure_domain": value["collector_failure_domain"],
        "metrics": metrics,
        "traces_sha256": hashlib.sha256(canonical_bytes(value["traces"])).hexdigest(),
    }
    if not _digest(collector_key):
        raise ValueError("runtime collector authority is not deployment-pinned")
    verify_operation_receipt(
        collector_subject,
        value["collector_operation_receipt"],
        purpose="runtime-collector-accounting",
        observed_at=authority_issued,
        challenge_sha256=challenge,
        expected_key_sha256=collector_key,
    )
    _verify_independent_runtime_observations(
        value,
        traces,
        deployment=deployment,
        graph_digest=graph_digest,
        observed_at=authority_issued,
        challenge=challenge,
    )
    return _artifact(
        sorted(traces, key=lambda item: str(item["trace_id"])),
        expected,
        deployment,
        graph_digest,
        authority,
        coverage_policy,
        coverage_authority,
        value,
        requirements,
        True,
    )


def _verify_raw_spans(raw_spans: object, traces: list[dict[str, Any]]) -> None:
    fields = {
        "trace_id",
        "span_id",
        "parent_span_id",
        "process_identity_sha256",
        "operation",
    }
    if not isinstance(raw_spans, list) or len(raw_spans) > 1_000_000:
        raise ValueError("runtime raw span ledger is invalid")
    known_traces = {str(item["trace_id"]): item for item in traces}
    spans: dict[str, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    for item in raw_spans:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("runtime raw span fields do not match")
        trace_id = str(item["trace_id"])
        span_id = str(item["span_id"])
        if (
            trace_id not in known_traces
            or not span_id
            or span_id in spans
            or not _digest(str(item["process_identity_sha256"]))
            or item["operation"] != known_traces[trace_id]["operation"]
        ):
            raise ValueError("runtime raw span is detached from its trace")
        spans[span_id] = item
        counts[trace_id] = counts.get(trace_id, 0) + 1
    for span in spans.values():
        parent = str(span["parent_span_id"])
        if parent and (
            parent not in spans or spans[parent]["trace_id"] != span["trace_id"]
        ):
            raise ValueError("runtime raw span parent is missing or cross-trace")
    if any(
        counts.get(trace_id, 0) != trace["span_count"]
        for trace_id, trace in known_traces.items()
    ):
        raise ValueError("runtime raw span accounting does not match trace summaries")


def _verify_independent_runtime_observations(
    value: dict[str, Any],
    traces: list[dict[str, Any]],
    *,
    deployment: str,
    graph_digest: str,
    observed_at: Any,
    challenge: str,
) -> None:
    observations = value["independent_observations"]
    independent_spans = value["independent_raw_spans"]
    require_independent_failure_domains(
        value["collector_failure_domain"],
        value["independent_failure_domain"],
        labels=("runtime collector", "runtime observer"),
    )
    _verify_raw_spans(independent_spans, traces)
    if {canonical_bytes(item) for item in independent_spans} != {
        canonical_bytes(item) for item in value["raw_spans"]
    }:
        raise ValueError("independent raw telemetry disagrees with collector spans")
    observer_config = value["independent_observer_config"]
    _verify_independent_observer_config(
        observer_config, independent_spans, value["collector_identity_sha256"]
    )
    fields = {
        "trace_id",
        "span_count",
        "sink_observed",
        "process_identity_sha256",
        "kernel_identity_sha256",
    }
    by_trace: dict[str, dict[str, Any]] = {}
    for item in observations:
        if (
            not isinstance(item, dict)
            or set(item) != fields
            or str(item["trace_id"]) in by_trace
            or not _digest(str(item["process_identity_sha256"]))
            or not _digest(str(item["kernel_identity_sha256"]))
        ):
            raise ValueError("independent runtime observation is invalid")
        by_trace[str(item["trace_id"])] = item
    if set(by_trace) != {str(item["trace_id"]) for item in traces} or any(
        by_trace[str(trace["trace_id"])]["span_count"] != trace["span_count"]
        or by_trace[str(trace["trace_id"])]["sink_observed"]
        is not trace["sink_observed"]
        for trace in traces
    ):
        raise ValueError("independent runtime observations disagree with traces")
    expected_key = (
        os.environ.get("PYSEC_RUNTIME_INDEPENDENT_AUTHORITY_KEY_SHA256", "")
        .strip()
        .casefold()
    )
    if (
        not _digest(expected_key)
        or value["independent_authority_key_sha256"] != expected_key
        or not _digest(str(value["independent_observer_identity_sha256"]))
        or value["independent_observer_identity_sha256"]
        == value["collector_identity_sha256"]
    ):
        raise ValueError("independent runtime observer is not deployment-pinned")
    verify_registered_failure_domain(
        value["independent_failure_domain"],
        expected_key,
        "runtime observer",
    )
    subject = {
        "schema_version": "1.0",
        "deployment_sha256": deployment,
        "boundary_graph_sha256": graph_digest,
        "observer_identity_sha256": value["independent_observer_identity_sha256"],
        "instrumented_build_sha256": value["instrumented_build_sha256"],
        "observations_sha256": hashlib.sha256(
            canonical_bytes(observations)
        ).hexdigest(),
        "raw_spans_sha256": value["independent_raw_spans_sha256"],
        "observer_config_sha256": value["independent_observer_config_sha256"],
        "failure_domain": value["independent_failure_domain"],
    }
    verify_operation_receipt(
        subject,
        value["independent_operation_receipt"],
        purpose="runtime-independent-observation",
        observed_at=observed_at,
        challenge_sha256=challenge,
        expected_key_sha256=expected_key,
    )


def _verify_independent_observer_config(
    observer_config: object,
    independent_spans: list[dict[str, Any]],
    collector_identity_sha256: str,
) -> None:
    if (
        not isinstance(observer_config, dict)
        or set(observer_config)
        != {
            "schema_version",
            "channel",
            "collector_identity_sha256",
            "observer_executable_sha256",
            "observer_runtime_sha256",
            "configuration_base64",
            "configuration_sha256",
            "sequence_start",
            "sequence_end",
            "dropped_events",
            "clock_source",
            "source_boot_id_sha256",
            "event_ledger",
            "event_ledger_sha256",
            "batch_merkle_root_sha256",
            "canary_event",
        }
        or observer_config.get("schema_version") != "1.0"
        or observer_config.get("channel")
        not in {"kernel-audit", "service-mesh-tap", "independent-otlp"}
        or not _digest(str(observer_config.get("collector_identity_sha256") or ""))
        or observer_config["collector_identity_sha256"] == collector_identity_sha256
        or not _digest(str(observer_config.get("observer_executable_sha256") or ""))
        or not _digest(str(observer_config.get("observer_runtime_sha256") or ""))
        or observer_config.get("sequence_start") != 1
        or observer_config.get("sequence_end") != len(independent_spans)
        or observer_config.get("dropped_events") != 0
        or observer_config.get("clock_source") != "kernel-monotonic"
        or not _digest(str(observer_config.get("source_boot_id_sha256") or ""))
    ):
        raise ValueError("independent runtime observer channel is invalid")
    try:
        observer_configuration = base64.b64decode(
            str(observer_config["configuration_base64"]), validate=True
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "independent runtime observer configuration is invalid"
        ) from exc
    if (
        not observer_configuration
        or len(observer_configuration) > 1024 * 1024
        or hashlib.sha256(observer_configuration).hexdigest()
        != observer_config["configuration_sha256"]
    ):
        raise ValueError("independent runtime observer configuration is detached")
    _verify_observer_event_ledger(observer_config, independent_spans)


def _verify_observer_event_ledger(
    observer_config: dict[str, Any], independent_spans: list[dict[str, Any]]
) -> None:
    ledger = observer_config["event_ledger"]
    fields = {
        "sequence",
        "trace_id",
        "span_id",
        "monotonic_ns",
        "source_event_sha256",
    }
    if (
        not isinstance(ledger, list)
        or len(ledger) != len(independent_spans)
        or observer_config["event_ledger_sha256"]
        != hashlib.sha256(canonical_bytes(ledger)).hexdigest()
    ):
        raise ValueError("independent runtime event ledger is detached")
    boot_id = observer_config["source_boot_id_sha256"]
    event_hashes: list[str] = []
    previous_monotonic = -1
    for sequence, (event, span) in enumerate(
        zip(ledger, independent_spans, strict=True), start=1
    ):
        if (
            not isinstance(event, dict)
            or set(event) != fields
            or event.get("sequence") != sequence
            or event.get("trace_id") != span["trace_id"]
            or event.get("span_id") != span["span_id"]
            or isinstance(event.get("monotonic_ns"), bool)
            or not isinstance(event.get("monotonic_ns"), int)
            or event["monotonic_ns"] <= previous_monotonic
        ):
            raise ValueError("independent runtime event sequence is invalid")
        expected = hashlib.sha256(
            canonical_bytes(
                {
                    "source_boot_id_sha256": boot_id,
                    "monotonic_ns": event["monotonic_ns"],
                    "span": span,
                }
            )
        ).hexdigest()
        if event.get("source_event_sha256") != expected:
            raise ValueError("independent runtime source event is detached")
        previous_monotonic = event["monotonic_ns"]
        event_hashes.append(expected)
    if observer_config["batch_merkle_root_sha256"] != _merkle_root(event_hashes):
        raise ValueError("independent runtime event batch root is invalid")
    canary = observer_config["canary_event"]
    challenge = os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    if (
        not isinstance(canary, dict)
        or set(canary) != {"challenge_sha256", "source_event_sha256", "observed"}
        or canary.get("challenge_sha256") != challenge
        or not _digest(str(canary.get("source_event_sha256") or ""))
        or canary.get("observed") is not True
        or canary["source_event_sha256"] in event_hashes
    ):
        raise ValueError("independent runtime observer canary is invalid")


def _merkle_root(digests: list[str]) -> str:
    nodes = [bytes.fromhex(item) for item in digests]
    if not nodes:
        return hashlib.sha256(b"").hexdigest()
    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [
            hashlib.sha256(nodes[index] + nodes[index + 1]).digest()
            for index in range(0, len(nodes), 2)
        ]
    return nodes[0].hex()


def _artifact(
    traces: list[dict[str, Any]],
    evidence_sha256: str,
    deployment_sha256: str,
    boundary_graph_sha256: str,
    authority_receipt: dict[str, Any] | None,
    coverage_policy: dict[str, Any] | None,
    coverage_policy_authority_receipt: dict[str, Any] | None,
    evidence: dict[str, Any] | None,
    coverage_requirements: list[dict[str, str]],
    complete: bool,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "analysis": "deployment-pinned-request-to-sink-runtime-correlation",
        "complete": complete,
        "evidence_sha256": evidence_sha256,
        "deployment_sha256": deployment_sha256,
        "boundary_graph_sha256": boundary_graph_sha256,
        "authority_receipt": authority_receipt,
        "coverage_policy": coverage_policy,
        "coverage_policy_authority_receipt": coverage_policy_authority_receipt,
        "evidence": evidence,
        "coverage_requirements": coverage_requirements,
        "coverage_required": len(coverage_requirements),
        "coverage_observed": len(coverage_requirements) if complete else 0,
        "coverage_percent": 100.0 if complete else 0.0,
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


def _coverage_policy(
    deployment_sha256: str, boundary_graph_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_path = os.environ.get("PYSEC_RUNTIME_COVERAGE_POLICY_PATH", "").strip()
    expected = (
        os.environ.get("PYSEC_RUNTIME_COVERAGE_POLICY_SHA256", "").strip().casefold()
    )
    producer = (
        os.environ.get("PYSEC_RUNTIME_COVERAGE_POLICY_PRODUCER_SHA256", "")
        .strip()
        .casefold()
    )
    if not raw_path or not _digest(expected) or not _digest(producer):
        raise ValueError("runtime coverage policy configuration is incomplete")
    path = Path(raw_path).expanduser().resolve()
    _, payload = read_regular_file(
        path, "runtime coverage policy", maximum_bytes=16 * 1024 * 1024
    )
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError("runtime coverage policy does not match its deployment pin")
    value = strict_loads(payload)
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "deployment_sha256",
            "boundary_graph_sha256",
            "producer_identity_sha256",
            "requirements",
            "source_inventories",
        }
        or value.get("schema_version") != "1.0"
        or value.get("deployment_sha256") != deployment_sha256
        or value.get("boundary_graph_sha256") != boundary_graph_sha256
        or value.get("producer_identity_sha256") != producer
        or not isinstance(value.get("requirements"), list)
        or not isinstance(value.get("source_inventories"), list)
        or len(value["source_inventories"]) != 3
    ):
        raise ValueError("runtime coverage policy fields do not match")
    try:
        inventory_keys = json.loads(
            os.environ.get("PYSEC_RUNTIME_INVENTORY_KEYS_JSON", "")
        )
    except json.JSONDecodeError as exc:
        raise ValueError("runtime inventory authority pins are invalid") from exc
    authority = verify_deployment_receipt(
        value,
        purpose="runtime-coverage-policy",
        environment_prefix="PYSEC_RUNTIME_COVERAGE_AUTHORITY",
    )
    kinds = {"api-contract", "deployment-route", "authorization-policy"}
    inventory_requirements: set[bytes] = set()
    seen: set[str] = set()
    challenge = (
        os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    )
    observed_at = _timestamp(
        str(authority["statement"]["issued_at"]),
        "runtime coverage authority issued_at",
    )
    for inventory in value["source_inventories"]:
        fields = {
            "schema_version",
            "kind",
            "artifact_sha256",
            "source_artifact",
            "producer_identity_sha256",
            "authority_key_sha256",
            "requirements",
            "operation_receipt",
        }
        if (
            not isinstance(inventory, dict)
            or set(inventory) != fields
            or inventory.get("schema_version") != "1.0"
            or inventory.get("kind") not in kinds
            or inventory["kind"] in seen
            or not _digest(str(inventory.get("artifact_sha256") or ""))
            or inventory["artifact_sha256"]
            != hashlib.sha256(canonical_bytes(inventory["source_artifact"])).hexdigest()
            or not _digest(str(inventory.get("producer_identity_sha256") or ""))
            or not isinstance(inventory.get("requirements"), list)
            or not isinstance(inventory_keys, dict)
            or not _digest(str(inventory_keys.get(inventory["kind"]) or ""))
            or inventory["authority_key_sha256"] != inventory_keys[inventory["kind"]]
            or not _runtime_source_artifact_valid(
                inventory["kind"],
                inventory["source_artifact"],
                inventory["requirements"],
            )
        ):
            raise ValueError("runtime source inventory is invalid")
        subject = {
            name: item
            for name, item in inventory.items()
            if name != "operation_receipt"
        }
        verify_operation_receipt(
            subject,
            inventory["operation_receipt"],
            purpose=f"runtime-route-inventory:{inventory['kind']}",
            observed_at=observed_at,
            challenge_sha256=challenge,
            expected_key_sha256=str(inventory_keys[inventory["kind"]]),
        )
        seen.add(str(inventory["kind"]))
        inventory_requirements.update(
            canonical_bytes(item) for item in inventory["requirements"]
        )
    if seen != kinds or inventory_requirements != {
        canonical_bytes(item) for item in value["requirements"]
    }:
        raise ValueError("runtime denominator omits or adds inventoried routes")
    return value, authority


def _runtime_source_artifact_valid(
    kind: str, value: object, requirements: object
) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value) == {"schema_version", "kind", "routes"}
        and value.get("schema_version") == "1.0"
        and value.get("kind") == kind
        and isinstance(requirements, list)
        and value.get("routes") == requirements
    )


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _timestamp(value: str, label: str):
    from datetime import UTC, datetime

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)
