from __future__ import annotations

import argparse
import hashlib
import os
import ssl
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

try:
    from companion.file_safety import read_bounded_regular
    from companion.evidence_authority import verify_authority_quorum
    from companion.strict_json import canonical_bytes
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
    from companion.trusted_time import verify_rfc3161
except ModuleNotFoundError:  # Direct script execution.
    from file_safety import read_bounded_regular  # type: ignore[import-not-found,no-redef]
    from evidence_authority import verify_authority_quorum  # type: ignore[import-not-found,no-redef]
    from strict_json import canonical_bytes  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]
    from trusted_time import verify_rfc3161  # type: ignore[import-not-found,no-redef]


_AREAS = {
    "ai": "ai-independent-adjudication",
    "browser": "browser-active-abuse-matrix",
    "ci": "ci-isolated-supply-chain",
    "kafka": "kafka-authz-durability-failover",
    "postgresql": "postgresql-transport-rls-recovery",
    "sarif": "sarif-full-fidelity",
    "supply-chain": "composed-slsa-sigstore-vsa",
    "surface": "surface-server-receipts-history",
    "trust-state": "distributed-transparent-checkpoint",
}


def verify_area_receipt(
    context: Path,
    *,
    area: str,
    filename: object,
    sha256: object,
    target: object,
) -> dict[str, Any]:
    """Verify one quorum-signed, contextual, replay-protected area receipt."""
    if area not in _AREAS:
        raise ValueError("deep qualification area is unknown")
    manifest_path, _digest_value = _pinned_sibling(
        context, filename, sha256, 8 * 1024 * 1024
    )
    expected = _deployment_context(target)
    result = qualify(manifest_path, expected_context=expected, requested_area=area)
    return dict(result["areas"][area]["metrics"])


def qualify(
    path: Path,
    *,
    expected_context: dict[str, Any] | None = None,
    requested_area: str | None = None,
    consume_replay: bool = True,
) -> dict[str, Any]:
    """Verify pinned, independently signed receipts for every deep-assurance area."""
    value = _read_json(path, maximum=1024 * 1024)
    required = {"schema_version", "context", "trusted_time", "areas"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("deep qualification manifest fields do not match")
    if value.get("schema_version") != "2.0":
        raise ValueError("deep qualification schema_version must be 2.0")
    qualification_context = _qualification_context(value.get("context"))
    context_sha256 = hashlib.sha256(canonical_bytes(qualification_context)).hexdigest()
    trusted_time = verify_rfc3161(path, value.get("trusted_time"), context_sha256)
    observed_at = _timestamp(
        trusted_time["trusted_time_observed_at"], "qualification trusted time"
    )
    issued_at = _timestamp(qualification_context["issued_at"], "issued_at")
    expires_at = _timestamp(qualification_context["expires_at"], "expires_at")
    if not issued_at <= observed_at <= expires_at or expires_at - issued_at > timedelta(
        hours=24
    ):
        raise ValueError("qualification validity is detached from trusted time")
    if expected_context is not None and any(
        qualification_context.get(name) != expected_context.get(name)
        for name in (
            "run_id",
            "environment_sha256",
            "target_sha256",
            "source_sha256",
            "profile_sha256",
            "profile_generation",
            "trust_policy_sha256",
        )
    ):
        raise ValueError("qualification manifest does not match the active run context")
    if requested_area is not None and requested_area not in _AREAS:
        raise ValueError("deep qualification area is unknown")
    entries = value.get("areas")
    if not isinstance(entries, list) or len(entries) != len(_AREAS):
        raise ValueError("deep qualification manifest must cover every assurance area")
    threshold = _environment_integer("PYSEC_QUALIFICATION_AUTHORITY_THRESHOLD", 2)
    if not 2 <= threshold <= 16:
        raise ValueError("deep qualification authority threshold is invalid")
    observed: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "area",
            "file",
            "sha256",
            "authorities",
        }:
            raise ValueError("deep qualification area fields do not match")
        area = str(entry.get("area") or "")
        if area not in _AREAS or area in observed:
            raise ValueError("deep qualification area is unknown or duplicated")
        receipt_path, receipt_sha256 = _pinned_sibling(
            path, entry.get("file"), entry.get("sha256"), 8 * 1024 * 1024
        )
        receipt_value = _read_json(receipt_path, maximum=8 * 1024 * 1024)
        receipt = _validate_area(area, receipt_value, receipt_path)
        subject = {
            "area": area,
            "receipt_sha256": receipt_sha256,
            "feature": _AREAS[area],
            "context_sha256": context_sha256,
        }
        authority_values = entry.get("authorities")
        if not isinstance(authority_values, list) or any(
            not isinstance(item, dict) or item.get("schema_version") != "2.0"
            for item in authority_values
        ):
            raise ValueError(
                "deep qualification requires lifecycle-bound v2 authorities"
            )
        authorities = verify_authority_quorum(
            path,
            authority_values,
            purpose=f"deep-qualification:{area}",
            subject=subject,
            minimum_signatures=threshold,
            at=observed_at,
        )
        observed[area] = {
            "receipt_sha256": receipt_sha256,
            "feature": _AREAS[area],
            "signers": sorted(item["signer_id"] for item in authorities),
            "collectors": sorted(item["collector_id"] for item in authorities),
            "organizations": sorted(item["organization"] for item in authorities),
            "metrics": receipt,
        }
    if set(observed) != set(_AREAS):
        raise ValueError("deep qualification manifest is incomplete")
    if requested_area is not None and requested_area not in observed:
        raise ValueError("requested qualification area is absent")
    if consume_replay:
        _consume_replay(
            qualification_context,
            context_sha256=context_sha256,
            scope=requested_area or "all",
        )
    return {
        "schema_version": "2.0",
        "status": "passed",
        "areas": observed,
        "features": sorted(_AREAS.values()),
        "manifest_sha256": hashlib.sha256(
            read_bounded_regular(path, 1024 * 1024, "qualification manifest")
        ).hexdigest(),
        "context": qualification_context,
        "context_sha256": context_sha256,
        "trusted_time": trusted_time,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify signed deep-assurance qualification receipts."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--expected-context",
        type=Path,
        help="pinned active run context that must match the qualification manifest",
    )
    args = parser.parse_args(argv)
    expected = (
        _qualification_context(_read_json(args.expected_context, maximum=1024 * 1024))
        if args.expected_context
        else None
    )
    _write(args.output, qualify(args.manifest, expected_context=expected))
    return 0


def _browser(value: object) -> dict[str, Any]:
    required = {"schema_version", "engines", "authenticated_roles", "probes"}
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
    ):
        raise ValueError("browser qualification receipt is invalid")
    if set(_strings(value.get("engines"), "browser engines")) != {
        "chromium",
        "firefox",
        "webkit",
    }:
        raise ValueError("browser qualification must exercise all supported engines")
    if _integer(value.get("authenticated_roles"), "authenticated roles") < 2:
        raise ValueError(
            "browser qualification requires at least two authenticated roles"
        )
    expected = {
        "csrf",
        "dom-xss",
        "postmessage-origin",
        "session-fixation",
        "cross-tenant",
        "service-worker-cache",
        "websocket-authz",
    }
    probes = _passed_cases(value.get("probes"), "browser probe")
    if set(probes) != expected:
        raise ValueError("browser qualification active probe coverage is incomplete")
    return {
        "engine_count": 3,
        "role_count": value["authenticated_roles"],
        "probe_count": len(probes),
    }


def _kafka(value: object) -> dict[str, Any]:
    required = {
        "schema_version",
        "tls_version",
        "sasl_mechanism",
        "acl_resources",
        "durability",
        "tests",
        "schema_formats",
        "key_and_headers_validated",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
    ):
        raise ValueError("Kafka qualification receipt is invalid")
    if value.get("tls_version") != "TLSv1.3" or value.get("sasl_mechanism") not in {
        "SCRAM-SHA-512",
        "OAUTHBEARER",
    }:
        raise ValueError("Kafka qualification requires TLS 1.3 and strong SASL")
    if set(_strings(value.get("acl_resources"), "Kafka ACL resources")) != {
        "cluster",
        "group",
        "topic",
        "transactional-id",
    }:
        raise ValueError("Kafka ACL qualification is incomplete")
    durability = value.get("durability")
    if not isinstance(durability, dict) or set(durability) != {
        "acks",
        "min_insync_replicas",
        "replication_factor",
    }:
        raise ValueError("Kafka durability receipt is invalid")
    if (
        durability.get("acks") != "all"
        or _integer(durability.get("min_insync_replicas"), "minimum ISR") < 2
        or _integer(durability.get("replication_factor"), "replication factor") < 3
    ):
        raise ValueError("Kafka durability policy is insufficient")
    tests = _passed_cases(value.get("tests"), "Kafka test")
    if set(tests) != {
        "acl-denial",
        "consumer-isolation",
        "failover",
        "multi-partition-atomicity",
        "producer-fencing",
        "restart-deduplication",
    }:
        raise ValueError("Kafka failure and authorization qualification is incomplete")
    if (
        set(_strings(value.get("schema_formats"), "schema formats"))
        != {"avro", "json", "protobuf"}
        or value.get("key_and_headers_validated") is not True
    ):
        raise ValueError("Kafka schema qualification is incomplete")
    return {"test_count": len(tests), "acl_resource_count": 4, "schema_format_count": 3}


def _postgresql(value: object) -> dict[str, Any]:
    required = {
        "schema_version",
        "sslmode",
        "channel_binding",
        "audits",
        "rls_tests",
        "recovery_tests",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
    ):
        raise ValueError("PostgreSQL qualification receipt is invalid")
    if (
        value.get("sslmode") != "verify-full"
        or value.get("channel_binding") != "require"
    ):
        raise ValueError(
            "PostgreSQL qualification requires hostname TLS and channel binding"
        )
    audits = set(_strings(value.get("audits"), "PostgreSQL audits"))
    if audits != {
        "bypassrls",
        "default-privileges",
        "force-row-security",
        "grants",
        "search-path",
        "security-definer",
    }:
        raise ValueError("PostgreSQL privilege audit coverage is incomplete")
    rls = _passed_cases(value.get("rls_tests"), "PostgreSQL RLS test")
    if set(rls) != {
        "concurrent-policy-race",
        "covert-channel",
        "cross-tenant-crud",
        "owner-bypass",
        "referential-integrity",
    }:
        raise ValueError("PostgreSQL RLS adversarial coverage is incomplete")
    recovery = _passed_cases(value.get("recovery_tests"), "PostgreSQL recovery test")
    if set(recovery) != {
        "cross-version",
        "encrypted-backup",
        "extension-restore",
        "large-dataset",
        "logical-restore",
        "pitr",
        "wal-replay",
    }:
        raise ValueError("PostgreSQL recovery qualification is incomplete")
    return {
        "audit_count": len(audits),
        "rls_test_count": len(rls),
        "recovery_test_count": len(recovery),
    }


def _ai(value: object) -> dict[str, Any]:
    required = {
        "schema_version",
        "independence_dimensions",
        "attestation_sha256",
        "inter_rater_kappa",
        "adjudication_rate",
        "per_control_confusion",
        "calibration_windows",
    }
    artifact_fields = {
        "attestation_file",
        "adjudication_file",
        "adjudication_sha256",
        "calibration_file",
        "calibration_sha256",
    }
    if (
        not isinstance(value, dict)
        or frozenset(value)
        not in {frozenset(required), frozenset(required | artifact_fields)}
        or value.get("schema_version") != "1.0"
    ):
        raise ValueError("AI qualification receipt is invalid")
    if set(
        _strings(value.get("independence_dimensions"), "AI independence dimensions")
    ) != {"hardware", "network", "organization", "process"} or not _digest(
        str(value.get("attestation_sha256") or "")
    ):
        raise ValueError("AI execution independence is not attested")
    kappa = _fraction(value.get("inter_rater_kappa"), "inter-rater kappa")
    adjudication = _fraction(value.get("adjudication_rate"), "adjudication rate")
    matrices = value.get("per_control_confusion")
    if (
        kappa < 0.8
        or adjudication > 0.2
        or not isinstance(matrices, dict)
        or not matrices
    ):
        raise ValueError(
            "AI judge agreement or per-control calibration is insufficient"
        )
    for matrix in matrices.values():
        if (
            not isinstance(matrix, dict)
            or set(matrix) != {"fn", "fp", "tn", "tp"}
            or any(
                _nonnegative_integer(item, "confusion count") < 0
                for item in matrix.values()
            )
        ):
            raise ValueError("AI per-control confusion matrix is invalid")
    if _integer(value.get("calibration_windows"), "calibration windows") < 3:
        raise ValueError("AI calibration drift requires at least three windows")
    return {
        "control_count": len(matrices),
        "calibration_windows": value["calibration_windows"],
        "inter_rater_kappa": kappa,
    }


def _sarif(value: object) -> dict[str, Any]:
    required = {
        "schema_version",
        "official_schema_sha256",
        "runs",
        "native_results",
        "normalized_results",
        "exit_status_reconciled",
        "preserved_semantics",
        "redaction_detectors",
    }
    artifact_fields = {
        "official_schema_file",
        "native_report_file",
        "native_report_sha256",
        "normalized_report_file",
        "normalized_report_sha256",
        "process_exit_code",
    }
    if (
        not isinstance(value, dict)
        or frozenset(value)
        not in {frozenset(required), frozenset(required | artifact_fields)}
        or value.get("schema_version") != "2.1.0"
        or not _digest(str(value.get("official_schema_sha256") or ""))
    ):
        raise ValueError("SARIF qualification receipt is invalid")
    native = _nonnegative_integer(value.get("native_results"), "native SARIF results")
    normalized = _nonnegative_integer(
        value.get("normalized_results"), "normalized SARIF results"
    )
    if (
        _integer(value.get("runs"), "SARIF runs") < 1
        or normalized != native
        or value.get("exit_status_reconciled") is not True
    ):
        raise ValueError("SARIF result or invocation reconciliation failed")
    semantics = set(_strings(value.get("preserved_semantics"), "SARIF semantics"))
    if semantics != {
        "automation-details",
        "baseline-state",
        "code-flows",
        "fixes",
        "graphs",
        "related-locations",
        "stacks",
        "suppressions",
        "taxa",
    }:
        raise ValueError("SARIF semantic preservation is incomplete")
    if set(_strings(value.get("redaction_detectors"), "redaction detectors")) != {
        "credential-pattern",
        "entropy",
        "known-token-format",
    }:
        raise ValueError("SARIF redaction qualification is incomplete")
    return {
        "run_count": value["runs"],
        "result_count": native,
        "semantic_count": len(semantics),
    }


def _surface(value: object) -> dict[str, Any]:
    required = {
        "schema_version",
        "server_signed_pages",
        "trusted_time_sha256",
        "tombstones",
        "history_windows",
        "signed_total_count",
        "liveness_probes",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
    ):
        raise ValueError("surface qualification receipt is invalid")
    if (
        _integer(value.get("server_signed_pages"), "server-signed pages") < 1
        or not _digest(str(value.get("trusted_time_sha256") or ""))
        or _integer(value.get("history_windows"), "history windows") < 2
        or value.get("signed_total_count") is not True
        or _integer(value.get("liveness_probes"), "liveness probes") < 1
    ):
        raise ValueError(
            "surface completeness, freshness, or history proof is insufficient"
        )
    tombstones = value.get("tombstones")
    if (
        isinstance(tombstones, bool)
        or not isinstance(tombstones, int)
        or tombstones < 0
    ):
        raise ValueError("surface tombstone count is invalid")
    return {
        "page_count": value["server_signed_pages"],
        "history_windows": value["history_windows"],
        "tombstone_count": tombstones,
    }


def _supply_chain(value: object) -> dict[str, Any]:
    required = {
        "schema_version",
        "artifact_sha256",
        "slsa_level",
        "verifiers",
        "container_images",
        "recursive_dependencies",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
        or not _digest(str(value.get("artifact_sha256") or ""))
    ):
        raise ValueError("supply-chain qualification receipt is invalid")
    if (
        _integer(value.get("slsa_level"), "SLSA level") < 3
        or set(_strings(value.get("verifiers"), "provenance verifiers"))
        != {"dependency-closure", "sigstore", "slsa", "vsa"}
        or value.get("recursive_dependencies") is not True
    ):
        raise ValueError("supply-chain provenance composition is incomplete")
    images = value.get("container_images")
    if not isinstance(images, list) or not images:
        raise ValueError("supply-chain container inventory is empty")
    for image in images:
        if (
            not isinstance(image, dict)
            or set(image) != {"digest", "sbom_sha256", "signature_bundle_sha256"}
            or not all(_digest(str(item)) for item in image.values())
        ):
            raise ValueError("container image signature or SBOM receipt is invalid")
    return {"slsa_level": value["slsa_level"], "container_count": len(images)}


def _trust_state(value: object) -> dict[str, Any]:
    required = {
        "schema_version",
        "backend",
        "cas_verified",
        "append_only_verified",
        "transparency_proof_sha256",
        "checkpoint_sequence",
        "authority_quorum",
        "rotation_tested",
        "algorithms",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
        or value.get("backend")
        not in {"https-cas-transparency", "rfc6962-transparency-log"}
    ):
        raise ValueError("trust-state qualification receipt is invalid")
    if (
        value.get("cas_verified") is not True
        or value.get("append_only_verified") is not True
        or not _digest(str(value.get("transparency_proof_sha256") or ""))
        or _integer(value.get("checkpoint_sequence"), "checkpoint sequence") < 1
        or _integer(value.get("authority_quorum"), "authority quorum") < 2
        or value.get("rotation_tested") is not True
    ):
        raise ValueError("distributed trust-state guarantees are incomplete")
    if not {"ed25519", "ecdsa-p256"}.issubset(
        _strings(value.get("algorithms"), "trust algorithms")
    ):
        raise ValueError("trust-state algorithm agility is insufficient")
    return {
        "checkpoint_sequence": value["checkpoint_sequence"],
        "authority_quorum": value["authority_quorum"],
        "algorithm_count": len(value["algorithms"]),
    }


def _ci(value: object) -> dict[str, Any]:
    required = {
        "schema_version",
        "runner_isolation_attested",
        "egress_policy_attested",
        "image_signatures_verified",
        "sboms_verified",
        "build_provenance_verified",
        "fault_injection_scenarios",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
    ):
        raise ValueError("CI qualification receipt is invalid")
    for field in required - {"schema_version", "fault_injection_scenarios"}:
        if value.get(field) is not True:
            raise ValueError(f"CI qualification requires {field}")
    scenarios = set(
        _strings(value.get("fault_injection_scenarios"), "CI fault scenarios")
    )
    if scenarios != {
        "broker-failover",
        "database-restore",
        "network-partition",
        "signer-rotation",
        "stale-policy",
        "tampered-artifact",
    }:
        raise ValueError("CI fault-injection coverage is incomplete")
    return {"fault_scenario_count": len(scenarios)}


def _validators() -> dict[str, Callable[[object], dict[str, Any]]]:
    return {
        "ai": _ai,
        "browser": _browser,
        "ci": _ci,
        "kafka": _kafka,
        "postgresql": _postgresql,
        "sarif": _sarif,
        "supply-chain": _supply_chain,
        "surface": _surface,
        "trust-state": _trust_state,
    }


def _validate_area(area: str, value: object, context: Path) -> dict[str, Any]:
    metrics = _validators()[area](value)
    if area == "ai":
        metrics.update(_verify_ai_artifacts(value, context))
    elif area == "sarif":
        metrics.update(_verify_sarif_artifacts(value, context))
    return metrics


def _verify_ai_artifacts(value: object, context: Path) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("AI qualification receipt is invalid")
    required = {
        "attestation_file",
        "adjudication_file",
        "adjudication_sha256",
        "calibration_file",
        "calibration_sha256",
    }
    if not required.issubset(value):
        raise ValueError("AI qualification requires pinned raw adjudication artifacts")
    attestation, attestation_digest = _pinned_sibling(
        context,
        value.get("attestation_file"),
        value.get("attestation_sha256"),
        8 * 1024 * 1024,
    )
    adjudication, adjudication_digest = _pinned_sibling(
        context,
        value.get("adjudication_file"),
        value.get("adjudication_sha256"),
        16 * 1024 * 1024,
    )
    calibration, calibration_digest = _pinned_sibling(
        context,
        value.get("calibration_file"),
        value.get("calibration_sha256"),
        16 * 1024 * 1024,
    )
    if not attestation.read_bytes():
        raise ValueError("AI independence attestation is empty")
    records = _rating_records(_read_json(adjudication, maximum=16 * 1024 * 1024))
    windows = _read_json(calibration, maximum=16 * 1024 * 1024)
    if not isinstance(windows, list) or len(windows) < 3:
        raise ValueError("AI calibration artifact requires at least three windows")
    calibration_records: list[dict[str, Any]] = []
    window_ids: set[str] = set()
    for window in windows:
        if not isinstance(window, dict) or set(window) != {"window_id", "records"}:
            raise ValueError("AI calibration window is invalid")
        window_id = str(window.get("window_id") or "")
        if not window_id or window_id in window_ids:
            raise ValueError("AI calibration window identity is invalid")
        window_ids.add(window_id)
        calibration_records.extend(_rating_records(window.get("records")))
    kappa, adjudication_rate, matrices = _rating_metrics(records)
    declared_matrices = value.get("per_control_confusion")
    if (
        abs(kappa - float(value.get("inter_rater_kappa", -1))) > 1e-9
        or abs(adjudication_rate - float(value.get("adjudication_rate", -1))) > 1e-9
        or declared_matrices != matrices
        or int(value.get("calibration_windows", 0)) != len(windows)
    ):
        raise ValueError("AI declared metrics do not match pinned adjudication data")
    calibration_kappa, _rate, _matrices = _rating_metrics(calibration_records)
    if calibration_kappa < 0.8:
        raise ValueError("AI calibration artifact does not meet agreement policy")
    return {
        "attestation_sha256": attestation_digest,
        "adjudication_sha256": adjudication_digest,
        "calibration_sha256": calibration_digest,
        "calibration_inter_rater_kappa": calibration_kappa,
    }


def _rating_records(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError("AI rating records are invalid")
    records: list[dict[str, Any]] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item)
            != {"control", "reviewer_a", "reviewer_b", "adjudicated", "expected"}
            or not isinstance(item.get("control"), str)
            or not item["control"]
            or any(
                not isinstance(item.get(name), bool)
                for name in ("reviewer_a", "reviewer_b", "adjudicated", "expected")
            )
        ):
            raise ValueError("AI rating record fields are invalid")
        records.append(dict(item))
    return records


def _rating_metrics(
    records: list[dict[str, Any]],
) -> tuple[float, float, dict[str, dict[str, int]]]:
    total = len(records)
    agreement = (
        sum(item["reviewer_a"] == item["reviewer_b"] for item in records) / total
    )
    a_positive = sum(item["reviewer_a"] for item in records) / total
    b_positive = sum(item["reviewer_b"] for item in records) / total
    expected_agreement = a_positive * b_positive + (1 - a_positive) * (1 - b_positive)
    kappa = (
        1.0
        if expected_agreement == 1.0
        else (agreement - expected_agreement) / (1 - expected_agreement)
    )
    adjudication_rate = (
        sum(item["reviewer_a"] != item["reviewer_b"] for item in records) / total
    )
    matrices: dict[str, dict[str, int]] = {}
    for item in records:
        matrix = matrices.setdefault(
            item["control"], {"fn": 0, "fp": 0, "tn": 0, "tp": 0}
        )
        predicted = item["adjudicated"]
        expected = item["expected"]
        key = (
            "tp"
            if predicted and expected
            else "fp"
            if predicted
            else "fn"
            if expected
            else "tn"
        )
        matrix[key] += 1
    return kappa, adjudication_rate, matrices


def _verify_sarif_artifacts(value: object, context: Path) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("SARIF qualification receipt is invalid")
    required = {
        "official_schema_file",
        "native_report_file",
        "native_report_sha256",
        "normalized_report_file",
        "normalized_report_sha256",
        "process_exit_code",
    }
    if not required.issubset(value):
        raise ValueError(
            "SARIF qualification requires pinned native and normalized artifacts"
        )
    schema_path, schema_digest = _pinned_sibling(
        context,
        value.get("official_schema_file"),
        value.get("official_schema_sha256"),
        8 * 1024 * 1024,
    )
    native_path, native_digest = _pinned_sibling(
        context,
        value.get("native_report_file"),
        value.get("native_report_sha256"),
        64 * 1024 * 1024,
    )
    normalized_path, normalized_digest = _pinned_sibling(
        context,
        value.get("normalized_report_file"),
        value.get("normalized_report_sha256"),
        64 * 1024 * 1024,
    )
    schema = _read_json(schema_path, maximum=8 * 1024 * 1024)
    native = _read_json(native_path, maximum=64 * 1024 * 1024)
    normalized = _read_json(normalized_path, maximum=64 * 1024 * 1024)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(native)
    if not isinstance(native, dict) or not isinstance(normalized, dict):
        raise ValueError("SARIF qualification artifacts must be objects")
    native_results = sum(
        len(run.get("results", []))
        for run in native.get("runs", [])
        if isinstance(run, dict) and isinstance(run.get("results", []), list)
    )
    normalized_findings = normalized.get("findings")
    if not isinstance(normalized_findings, list):
        raise ValueError("normalized SARIF artifact lacks findings")
    exit_code = value.get("process_exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code != 0:
        raise ValueError("SARIF process exit status did not independently succeed")
    if native_results != len(normalized_findings):
        raise ValueError("SARIF native and normalized artifacts lose results")
    return {
        "official_schema_sha256": schema_digest,
        "native_report_sha256": native_digest,
        "normalized_report_sha256": normalized_digest,
        "artifact_result_count": native_results,
        "process_exit_code": exit_code,
    }


def _passed_cases(value: object, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} cases are invalid")
    result: dict[str, dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "name",
            "status",
            "case_count",
            "receipt_sha256",
        }:
            raise ValueError(f"{label} fields do not match")
        name = str(item.get("name") or "")
        if (
            not name
            or name in result
            or item.get("status") != "passed"
            or _integer(item.get("case_count"), f"{label} count") < 1
            or not _digest(str(item.get("receipt_sha256") or ""))
        ):
            raise ValueError(f"{label} did not pass with a valid receipt")
        result[name] = item
    return result


def _strings(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) != len(set(value))
        or any(
            not isinstance(item, str) or not item or len(item) > 200 for item in value
        )
    ):
        raise ValueError(f"{label} must be a unique bounded string list")
    return value


def _read_json(path: Path, *, maximum: int) -> object:
    return strict_loads(read_bounded_regular(path, maximum, "qualification input"))


def _qualification_context(value: object) -> dict[str, Any]:
    required = {
        "run_id",
        "environment_sha256",
        "target_sha256",
        "source_sha256",
        "profile_sha256",
        "trust_policy_sha256",
        "profile_generation",
        "issued_at",
        "expires_at",
        "nonce",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("qualification context fields do not match")
    result = dict(value)
    run_id = str(result.get("run_id") or "")
    if (
        not 8 <= len(run_id) <= 200
        or any(ord(character) < 32 for character in run_id)
        or any(
            not _digest(str(result.get(name) or ""))
            for name in (
                "environment_sha256",
                "target_sha256",
                "source_sha256",
                "profile_sha256",
                "trust_policy_sha256",
            )
        )
        or not _digest(str(result.get("nonce") or ""))
    ):
        raise ValueError("qualification context identity is invalid")
    result["run_id"] = run_id
    result["profile_generation"] = _integer(
        result.get("profile_generation"), "profile generation"
    )
    issued = _timestamp(result.get("issued_at"), "issued_at")
    expires = _timestamp(result.get("expires_at"), "expires_at")
    if expires <= issued:
        raise ValueError("qualification context validity window is invalid")
    result["issued_at"] = issued.isoformat()
    result["expires_at"] = expires.isoformat()
    return result


def _deployment_context(target: object) -> dict[str, Any]:
    required_environment = {
        "run_id": "PYSEC_RUN_ID",
        "environment_sha256": "PYSEC_ENVIRONMENT_SHA256",
        "source_sha256": "PYSEC_SOURCE_SHA256",
        "profile_sha256": "PYSEC_ASSURANCE_PROFILE_SHA256",
        "profile_generation": "PYSEC_ASSURANCE_PROFILE_GENERATION",
        "trust_policy_sha256": "PYSEC_TRUST_POLICY_SHA256",
    }
    values = {
        name: os.environ.get(variable, "")
        for name, variable in required_environment.items()
    }
    sanitized = (
        {
            key: item
            for key, item in target.items()
            if key not in {"qualification_receipt_file", "qualification_receipt_sha256"}
        }
        if isinstance(target, dict)
        else target
    )
    return {
        **values,
        "profile_generation": _integer(
            values["profile_generation"], "profile generation"
        ),
        "target_sha256": hashlib.sha256(canonical_bytes(sanitized)).hexdigest(),
    }


def _consume_replay(
    context: dict[str, Any], *, context_sha256: str, scope: str
) -> None:
    token = _replay_token(context, context_sha256=context_sha256, scope=scope)
    service = os.environ.get("PYSEC_QUALIFICATION_REPLAY_SERVICE_URL", "").strip()
    if service:
        _consume_remote_replay(token, service)
        return
    ledger_name = os.environ.get("PYSEC_QUALIFICATION_REPLAY_LEDGER", "").strip()
    if not ledger_name:
        raise ValueError("qualification replay protection is not configured")
    ledger = Path(ledger_name).expanduser().resolve()
    if ledger.exists() and (ledger.is_symlink() or not ledger.is_file()):
        raise ValueError("qualification replay ledger is not a regular file")
    if ledger.exists() and ledger.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("qualification replay ledger exceeds 16 MiB")
    ledger.parent.mkdir(parents=True, exist_ok=True)
    lock = ledger.with_name(f".{ledger.name}.lock")
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ValueError("qualification replay ledger is busy") from exc
        entries: list[str] = []
        if ledger.exists():
            parsed = strict_loads(ledger.read_bytes())
            if (
                not isinstance(parsed, dict)
                or set(parsed) != {"schema_version", "consumed"}
                or parsed.get("schema_version") != "1.0"
                or not isinstance(parsed.get("consumed"), list)
                or any(not _digest(str(item)) for item in parsed["consumed"])
            ):
                raise ValueError("qualification replay ledger is invalid")
            entries = [str(item) for item in parsed["consumed"]]
        if token in entries:
            raise ValueError("qualification receipt was already consumed")
        entries.append(token)
        if len(entries) > 100_000:
            raise ValueError("qualification replay ledger capacity is exhausted")
        _write(ledger, {"schema_version": "1.0", "consumed": entries})
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if lock.exists():
            lock.unlink()


def _replay_token(context: dict[str, Any], *, context_sha256: str, scope: str) -> str:
    return hashlib.sha256(
        canonical_bytes(
            {
                "context_sha256": context_sha256,
                "nonce": context["nonce"],
                "scope": scope,
            }
        )
    ).hexdigest()


def _consume_remote_replay(token: str, service: str) -> None:
    target = urlsplit(service)
    if (
        target.scheme != "https"
        or not target.hostname
        or target.username
        or target.password
        or target.query
        or target.fragment
    ):
        raise ValueError(
            "qualification replay service must be a credential-free HTTPS URL"
        )
    token_environment = os.environ.get(
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_TOKEN_ENV", ""
    )
    if (
        not token_environment
        or len(token_environment) > 100
        or token_environment.upper() != token_environment
        or not token_environment.replace("_", "").isalnum()
    ):
        raise ValueError("qualification replay token environment name is invalid")
    bearer = os.environ.get(token_environment, "")
    if (
        not bearer
        or len(bearer) > 8192
        or any(ord(character) < 33 for character in bearer)
    ):
        raise ValueError("qualification replay authentication token is unavailable")
    ca = _replay_credential("PYSEC_QUALIFICATION_REPLAY_SERVICE_CA", "CA bundle")
    certificate = _replay_credential(
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_CLIENT_CERT", "client certificate"
    )
    key = _replay_credential(
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_CLIENT_KEY", "client key"
    )
    tls = ssl.create_default_context(cafile=str(ca))
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(certfile=str(certificate), keyfile=str(key))
    payload = canonical_bytes(
        {"schema_version": "1.0", "token": token, "scope": "deep-qualification"}
    )
    request = Request(  # noqa: S310 - URL is restricted to HTTPS above.
        service,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Idempotency-Key": token,
        },
    )
    try:
        with urlopen(request, timeout=10.0, context=tls) as response:  # noqa: S310
            if response.status != 201:
                raise ValueError("qualification replay service rejected consumption")
            content_type = str(response.headers.get("Content-Type", ""))
            if not content_type.casefold().startswith("application/json"):
                raise ValueError("qualification replay service response is not JSON")
            raw = response.read(4097)
            if len(raw) > 4096:
                raise ValueError("qualification replay service response is oversized")
            receipt = strict_loads(raw)
            if (
                not isinstance(receipt, dict)
                or set(receipt) != {"schema_version", "token", "status"}
                or receipt.get("schema_version") != "1.0"
                or receipt.get("token") != token
                or receipt.get("status") != "consumed"
            ):
                raise ValueError("qualification replay service receipt is invalid")
    except HTTPError as exc:
        if exc.code == 409:
            raise ValueError("qualification receipt was already consumed") from exc
        raise ValueError("qualification replay service rejected consumption") from exc
    except (OSError, URLError) as exc:
        raise ValueError("qualification replay service could not be reached") from exc


def _replay_credential(variable: str, label: str) -> Path:
    configured = os.environ.get(variable, "").strip()
    if not configured:
        raise ValueError(f"qualification replay service {label} is not configured")
    path = Path(configured).expanduser()
    resolved = path.resolve()
    if (
        path.is_symlink()
        or resolved.is_symlink()
        or not resolved.is_file()
        or resolved.stat().st_size > 1024 * 1024
    ):
        raise ValueError(f"qualification replay service {label} is not a bounded file")
    return resolved


def _timestamp(value: object, label: str) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"qualification {label} is invalid") from exc
    if result.tzinfo is None:
        raise ValueError(f"qualification {label} requires a timezone")
    return result.astimezone(UTC)


def _pinned_sibling(
    context: Path, name: object, expected: object, maximum: int
) -> tuple[Path, str]:
    filename = str(name or "")
    digest = str(expected or "")
    if (
        not filename
        or Path(filename).name != filename
        or len(filename) > 200
        or not _digest(digest)
    ):
        raise ValueError("qualification receipt reference is invalid")
    path = context.resolve().parent / filename
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > maximum
        or hashlib.sha256(
            read_bounded_regular(path, maximum, "qualification sibling")
        ).hexdigest()
        != digest
    ):
        raise ValueError("qualification receipt digest does not match")
    return path, digest


def _environment_integer(name: str, default: int) -> int:
    return _integer(os.environ.get(name, str(default)), name)


def _integer(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, str))
        or not str(value).isdigit()
        or int(value) < 1
    ):
        raise ValueError(f"{label} must be a positive integer")
    return int(value)


def _nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _fraction(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise ValueError(f"{label} must be between zero and one")
    return result


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("qualification output is not replaceable")
    payload = (strict_dumps(value, indent=2) + "\n").encode()
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
