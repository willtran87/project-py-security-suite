from __future__ import annotations

import base64
import hashlib
import math
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .path_safety import read_regular_file, resolve_regular_file
from .benchmark_statistical_evidence import (
    BenchmarkStatisticalEvidenceError,
    verify_contamination_analysis,
    verify_duplicate_analysis,
    verify_environment_capture,
    verify_leakage_analysis,
    verify_power_analysis,
)
from .strict_json import canonical_bytes, loads as strict_loads
from .trusted_time import verify_rfc3161


_MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
_DIGEST_CHARACTERS = frozenset("0123456789abcdef")


class BenchmarkEvidenceError(ValueError):
    """Raised when a signed benchmark claim cannot be replayed from evidence."""


def verify_benchmark_trusted_time(
    context_path: Path,
    expected_sha256: str,
    *,
    workspace: Path,
    subject_sha256: str,
    claims: dict[str, Any],
) -> dict[str, str]:
    """Replay an advanced RFC 3161 context against the benchmark subject."""
    if not _digest(expected_sha256):
        raise BenchmarkEvidenceError("trusted-time context digest is invalid")
    requested = context_path.expanduser().absolute()
    boundary = workspace.expanduser().absolute().resolve()
    try:
        requested.relative_to(boundary)
    except ValueError:
        pass
    else:
        raise BenchmarkEvidenceError(
            "trusted-time context must remain outside the benchmark workspace"
        )
    try:
        resolved, payload = read_regular_file(
            requested,
            "benchmark trusted-time context",
            maximum_bytes=_MAX_EVIDENCE_BYTES,
        )
    except (OSError, ValueError) as exc:
        raise BenchmarkEvidenceError(
            "trusted-time context is not a safe regular file"
        ) from exc
    try:
        resolved.relative_to(boundary)
    except ValueError:
        pass
    else:
        raise BenchmarkEvidenceError(
            "trusted-time context must remain outside the benchmark workspace"
        )
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise BenchmarkEvidenceError("trusted-time context digest does not match")
    try:
        context = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise BenchmarkEvidenceError("trusted-time context is invalid JSON") from exc
    if (
        not isinstance(context, dict)
        or set(context) != {"schema_version", "trusted_time"}
        or context["schema_version"] != "1.0"
    ):
        raise BenchmarkEvidenceError("trusted-time context contract is invalid")
    if not os.environ.get("PYSEC_TRUSTED_TIME_STATE_PATH", "").strip():
        raise BenchmarkEvidenceError(
            "benchmark trusted time requires deployment monotonic state"
        )
    try:
        result = verify_rfc3161(
            resolved,
            context["trusted_time"],
            subject_sha256,
            require_advanced=True,
        )
    except (TypeError, ValueError) as exc:
        raise BenchmarkEvidenceError("benchmark RFC 3161 proof is invalid") from exc
    expected = {
        "trusted_time_receipt_sha256": claims.get("trusted_time_receipt_sha256"),
        "trusted_time_sha256": claims.get("trusted_time_sha256"),
    }
    if any(result.get(name) != value for name, value in expected.items()):
        raise BenchmarkEvidenceError(
            "trusted-time proof does not reproduce signed claims"
        )
    try:
        observed = datetime.fromisoformat(
            result["trusted_time_observed_at"].replace("Z", "+00:00")
        )
        claimed = datetime.fromisoformat(
            str(claims.get("observed_at", "")).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise BenchmarkEvidenceError("trusted-time proof timestamp is invalid") from exc
    age = (datetime.now(UTC) - observed).total_seconds()
    if observed != claimed or age < -60 or age > 15 * 60:
        raise BenchmarkEvidenceError(
            "trusted-time proof is detached, stale, or in the future"
        )
    return result


def _verify_legacy_conformance(
    conformance: dict[str, Any], claims: dict[str, Any]
) -> None:
    expected = {
        "schema_version": "1.0",
        "adapter_spec_sha256": claims["adapter_spec_sha256"],
        "runner_executable_sha256": claims["runner_executable_sha256"],
        "normalizer": claims["normalizer"],
        "golden_fixture_sha256": claims["golden_fixture_sha256"],
        "malformed_fixture_sha256": claims["malformed_fixture_sha256"],
        "deterministic_runs": claims["deterministic_runs"],
        "golden_passed": True,
        "malformed_rejected": True,
        "label_inversion_detected": True,
    }
    runs = conformance.get("runs")
    if not isinstance(runs, list) or len(runs) != expected["deterministic_runs"]:
        raise BenchmarkEvidenceError(
            "adapter conformance report has incomplete replay records"
        )
    outputs: set[str] = set()
    for index, run in enumerate(runs, start=1):
        if (
            not isinstance(run, dict)
            or set(run)
            != {
                "run",
                "golden_passed",
                "malformed_rejected",
                "label_inversion_detected",
                "output_sha256",
            }
            or run["run"] != index
            or run["golden_passed"] is not True
            or run["malformed_rejected"] is not True
            or run["label_inversion_detected"] is not True
            or not isinstance(run["output_sha256"], str)
            or not _digest(run["output_sha256"])
        ):
            raise BenchmarkEvidenceError("adapter conformance replay record is invalid")
        outputs.add(run["output_sha256"])
    if len(outputs) != 1:
        raise BenchmarkEvidenceError("adapter conformance runs are not deterministic")
    if conformance != {**expected, "runs": runs}:
        raise BenchmarkEvidenceError(
            "adapter conformance report does not reproduce signed claims"
        )


def verify_benchmark_evidence_documents(
    workspace: Path,
    manifest: dict[str, Any],
    attestations: dict[str, Any],
    *,
    trust_policy: dict[str, Any],
) -> dict[str, Any]:
    """Read and semantically verify high-value documents named by attestations."""
    image_sha256 = _runner_image_sha256(manifest, attestations)
    sbom_claims = _claims(attestations, "runner_sbom")
    provenance_claims = _claims(attestations, "runner_provenance")
    conformance_claims = _claims(attestations, "adapter_conformance")
    observation_claims = _claims(attestations, "runtime_observation")
    contamination_claims = _claims(attestations, "contamination_manifest")
    environment_claims = _claims(attestations, "environment")

    sbom = _bound_json(
        workspace,
        sbom_claims,
        path_field="sbom_document_path",
        digest_field="sbom_document_sha256",
        label="runner SBOM",
    )
    _verify_sbom(sbom, str(sbom_claims["format"]), image_sha256)

    provenance = _bound_json(
        workspace,
        provenance_claims,
        path_field="provenance_document_path",
        digest_field="provenance_document_sha256",
        label="runner provenance",
    )
    _verify_provenance(
        provenance,
        image_sha256=image_sha256,
        builder_id=str(provenance_claims["builder_id"]),
        require_slsa_build_definition=manifest.get("schema_version") == "1.2",
        expected_build_type=(
            str(provenance_claims["build_type"])
            if manifest.get("schema_version") == "1.2"
            else None
        ),
        expected_source_uri=(
            str(provenance_claims["source_repository_uri"])
            if manifest.get("schema_version") == "1.2"
            else None
        ),
        expected_source_sha256=(
            str(provenance_claims["source_revision_sha256"])
            if manifest.get("schema_version") == "1.2"
            else None
        ),
        expected_materials_sha256=(
            str(provenance_claims["resolved_dependencies_sha256"])
            if manifest.get("schema_version") == "1.2"
            else None
        ),
        expected_materials_count=(
            int(provenance_claims["resolved_dependencies_count"])
            if manifest.get("schema_version") == "1.2"
            else None
        ),
    )
    builder_key_id = _verify_provenance_signature(
        workspace, provenance_claims, provenance
    )
    builder_authority = trust_policy["authority_index"].get(
        ("provenance-builder", builder_key_id)
    )
    if (
        not isinstance(builder_authority, dict)
        or builder_authority.get("status") != "active"
        or builder_authority.get("organization_id")
        != provenance_claims.get("builder_organization_id")
    ):
        raise BenchmarkEvidenceError(
            "runner provenance builder is not admitted by deployment policy"
        )

    conformance = _bound_json(
        workspace,
        conformance_claims,
        path_field="conformance_report_path",
        digest_field="conformance_report_sha256",
        label="adapter conformance report",
    )
    if manifest.get("schema_version") == "1.1":
        _verify_legacy_conformance(conformance, conformance_claims)
    else:
        expected_conformance: dict[str, Any] = {
            "schema_version": "1.1",
            "adapter_spec_sha256": conformance_claims["adapter_spec_sha256"],
            "runner_executable_sha256": conformance_claims["runner_executable_sha256"],
            "normalizer": conformance_claims["normalizer"],
            "semantic_oracle_identity": conformance_claims["semantic_oracle_identity"],
            "semantic_oracle_sha256": conformance_claims["semantic_oracle_sha256"],
            "deterministic_runs": conformance_claims["deterministic_runs"],
            "fixture_counts": conformance_claims["fixture_counts"],
            "fixture_set_sha256": conformance_claims["fixture_set_sha256"],
            "output_sha256": conformance_claims["output_sha256"],
            "parser_negative_controls_passed": True,
            "semantic_inversion_controls_passed": True,
        }
        if conformance != expected_conformance:
            raise BenchmarkEvidenceError(
                "adapter conformance report does not reproduce signed claims"
            )

    observation = _bound_json(
        workspace,
        observation_claims,
        path_field="observation_report_path",
        digest_field="observation_report_sha256",
        label="runtime observation report",
    )
    observed_claims = {
        key: value
        for key, value in observation_claims.items()
        if key not in {"observation_report_path", "observation_report_sha256"}
    }
    samples = observation.get("samples")
    if not isinstance(samples, list) or len(samples) < int(
        observation_claims["minimum_repetitions"]
    ):
        raise BenchmarkEvidenceError(
            "runtime observation report has insufficient raw samples"
        )
    expected_sample = {
        key: observation_claims[key]
        for key in (
            "target_sha256",
            "runner_image_sha256",
            "network_policy_sha256",
            "resource_limits_sha256",
            "egress_transcript_sha256",
            "environment_sha256",
        )
    }
    for index, sample in enumerate(samples, start=1):
        if not isinstance(sample, dict) or sample != {
            "repetition": index,
            **expected_sample,
            "completed": True,
        }:
            raise BenchmarkEvidenceError("runtime observation sample is invalid")
    if observation != {
        "schema_version": "1.0",
        "observations": observed_claims,
        "samples": samples,
    }:
        raise BenchmarkEvidenceError(
            "runtime observation report does not reproduce signed claims"
        )
    if (
        observation_claims.get("achieved_power", 0)
        < manifest["evaluation"]["minimum_power"]
        or observation_claims.get("leakage_detected") is not False
        or observation_claims.get("duplicate_count") != 0
    ):
        raise BenchmarkEvidenceError(
            "runtime observation does not satisfy power, leakage, and duplicate controls"
        )

    power = _bound_json(
        workspace,
        observation_claims,
        path_field="power_analysis_path",
        digest_field="power_analysis_sha256",
        label="power analysis",
    )
    leakage = _bound_json(
        workspace,
        observation_claims,
        path_field="leakage_check_path",
        digest_field="leakage_check_sha256",
        label="leakage analysis",
    )
    duplicates = _bound_json(
        workspace,
        observation_claims,
        path_field="duplicate_check_path",
        digest_field="duplicate_check_sha256",
        label="duplicate analysis",
    )
    contamination = _bound_json(
        workspace,
        contamination_claims,
        path_field="contamination_manifest_path",
        digest_field="contamination_manifest_sha256",
        label="contamination analysis",
    )
    environment = _bound_json(
        workspace,
        environment_claims,
        path_field="environment_document_path",
        digest_field="environment_document_sha256",
        label="environment capture",
    )
    try:
        strict_design = manifest.get("schema_version") == "1.2"
        achieved_power = verify_power_analysis(
            power,
            minimum_power=float(manifest["evaluation"]["minimum_power"]),
            minimum_cases=int(manifest["evaluation"]["minimum_cases"]),
            protocol=str(manifest["protocol"]),
            require_adjusted_design=strict_design,
            require_protocol_specific=strict_design,
            workspace=workspace,
        )
        leakage_count = verify_leakage_analysis(
            leakage,
            require_semantic=strict_design,
            require_derived_semantic=strict_design,
            workspace=workspace,
        )
        duplicate_count = verify_duplicate_analysis(
            duplicates,
            minimum_cases=int(manifest["evaluation"]["minimum_cases"]),
            require_semantic=strict_design,
            require_derived_semantic=strict_design,
            workspace=workspace,
        )
        contamination_count = verify_contamination_analysis(
            contamination,
            require_semantic=strict_design,
            require_derived_semantic=strict_design,
            workspace=workspace,
        )
        hermetic = verify_environment_capture(environment)
    except BenchmarkStatisticalEvidenceError as exc:
        raise BenchmarkEvidenceError(str(exc)) from exc
    if (
        not isinstance(observation_claims.get("achieved_power"), (int, float))
        or not math.isclose(
            float(observation_claims["achieved_power"]),
            achieved_power,
            rel_tol=0,
            abs_tol=1e-9,
        )
        or observation_claims.get("leakage_detected") is not (leakage_count > 0)
        or observation_claims.get("duplicate_count") != duplicate_count
        or contamination_claims.get("contaminated") is not (contamination_count > 0)
        or environment_claims.get("hermetic") is not hermetic
        or environment_claims.get("environment_sha256")
        != environment_claims.get("environment_document_sha256")
    ):
        raise BenchmarkEvidenceError(
            "raw benchmark evidence does not reproduce signed outcomes"
        )
    if strict_design:
        expected_toolset = hashlib.sha256(
            canonical_bytes(
                [
                    {"name": item["name"], "sha256": item["executable_sha256"]}
                    for item in manifest["stages"]
                ]
            )
        ).hexdigest()
        expected_network = hashlib.sha256(
            canonical_bytes(manifest["isolation"]["network_policy"])
        ).hexdigest()
        if (
            environment.get("toolset_sha256") != expected_toolset
            or environment.get("network_policy_sha256") != expected_network
        ):
            raise BenchmarkEvidenceError(
                "environment capture is not bound to the executed toolset and network policy"
            )

    verified = {
        "runner_sbom": True,
        "runner_provenance": True,
        "adapter_conformance": True,
        "runtime_observation": True,
        "power_analysis": True,
        "leakage_analysis": True,
        "duplicate_analysis": True,
        "contamination_analysis": True,
        "environment_capture": True,
    }
    if "cleanup_capability" in attestations:
        cleanup_claims = _claims(attestations, "cleanup_capability")
        cleanup = _bound_json(
            workspace,
            cleanup_claims,
            path_field="cleanup_receipt_path",
            digest_field="cleanup_receipt_sha256",
            label="cleanup receipt",
        )
        expected_cleanup = {
            "schema_version": "1.0",
            "target_sha256": cleanup_claims["target_sha256"],
            "destruction_probe_sha256": cleanup_claims["destruction_probe_sha256"],
            "target_destroyed": True,
            "cleanup_validated": True,
        }
        probes = cleanup.get("probes")
        if probes != [
            {"probe": "lookup", "target_absent": True},
            {"probe": "access", "target_absent": True},
        ]:
            raise BenchmarkEvidenceError(
                "cleanup receipt does not contain independent destruction probes"
            )
        if cleanup != {**expected_cleanup, "probes": probes}:
            raise BenchmarkEvidenceError(
                "cleanup receipt does not reproduce destruction claims"
            )
        verified["cleanup_capability"] = True
    return {
        "verified": True,
        "documents": verified,
        "runner_image_sha256": image_sha256,
    }


def _bound_json(
    workspace: Path,
    claims: dict[str, Any],
    *,
    path_field: str,
    digest_field: str,
    label: str,
) -> dict[str, Any]:
    path_value = claims.get(path_field)
    digest = claims.get(digest_field)
    if not isinstance(path_value, str) or not path_value:
        raise BenchmarkEvidenceError(f"{label} path is missing")
    if not isinstance(digest, str) or not _digest(digest):
        raise BenchmarkEvidenceError(f"{label} digest is invalid")
    candidate = workspace / Path(path_value)
    resolved = resolve_regular_file(candidate, label)
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise BenchmarkEvidenceError(
            f"{label} must remain inside the workspace"
        ) from exc
    _, payload = read_regular_file(
        resolved,
        label,
        maximum_bytes=_MAX_EVIDENCE_BYTES,
        boundary=workspace,
    )
    if hashlib.sha256(payload).hexdigest() != digest:
        raise BenchmarkEvidenceError(f"{label} digest does not match")
    try:
        value = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise BenchmarkEvidenceError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise BenchmarkEvidenceError(f"{label} must be a JSON object")
    return value


def _verify_sbom(value: dict[str, Any], format_name: str, image_sha256: str) -> None:
    if format_name.startswith("CycloneDX"):
        expected_version = format_name.removeprefix("CycloneDX-")
        metadata = value.get("metadata")
        component = metadata.get("component") if isinstance(metadata, dict) else None
        hashes = component.get("hashes") if isinstance(component, dict) else None
        if (
            value.get("bomFormat") != "CycloneDX"
            or value.get("specVersion") != expected_version
            or not isinstance(hashes, list)
            or not any(
                isinstance(item, dict)
                and str(item.get("alg", "")).replace("-", "").casefold() == "sha256"
                and item.get("content") == image_sha256
                for item in hashes
            )
        ):
            raise BenchmarkEvidenceError("runner CycloneDX SBOM subject is invalid")
        return
    if format_name.startswith("SPDX"):
        expected_version = format_name.removeprefix("SPDX-")
        packages = value.get("packages")
        if (
            value.get("spdxVersion") != f"SPDX-{expected_version}"
            or not isinstance(packages, list)
            or not any(
                isinstance(package, dict)
                and any(
                    isinstance(checksum, dict)
                    and checksum.get("algorithm") == "SHA256"
                    and checksum.get("checksumValue") == image_sha256
                    for checksum in package.get("checksums", [])
                    if isinstance(package.get("checksums"), list)
                )
                for package in packages
            )
        ):
            raise BenchmarkEvidenceError("runner SPDX SBOM subject is invalid")
        return
    raise BenchmarkEvidenceError("runner SBOM format is unsupported")


def _verify_provenance(
    value: dict[str, Any],
    *,
    image_sha256: str,
    builder_id: str,
    require_slsa_build_definition: bool = False,
    expected_build_type: str | None = None,
    expected_source_uri: str | None = None,
    expected_source_sha256: str | None = None,
    expected_materials_sha256: str | None = None,
    expected_materials_count: int | None = None,
) -> None:
    subjects = value.get("subject")
    predicate = value.get("predicate")
    run_details = predicate.get("runDetails") if isinstance(predicate, dict) else None
    builder = run_details.get("builder") if isinstance(run_details, dict) else None
    if (
        value.get("_type") != "https://in-toto.io/Statement/v1"
        or value.get("predicateType") != "https://slsa.dev/provenance/v1"
        or not isinstance(subjects, list)
        or not any(
            isinstance(subject, dict)
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == image_sha256
            for subject in subjects
        )
        or not isinstance(builder, dict)
        or builder.get("id") != builder_id
    ):
        raise BenchmarkEvidenceError("runner SLSA provenance subject is invalid")
    if not require_slsa_build_definition:
        return
    predicate = cast(dict[str, Any], predicate)
    run_details = cast(dict[str, Any], run_details)
    build_definition = predicate.get("buildDefinition")
    metadata = run_details.get("metadata")
    if not isinstance(build_definition, dict) or set(build_definition) != {
        "buildType",
        "externalParameters",
        "internalParameters",
        "resolvedDependencies",
    }:
        raise BenchmarkEvidenceError(
            "runner SLSA provenance build definition is incomplete"
        )
    dependencies = build_definition["resolvedDependencies"]
    if (
        not isinstance(build_definition["buildType"], str)
        or build_definition["buildType"] != expected_build_type
        or not isinstance(expected_source_uri, str)
        or not expected_source_uri.startswith("https://")
        or not isinstance(expected_source_sha256, str)
        or not _digest(expected_source_sha256)
        or not isinstance(build_definition["externalParameters"], dict)
        or not isinstance(build_definition["internalParameters"], dict)
        or not isinstance(dependencies, list)
        or not dependencies
    ):
        raise BenchmarkEvidenceError(
            "runner SLSA provenance build definition is invalid"
        )
    for dependency in dependencies:
        if (
            not isinstance(dependency, dict)
            or set(dependency) != {"uri", "digest"}
            or not isinstance(dependency["uri"], str)
            or not dependency["uri"]
            or not isinstance(dependency["digest"], dict)
            or set(dependency["digest"]) != {"sha256"}
            or not _digest(dependency["digest"]["sha256"])
        ):
            raise BenchmarkEvidenceError("runner SLSA provenance material is invalid")
    material_identities = [
        (dependency["uri"], dependency["digest"]["sha256"])
        for dependency in dependencies
    ]
    materials_sha256 = hashlib.sha256(
        canonical_bytes(
            [
                {"uri": uri, "sha256": digest}
                for uri, digest in sorted(material_identities)
            ]
        )
    ).hexdigest()
    external_parameters = build_definition["externalParameters"]
    if (
        len({item[0] for item in material_identities}) != len(material_identities)
        or (expected_source_uri, expected_source_sha256) not in material_identities
        or external_parameters.get("source_repository_uri") != expected_source_uri
        or external_parameters.get("source_revision_sha256") != expected_source_sha256
        or expected_materials_count != len(material_identities)
        or expected_materials_sha256 != materials_sha256
    ):
        raise BenchmarkEvidenceError(
            "runner SLSA provenance material set does not match policy"
        )
    if (
        not isinstance(metadata, dict)
        or set(metadata) != {"invocationId", "startedOn", "finishedOn"}
        or not isinstance(metadata["invocationId"], str)
        or not metadata["invocationId"]
    ):
        raise BenchmarkEvidenceError("runner SLSA provenance metadata is incomplete")
    try:
        started = datetime.fromisoformat(
            str(metadata["startedOn"]).replace("Z", "+00:00")
        )
        finished = datetime.fromisoformat(
            str(metadata["finishedOn"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise BenchmarkEvidenceError(
            "runner SLSA provenance timestamps are invalid"
        ) from exc
    if (
        started.tzinfo is None
        or finished.tzinfo is None
        or finished < started
        or finished - started > timedelta(days=7)
    ):
        raise BenchmarkEvidenceError("runner SLSA provenance build interval is invalid")


def _verify_provenance_signature(
    workspace: Path,
    claims: dict[str, Any],
    provenance: dict[str, Any],
) -> str:
    signature_path = claims.get("provenance_signature_path")
    signature_sha256 = claims.get("provenance_signature_sha256")
    public_key_path = claims.get("provenance_public_key_path")
    public_key_sha256 = claims.get("provenance_public_key_sha256")
    if (
        claims.get("provenance_signature_format") != "dsse-ed25519"
        or not isinstance(signature_path, str)
        or not isinstance(public_key_path, str)
        or not isinstance(signature_sha256, str)
        or not _digest(signature_sha256)
        or not isinstance(public_key_sha256, str)
        or not _digest(public_key_sha256)
    ):
        raise BenchmarkEvidenceError("runner provenance signature binding is invalid")
    envelope_payload = _bound_binary(
        workspace,
        signature_path,
        signature_sha256,
        "runner provenance signature",
        maximum_bytes=4096,
    )
    public_key = _bound_binary(
        workspace,
        public_key_path,
        public_key_sha256,
        "runner provenance public key",
        maximum_bytes=64 * 1024,
    )
    try:
        key = serialization.load_pem_public_key(public_key)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("not Ed25519")
        key_id = hashlib.sha256(
            key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).hexdigest()
        envelope = strict_loads(envelope_payload)
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"payloadType", "payload", "signatures"}
            or envelope["payloadType"] != "application/vnd.in-toto+json"
            or not isinstance(envelope["payload"], str)
            or not isinstance(envelope["signatures"], list)
            or len(envelope["signatures"]) != 1
            or not isinstance(envelope["signatures"][0], dict)
            or set(envelope["signatures"][0]) != {"keyid", "sig"}
            or envelope["signatures"][0]["keyid"] != key_id
        ):
            raise ValueError("invalid DSSE envelope")
        decoded_payload = base64.b64decode(envelope["payload"], validate=True)
        if decoded_payload != canonical_bytes(provenance):
            raise ValueError("DSSE payload does not match provenance")
        signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
        key.verify(signature, _dsse_pae(envelope["payloadType"], decoded_payload))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise BenchmarkEvidenceError("runner provenance signature is invalid") from exc
    return key_id


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    encoded_type = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(encoded_type)).encode("ascii")
        + b" "
        + encoded_type
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _bound_binary(
    workspace: Path,
    path_value: str,
    expected_sha256: str,
    label: str,
    *,
    maximum_bytes: int,
) -> bytes:
    resolved = resolve_regular_file(workspace / Path(path_value), label)
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise BenchmarkEvidenceError(
            f"{label} must remain inside the workspace"
        ) from exc
    _, payload = read_regular_file(
        resolved,
        label,
        maximum_bytes=maximum_bytes,
        boundary=workspace,
    )
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise BenchmarkEvidenceError(f"{label} digest does not match")
    return payload


def _runner_image_sha256(manifest: dict[str, Any], attestations: dict[str, Any]) -> str:
    oci = manifest["isolation"].get("oci")
    if isinstance(oci, dict):
        return str(oci["image"]).rsplit("@sha256:", 1)[-1]
    value = _claims(attestations, "runtime_observation").get("runner_image_sha256")
    if not isinstance(value, str) or not _digest(value):
        raise BenchmarkEvidenceError("runtime observation image digest is invalid")
    return value


def _claims(attestations: dict[str, Any], name: str) -> dict[str, Any]:
    value = attestations.get(name)
    claims = value.get("claims") if isinstance(value, dict) else None
    if not isinstance(claims, dict):
        raise BenchmarkEvidenceError(f"{name} claims are unavailable")
    return claims


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in _DIGEST_CHARACTERS for character in value
    )
