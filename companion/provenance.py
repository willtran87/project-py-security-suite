from __future__ import annotations

import base64
import hashlib
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from companion.strict_json import canonical_bytes, loads as strict_loads
except ModuleNotFoundError:  # Direct script execution.
    from strict_json import canonical_bytes, loads as strict_loads  # type: ignore[import-not-found,no-redef]


SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
SLSA_VSA_V1 = "https://slsa.dev/verification_summary/v1"
IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def file_provenance(
    *,
    native_report: Path,
    normalizer: Path,
    builder_id: str,
    builder: Path,
    invocation: Path,
    materials: Path,
) -> dict[str, str]:
    return {
        "schema_version": "1.0",
        "builder_id": _builder_id(builder_id),
        "builder_sha256": _sha256(builder, "builder"),
        "native_report_sha256": _sha256(native_report, "native report"),
        "normalizer_sha256": _sha256(normalizer, "normalizer"),
        "invocation_sha256": _sha256(invocation, "invocation"),
        "materials_sha256": _sha256(materials, "materials"),
    }


def inline_provenance(
    *,
    native_receipt: object,
    builder_id: str,
    builder: Path,
    invocation: bytes,
    materials: object,
) -> dict[str, str]:
    builder_digest = _sha256(builder, "builder")
    return {
        "schema_version": "1.0",
        "builder_id": _builder_id(builder_id),
        "builder_sha256": builder_digest,
        "native_report_sha256": _digest_value(native_receipt),
        "normalizer_sha256": builder_digest,
        "invocation_sha256": hashlib.sha256(invocation).hexdigest(),
        "materials_sha256": _digest_value(materials),
    }


def slsa_provenance(
    *,
    native_report: Path,
    normalizer: Path,
    builder_id: str,
    builder: Path,
    builder_environment: Path,
    build_type: str,
    source_repository: str,
    source_revision: str,
    invocation: Path,
    external_parameters: Path,
    materials: Path,
    byproducts: Path,
) -> dict[str, str]:
    """Produce the policy-relevant SLSA provenance identity fields.

    Large statements remain out-of-band and digest-bound.  The ingester rejects
    unknown fields and can independently compare builder/build/source policy.
    """
    repository = source_repository.strip()
    if not repository.startswith("https://") or len(repository) > 500:
        raise ValueError("source-repository must be a canonical HTTPS URI")
    revision = source_revision.strip().lower()
    if len(revision) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in revision
    ):
        raise ValueError("source-revision must be a full hexadecimal revision")
    kind = build_type.strip()
    if not kind.startswith("https://") or len(kind) > 500:
        raise ValueError("build-type must be an HTTPS URI")
    return {
        "schema_version": "2.0",
        "builder_id": _builder_id(builder_id),
        "builder_sha256": _sha256(builder, "builder"),
        "builder_environment_sha256": _sha256(
            builder_environment, "builder environment"
        ),
        "build_type": kind,
        "source_repository": repository,
        "source_revision": revision,
        "native_report_sha256": _sha256(native_report, "native report"),
        "normalizer_sha256": _sha256(normalizer, "normalizer"),
        "invocation_sha256": _sha256(invocation, "invocation"),
        "external_parameters_sha256": _sha256(
            external_parameters, "external parameters"
        ),
        "materials_sha256": _sha256(materials, "materials"),
        "byproducts_sha256": _sha256(byproducts, "byproducts"),
    }


def verify_slsa_dsse(
    *,
    envelope: Path,
    artifact: Path,
    trusted_public_key: Path,
    expected_builder_id: str,
    expected_build_type: str,
    expected_source_repository: str,
    expected_source_revision: str,
    expected_external_parameters: object,
    expected_public_key_sha256: str | None = None,
    minimum_slsa_level: int = 2,
    dependency_manifest: Path | None = None,
) -> dict[str, str]:
    """Cryptographically verify a standard DSSE-wrapped SLSA v1 statement."""
    envelope_raw = _bounded(envelope, "SLSA DSSE envelope")
    value = strict_loads(envelope_raw)
    if not isinstance(value, dict) or set(value) != {
        "payloadType",
        "payload",
        "signatures",
    }:
        raise ValueError("SLSA DSSE envelope fields do not match the contract")
    if value.get("payloadType") != DSSE_PAYLOAD_TYPE:
        raise ValueError("SLSA DSSE payload type is invalid")
    try:
        payload = base64.b64decode(str(value.get("payload") or ""), validate=True)
    except ValueError as exc:
        raise ValueError("SLSA DSSE payload is invalid") from exc
    if len(payload) > 16 * 1024 * 1024:
        raise ValueError("SLSA DSSE payload exceeds 16 MiB")
    key_raw = _bounded(trusted_public_key, "SLSA trusted public key", 1024 * 1024)
    try:
        key = serialization.load_pem_public_key(key_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("SLSA trusted public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("SLSA trusted public key must use Ed25519")
    key_id = hashlib.sha256(
        key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).hexdigest()
    deployment_pin = expected_public_key_sha256 or os.environ.get(
        "PYSEC_SLSA_BUILDER_KEY_SHA256", ""
    )
    if deployment_pin != key_id:
        raise ValueError("SLSA builder key is not deployment-pinned")
    if isinstance(minimum_slsa_level, bool) or minimum_slsa_level not in {1, 2, 3}:
        raise ValueError("SLSA minimum level policy is invalid")
    builder_level = _builder_policy(expected_builder_id, key_id)
    if builder_level < minimum_slsa_level:
        raise ValueError("SLSA builder does not meet the required assurance level")
    signatures = value.get("signatures")
    if not isinstance(signatures, list) or not 1 <= len(signatures) <= 32:
        raise ValueError("SLSA DSSE signatures are invalid")
    verified = False
    pae = _dsse_pae(DSSE_PAYLOAD_TYPE, payload)
    for record in signatures:
        if not isinstance(record, dict) or set(record) != {"keyid", "sig"}:
            raise ValueError("SLSA DSSE signature fields are invalid")
        if record.get("keyid") != key_id:
            continue
        try:
            key.verify(base64.b64decode(str(record["sig"]), validate=True), pae)
            verified = True
        except (InvalidSignature, ValueError):
            continue
    if not verified:
        raise ValueError("SLSA DSSE has no valid trusted signature")
    statement = strict_loads(payload)
    if not isinstance(statement, dict) or set(statement) != {
        "_type",
        "subject",
        "predicateType",
        "predicate",
    }:
        raise ValueError("SLSA statement fields do not match in-toto v1")
    if (
        statement.get("_type") != IN_TOTO_STATEMENT_V1
        or statement.get("predicateType") != SLSA_PROVENANCE_V1
    ):
        raise ValueError("SLSA statement type is invalid")
    artifact_digest = _sha256(artifact, "SLSA subject artifact")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not any(
        isinstance(subject, dict)
        and isinstance(subject.get("digest"), dict)
        and subject["digest"].get("sha256") == artifact_digest
        for subject in subjects
    ):
        raise ValueError("SLSA subject does not identify the artifact")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict) or set(predicate) != {
        "buildDefinition",
        "runDetails",
    }:
        raise ValueError("SLSA provenance predicate fields are invalid")
    definition = predicate.get("buildDefinition")
    details = predicate.get("runDetails")
    if not isinstance(definition, dict) or not isinstance(details, dict):
        raise ValueError("SLSA build definition or run details are invalid")
    if set(definition) != {
        "buildType",
        "externalParameters",
        "internalParameters",
        "resolvedDependencies",
    } or set(details) != {"builder", "metadata", "byproducts"}:
        raise ValueError("SLSA provenance contains unknown policy fields")
    builder = details.get("builder")
    if (
        definition.get("buildType") != expected_build_type
        or definition.get("externalParameters") != expected_external_parameters
        or not isinstance(builder, dict)
        or set(builder) != {"id"}
        or builder.get("id") != expected_builder_id
    ):
        raise ValueError("SLSA builder, build type, or parameters do not match")
    dependencies = definition.get("resolvedDependencies")
    if not isinstance(dependencies, list) or not any(
        isinstance(item, dict)
        and item.get("uri") == expected_source_repository
        and isinstance(item.get("digest"), dict)
        and item["digest"].get("sha256") == expected_source_revision
        for item in dependencies
    ):
        raise ValueError("SLSA resolved source dependency does not match")
    dependency_digest = _digest_value(dependencies)
    dependency_manifest_verified = False
    if dependency_manifest is not None:
        expected_dependencies = strict_loads(
            _bounded(dependency_manifest, "SLSA dependency closure", 16 * 1024 * 1024)
        )
        if expected_dependencies != dependencies:
            raise ValueError("SLSA resolved dependency closure does not match policy")
        dependency_manifest_verified = True
    return {
        "schema_version": "1.0",
        "predicate_type": SLSA_PROVENANCE_V1,
        "builder_id": expected_builder_id,
        "build_type": expected_build_type,
        "source_repository": expected_source_repository,
        "source_revision": expected_source_revision,
        "artifact_sha256": artifact_digest,
        "external_parameters_sha256": _digest_value(expected_external_parameters),
        "envelope_sha256": hashlib.sha256(envelope_raw).hexdigest(),
        "signer_key_id": key_id,
        "slsa_level": str(builder_level),
        "resolved_dependencies_sha256": dependency_digest,
        "resolved_dependency_count": str(len(dependencies)),
        "dependency_manifest_verified": str(dependency_manifest_verified).lower(),
    }


def verify_sigstore_bundle(
    *,
    cosign: Path,
    artifact: Path,
    bundle: Path,
    trusted_root: Path,
    certificate_identity: str,
    certificate_oidc_issuer: str,
    expected_executable_sha256: str | None = None,
) -> dict[str, str]:
    """Run Cosign with explicit identity, issuer, bundle, and trusted-root policy."""
    executable_digest = _sha256(cosign, "Cosign executable")
    pin = expected_executable_sha256 or os.environ.get(
        "PYSEC_COSIGN_EXECUTABLE_SHA256", ""
    )
    if pin != executable_digest:
        raise ValueError("Cosign executable is not deployment-pinned")
    identity = certificate_identity.strip()
    issuer = certificate_oidc_issuer.strip()
    if not identity or len(identity) > 1000 or not issuer.startswith("https://"):
        raise ValueError("Sigstore certificate identity or issuer policy is invalid")
    bundle_digest = _sha256(bundle, "Sigstore bundle")
    trusted_root_digest = _sha256(trusted_root, "Sigstore trusted root")
    artifact_digest = _sha256(artifact, "Sigstore artifact")
    command = [
        str(cosign.resolve()),
        "verify-blob",
        "--bundle",
        str(bundle.resolve()),
        "--trusted-root",
        str(trusted_root.resolve()),
        "--certificate-identity",
        identity,
        "--certificate-oidc-issuer",
        issuer,
        str(artifact.resolve()),
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - executable is regular-file and digest pinned.
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=60,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("Sigstore verification timed out") from exc
    output = completed.stdout[: 1024 * 1024] + completed.stderr[: 1024 * 1024]
    if completed.returncode != 0:
        raise ValueError(
            "Sigstore bundle, identity, or transparency verification failed"
        )
    tlog_entries = _sigstore_tlog_entries(bundle)
    return {
        "schema_version": "1.0",
        "artifact_sha256": artifact_digest,
        "bundle_sha256": bundle_digest,
        "trusted_root_sha256": trusted_root_digest,
        "certificate_identity_sha256": hashlib.sha256(identity.encode()).hexdigest(),
        "certificate_oidc_issuer_sha256": hashlib.sha256(issuer.encode()).hexdigest(),
        "cosign_sha256": executable_digest,
        "verification_output_sha256": hashlib.sha256(output).hexdigest(),
        "transparency_log_verified": "true",
        "transparency_log_entry_count": str(tlog_entries),
    }


def verify_vsa_dsse(
    *,
    envelope: Path,
    artifact: Path,
    trusted_public_key: Path,
    expected_verifier_id: str,
    expected_policy_uri: str,
    expected_policy_sha256: str,
    expected_public_key_sha256: str | None = None,
    expected_resource_uri: str = "",
    minimum_slsa_level: int = 3,
    maximum_age_days: float = 7.0,
    at: datetime | None = None,
) -> dict[str, str]:
    """Verify a signed SLSA Verification Summary Attestation."""
    envelope_raw = _bounded(envelope, "VSA DSSE envelope")
    value = strict_loads(envelope_raw)
    if not isinstance(value, dict) or set(value) != {
        "payloadType",
        "payload",
        "signatures",
    }:
        raise ValueError("VSA DSSE envelope fields do not match the contract")
    if value.get("payloadType") != DSSE_PAYLOAD_TYPE:
        raise ValueError("VSA DSSE payload type is invalid")
    try:
        payload = base64.b64decode(str(value.get("payload") or ""), validate=True)
    except ValueError as exc:
        raise ValueError("VSA DSSE payload is invalid") from exc
    key_raw = _bounded(trusted_public_key, "VSA trusted public key", 1024 * 1024)
    try:
        key = serialization.load_pem_public_key(key_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("VSA trusted public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("VSA trusted public key must use Ed25519")
    key_id = hashlib.sha256(
        key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).hexdigest()
    pin = expected_public_key_sha256 or os.environ.get(
        "PYSEC_VSA_VERIFIER_KEY_SHA256", ""
    )
    if pin != key_id:
        raise ValueError("VSA verifier key is not deployment-pinned")
    _verify_vsa_signer_policy(key_id, expected_verifier_id)
    observed_at = (at or datetime.now(UTC)).astimezone(UTC)
    _verify_vsa_key_lifecycle(key_id, observed_at)
    signatures = value.get("signatures")
    pae = _dsse_pae(DSSE_PAYLOAD_TYPE, payload)
    if not isinstance(signatures, list) or not any(
        _valid_signature(key, item, key_id, pae) for item in signatures
    ):
        raise ValueError("VSA DSSE has no valid trusted signature")
    statement = strict_loads(payload)
    if not isinstance(statement, dict) or set(statement) != {
        "_type",
        "subject",
        "predicateType",
        "predicate",
    }:
        raise ValueError("VSA statement fields do not match in-toto v1")
    if (
        statement.get("_type") != IN_TOTO_STATEMENT_V1
        or statement.get("predicateType") != SLSA_VSA_V1
    ):
        raise ValueError("VSA statement type is invalid")
    artifact_digest = _sha256(artifact, "VSA subject artifact")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not any(
        isinstance(item, dict)
        and isinstance(item.get("digest"), dict)
        and item["digest"].get("sha256") == artifact_digest
        for item in subjects
    ):
        raise ValueError("VSA subject does not identify the artifact")
    predicate = statement.get("predicate")
    required = {
        "verifier",
        "timeVerified",
        "resourceUri",
        "policy",
        "inputAttestations",
        "verificationResult",
        "verifiedLevels",
        "dependencyLevels",
    }
    if not isinstance(predicate, dict) or set(predicate) != required:
        raise ValueError("VSA predicate fields do not match the v1 contract")
    verifier = predicate.get("verifier")
    policy = predicate.get("policy")
    resource_uri = expected_resource_uri or os.environ.get("PYSEC_VSA_RESOURCE_URI", "")
    if not resource_uri or len(resource_uri) > 1000:
        raise ValueError("VSA expected resource URI is not configured")
    verified_at = _timestamp(predicate.get("timeVerified"), "VSA timeVerified")
    if verified_at > observed_at + timedelta(
        minutes=5
    ) or observed_at - verified_at > timedelta(days=maximum_age_days):
        raise ValueError("VSA verification time is stale or in the future")
    levels = predicate.get("verifiedLevels")
    expected_levels = {
        f"SLSA_BUILD_LEVEL_{level}" for level in range(minimum_slsa_level, 4)
    }
    if (
        isinstance(minimum_slsa_level, bool)
        or minimum_slsa_level not in {1, 2, 3}
        or not isinstance(levels, list)
        or len(levels) != len(set(levels))
        or not expected_levels.intersection(levels)
        or sum(
            isinstance(item, str) and item.startswith("SLSA_BUILD_LEVEL_")
            for item in levels
        )
        != 1
    ):
        raise ValueError("VSA verifiedLevels does not satisfy build policy")
    dependencies = predicate.get("dependencyLevels")
    if (
        not isinstance(dependencies, dict)
        or any(
            key
            not in {
                "SLSA_BUILD_LEVEL_0",
                "SLSA_BUILD_LEVEL_1",
                "SLSA_BUILD_LEVEL_2",
                "SLSA_BUILD_LEVEL_3",
                "SLSA_BUILD_LEVEL_UNEVALUATED",
            }
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            for key, count in dependencies.items()
        )
        or dependencies.get("SLSA_BUILD_LEVEL_UNEVALUATED", 0) != 0
        or dependencies.get("SLSA_BUILD_LEVEL_0", 0) != 0
    ):
        raise ValueError("VSA dependencyLevels does not prove recursive closure")
    input_attestations = predicate.get("inputAttestations")
    if not isinstance(input_attestations, list) or not input_attestations:
        raise ValueError("VSA must identify the attestations used for verification")
    for item in input_attestations:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("digest"), dict)
            or not any(_is_digest(str(digest)) for digest in item["digest"].values())
        ):
            raise ValueError("VSA input attestation descriptor is invalid")
    if (
        not isinstance(verifier, dict)
        or verifier.get("id") != expected_verifier_id
        or not isinstance(policy, dict)
        or policy.get("uri") != expected_policy_uri
        or not isinstance(policy.get("digest"), dict)
        or policy["digest"].get("sha256") != expected_policy_sha256
        or predicate.get("verificationResult") != "PASSED"
        or predicate.get("resourceUri") != resource_uri
    ):
        raise ValueError("VSA verifier, policy, or result does not match")
    return {
        "schema_version": "1.0",
        "artifact_sha256": artifact_digest,
        "envelope_sha256": hashlib.sha256(envelope_raw).hexdigest(),
        "verifier_id": expected_verifier_id,
        "policy_sha256": expected_policy_sha256,
        "signer_key_id": key_id,
        "verified_levels_sha256": _digest_value(predicate.get("verifiedLevels")),
        "dependency_levels_sha256": _digest_value(predicate.get("dependencyLevels")),
        "verified_level": sorted(expected_levels.intersection(levels))[-1],
        "resource_uri_sha256": hashlib.sha256(resource_uri.encode()).hexdigest(),
        "input_attestations_sha256": _digest_value(input_attestations),
        "time_verified": verified_at.isoformat(),
        "dependency_count": str(sum(dependencies.values())),
        "dependency_closure_verified": "true",
    }


def compose_provenance(
    *,
    base: dict[str, str],
    slsa: dict[str, str],
    sigstore: dict[str, str],
    vsa: dict[str, str],
) -> dict[str, Any]:
    """Bind the independent SLSA, Sigstore, VSA, and dependency checks."""
    artifact_digests = {
        slsa.get("artifact_sha256"),
        sigstore.get("artifact_sha256"),
        vsa.get("artifact_sha256"),
    }
    if len(artifact_digests) != 1 or "" in artifact_digests or None in artifact_digests:
        raise ValueError(
            "provenance verification receipts identify different artifacts"
        )
    if base.get("schema_version") != "2.0" or slsa.get("builder_id") != base.get(
        "builder_id"
    ):
        raise ValueError("SLSA verification receipt does not match base provenance")
    required_sigstore = {"bundle_sha256", "trusted_root_sha256", "cosign_sha256"}
    if sigstore.get("transparency_log_verified") != "true" or not all(
        _is_digest(str(sigstore.get(name) or "")) for name in required_sigstore
    ):
        raise ValueError("Sigstore verification receipt is incomplete")
    for name in ("envelope_sha256", "policy_sha256", "signer_key_id"):
        if not _is_digest(str(vsa.get(name) or "")):
            raise ValueError("VSA verification receipt is incomplete")
    result: dict[str, Any] = {
        **base,
        "schema_version": "3.0",
        "artifact_sha256": str(next(iter(artifact_digests))),
        "slsa_level": slsa["slsa_level"],
        "verified_by": ["sigstore", "slsa", "vsa"],
        "slsa_envelope_sha256": slsa["envelope_sha256"],
        "resolved_dependencies_sha256": slsa["resolved_dependencies_sha256"],
        "sigstore_bundle_sha256": sigstore["bundle_sha256"],
        "sigstore_trusted_root_sha256": sigstore["trusted_root_sha256"],
        "vsa_sha256": vsa["envelope_sha256"],
        "vsa_policy_sha256": vsa["policy_sha256"],
    }
    if (
        slsa.get("dependency_manifest_verified") == "true"
        and vsa.get("dependency_closure_verified") == "true"
        and _is_digest(str(vsa.get("dependency_levels_sha256") or ""))
    ):
        result["verified_by"].insert(0, "dependency-closure")
    return result


def _valid_signature(
    key: Ed25519PublicKey, value: object, key_id: str, payload: bytes
) -> bool:
    if (
        not isinstance(value, dict)
        or set(value) != {"keyid", "sig"}
        or value.get("keyid") != key_id
    ):
        return False
    try:
        key.verify(base64.b64decode(str(value["sig"]), validate=True), payload)
    except (InvalidSignature, ValueError):
        return False
    return True


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _sigstore_tlog_entries(bundle: Path) -> int:
    try:
        value = strict_loads(_bounded(bundle, "Sigstore bundle", 16 * 1024 * 1024))
    except (TypeError, ValueError) as exc:
        raise ValueError("Sigstore bundle is not valid strict JSON") from exc

    def locate(item: object) -> list[object] | None:
        if isinstance(item, dict):
            entries = item.get("tlogEntries")
            if isinstance(entries, list):
                return entries
            for nested in item.values():
                found = locate(nested)
                if found is not None:
                    return found
        elif isinstance(item, list):
            for nested in item:
                found = locate(nested)
                if found is not None:
                    return found
        return None

    entries = locate(value)
    if not entries:
        raise ValueError("Sigstore bundle contains no transparency-log entries")
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or "logIndex" not in entry
            or "logId" not in entry
            or not ({"inclusionPromise", "inclusionProof"} & set(entry))
        ):
            raise ValueError("Sigstore transparency-log material is incomplete")
    return len(entries)


def _verify_vsa_signer_policy(key_id: str, verifier_id: str) -> None:
    raw = os.environ.get("PYSEC_VSA_SIGNER_VERIFIERS", "")
    try:
        value = strict_loads(raw.encode())
    except (TypeError, ValueError) as exc:
        raise ValueError("VSA signer-verifier policy is invalid") from exc
    allowed = value.get(key_id) if isinstance(value, dict) else None
    if not isinstance(allowed, list) or verifier_id not in allowed:
        raise ValueError("VSA signer is not authorized for the declared verifier")


def _verify_vsa_key_lifecycle(key_id: str, observed_at: datetime) -> None:
    raw = os.environ.get("PYSEC_VSA_KEY_LIFECYCLE", "")
    try:
        value = strict_loads(raw.encode())
    except (TypeError, ValueError) as exc:
        raise ValueError("VSA key lifecycle policy is invalid") from exc
    record = value.get(key_id) if isinstance(value, dict) else None
    if not isinstance(record, dict) or set(record) != {
        "not_before",
        "not_after",
        "revoked_at",
    }:
        raise ValueError("VSA verifier key lifecycle is not configured")
    not_before = _timestamp(record.get("not_before"), "VSA key not_before")
    not_after = _timestamp(record.get("not_after"), "VSA key not_after")
    revoked = record.get("revoked_at")
    revoked_at = (
        _timestamp(revoked, "VSA key revoked_at") if revoked not in {None, ""} else None
    )
    if not not_before <= observed_at <= not_after or (
        revoked_at is not None and observed_at >= revoked_at
    ):
        raise ValueError("VSA verifier key is expired, not yet valid, or revoked")


def _timestamp(value: object, label: str) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if result.tzinfo is None:
        raise ValueError(f"{label} requires a timezone")
    return result.astimezone(UTC)


def _builder_policy(builder_id: str, key_id: str) -> int:
    raw = os.environ.get("PYSEC_SLSA_BUILDER_POLICY", "")
    if not raw:
        raise ValueError("SLSA builder policy is not configured")
    try:
        policy = strict_loads(raw.encode())
    except (TypeError, ValueError) as exc:
        raise ValueError("SLSA builder policy is invalid JSON") from exc
    record = policy.get(builder_id) if isinstance(policy, dict) else None
    if (
        not isinstance(record, dict)
        or set(record) != {"key_sha256", "maximum_slsa_level"}
        or record.get("key_sha256") != key_id
        or isinstance(record.get("maximum_slsa_level"), bool)
        or record.get("maximum_slsa_level") not in {1, 2, 3}
    ):
        raise ValueError("SLSA builder identity is not deployment-approved")
    return int(record["maximum_slsa_level"])


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    encoded_type = payload_type.encode("utf-8")
    return b" ".join(
        (
            b"DSSEv1",
            str(len(encoded_type)).encode(),
            encoded_type,
            str(len(payload)).encode(),
            payload,
        )
    )


def _bounded(path: Path, label: str, maximum: int = 64 * 1024 * 1024) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError(f"{label} must be a bounded regular file")
    return path.read_bytes()


def _sha256(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular file")
    if path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError(f"{label} exceeds 256 MiB")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _builder_id(value: str) -> str:
    result = value.strip()
    if (
        not result
        or len(result) > 200
        or any(ord(character) < 32 for character in result)
    ):
        raise ValueError("builder-id is invalid")
    return result


def _digest_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
