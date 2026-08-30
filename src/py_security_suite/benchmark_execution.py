from __future__ import annotations

import hashlib
import base64
import os
import re
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any, Callable, ParamSpec, TypeVar, cast

import psutil
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from .benchmark_assurance import (
    BENCHMARK_REPLAY_GENESIS_SHA256,
    BenchmarkAssuranceError,
    BenchmarkReplayLease,
    consume_benchmark_replay,
    load_authority_trust_policy,
    load_benchmark_replay_checkpoint,
    load_benchmark_replay_intent,
    recover_benchmark_replay_intent,
    reconcile_completed_benchmark_replay_intent,
    remove_benchmark_replay_intent,
    sign_execution_receipt,
    sign_execution_receipt_with_provider,
    validate_trusted_authority,
    write_benchmark_replay_checkpoint,
    write_benchmark_replay_intent,
)
from .benchmark_signing import ReceiptSigningProvider
from .benchmark_telemetry import BenchmarkSecurityEventRecorder, SecurityEventSink
from .benchmark_evidence import (
    BenchmarkEvidenceError,
    verify_benchmark_evidence_documents,
    verify_benchmark_trusted_time,
)
from .benchmark_input_validation import (
    BenchmarkInputError,
    validate_benchmark_input,
)
from .benchmark_pipeline import (
    BenchmarkExecutionPhase,
    BenchmarkExecutionTracker,
    evaluate_normalized_payload,
    run_benchmark_stages,
)
from .benchmark_receipt import build_benchmark_execution_receipt
from .benchmark_protocols import (
    PROTOCOL_MINIMUM_CASES,
    PROTOCOL_THRESHOLD_FIELDS,
    validate_protocol_thresholds,
)
from .benchmark_runtime import (
    BenchmarkRuntimeError,
    build_stage_argv,
    oci_output_gaps,
    prepare_oci_output_directory,
    verify_oci_runtime_capabilities,
)
from .benchmark_scoring import (  # noqa: F401 - schema 1.x compatibility exports
    _score_normalized_result,
    _threshold_failures,
)
from .path_safety import read_regular_file, resolve_regular_file, resolve_unlinked_path
from .strict_json import canonical_bytes, loads as strict_loads


_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_MAX_RESULT_BYTES = 64 * 1024 * 1024
_MAX_CAPTURE_BYTES = 128 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_STAGE_NAMES = {"prepare", "build", "run", "normalize", "verify", "cleanup"}
_PROTOCOLS = set(PROTOCOL_THRESHOLD_FIELDS)
_ATTESTATION_KINDS = {
    "trusted_time": "trusted-time",
    "replay_protection": "replay-protection",
    "contamination_manifest": "contamination-manifest",
    "runner_sbom": "runner-sbom",
    "runner_provenance": "runner-provenance",
    "environment": "environment",
}
_ASSURANCE_ATTESTATION_KINDS = {
    "acceptance_criteria": "acceptance-criteria",
    "adapter_conformance": "adapter-conformance",
    "runtime_observation": "runtime-observation",
}
_ENHANCED_SCHEMA_VERSIONS = frozenset({"1.1", "1.2"})
_P = ParamSpec("_P")
_R = TypeVar("_R")


def _is_enhanced_manifest(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.get("schema_version") in _ENHANCED_SCHEMA_VERSIONS
    )


class BenchmarkExecutionError(ValueError):
    """Raised when a benchmark cannot be executed without weakening its contract."""


def _audit_benchmark_failures(function: Callable[_P, _R]) -> Callable[_P, _R]:
    @wraps(function)
    def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        try:
            return function(*args, **kwargs)
        except (OSError, ValueError) as exc:
            raw_sink = cast(dict[str, Any], kwargs).get("security_event_sink")
            sink = cast(SecurityEventSink | None, raw_sink)
            if sink is not None:
                BenchmarkSecurityEventRecorder(sink).record(
                    "benchmark-execution",
                    "failed",
                    details={"error_type": type(exc).__name__},
                )
            raise

    return wrapped


@_audit_benchmark_failures
def execute_benchmark_manifest(
    manifest_path: Path,
    workspace: Path,
    *,
    authorized: bool,
    known_benchmark_ids: set[str] | None = None,
    benchmark_contracts: dict[str, dict[str, Any]] | None = None,
    allow_legacy_unregistered: bool = False,
    authority_trust_policy: Path | None = None,
    authority_trust_policy_sha256: str = "",
    authority_trust_policy_signature: Path | None = None,
    authority_trust_root: Path | None = None,
    authority_trust_root_sha256: str = "",
    trusted_time_context: Path | None = None,
    trusted_time_context_sha256: str = "",
    replay_ledger: Path | None = None,
    replay_minimum_sequence: int = 0,
    replay_checkpoint_sha256: str = BENCHMARK_REPLAY_GENESIS_SHA256,
    replay_checkpoint_state: Path | None = None,
    initialize_replay_checkpoint: bool = False,
    receipt_signing_key: Path | None = None,
    receipt_signing_key_sha256: str = "",
    receipt_signing_provider: ReceiptSigningProvider | None = None,
    security_event_sink: SecurityEventSink | None = None,
) -> dict[str, Any]:
    """Execute a digest-pinned benchmark adapter and score normalized cases.

    The manifest is deliberately an execution authorization boundary. Commands are
    never passed through a shell, inherited environment variables are minimized,
    executables and the input corpus are verified immediately before execution, and
    every stage is bounded by a timeout and captured-output limit.
    """
    security_events = BenchmarkSecurityEventRecorder(security_event_sink)
    tracker = BenchmarkExecutionTracker()
    if not authorized:
        security_events.record("execution-authorization", "failed")
        tracker.fail()
        raise BenchmarkExecutionError(
            "benchmark execution requires explicit --authorize-execution"
        )
    tracker.advance(BenchmarkExecutionPhase.AUTHORIZED)
    try:
        manifest_file, payload = read_regular_file(
            manifest_path,
            "benchmark adapter manifest",
            maximum_bytes=_MAX_MANIFEST_BYTES,
        )
    except (OSError, ValueError):
        security_events.record("manifest-admission", "failed")
        raise
    try:
        manifest = strict_loads(payload)
    except (ValueError, TypeError) as exc:
        security_events.record("manifest-admission", "failed")
        raise BenchmarkExecutionError(
            "benchmark adapter manifest is invalid JSON"
        ) from exc
    if benchmark_contracts is None and not allow_legacy_unregistered:
        from .benchmark_adapters import benchmark_execution_contracts

        benchmark_contracts = benchmark_execution_contracts()
    registered_contract = _validate_manifest(
        manifest,
        known_benchmark_ids=known_benchmark_ids,
        benchmark_contracts=benchmark_contracts,
    )
    tracker.advance(BenchmarkExecutionPhase.MANIFEST_ADMITTED)

    work = resolve_unlinked_path(workspace, "benchmark workspace")
    if not work.is_dir():
        raise BenchmarkExecutionError(f"benchmark workspace is not a directory: {work}")
    trust_policy: dict[str, Any] | None = None
    if _is_enhanced_manifest(manifest):
        if authority_trust_policy is None:
            raise BenchmarkExecutionError(
                "schema 1.1 requires a deployment authority trust policy"
            )
        if replay_ledger is None:
            raise BenchmarkExecutionError(
                "schema 1.1 requires a deployment-owned replay ledger"
            )
        if replay_checkpoint_state is None:
            raise BenchmarkExecutionError(
                "schema 1.1 requires a deployment-retained replay checkpoint state"
            )
        if authority_trust_policy_signature is None:
            raise BenchmarkExecutionError(
                "schema 1.1 requires a detached authority policy signature"
            )
        if authority_trust_root is None:
            raise BenchmarkExecutionError(
                "schema 1.1 requires a deployment authority trust root"
            )
        if trusted_time_context is None:
            raise BenchmarkExecutionError(
                "schema 1.1 requires a raw trusted-time context"
            )
        if receipt_signing_key is None and receipt_signing_provider is None:
            raise BenchmarkExecutionError(
                "schema 1.1 requires a deployment receipt signing provider"
            )
        try:
            trust_policy = load_authority_trust_policy(
                authority_trust_policy,
                authority_trust_policy_sha256,
                signature_path=authority_trust_policy_signature,
                trust_root_path=authority_trust_root,
                trust_root_sha256=authority_trust_root_sha256,
                workspace=work,
                manifest_policy=manifest["authority_policy"],
            )
            security_events.record("authority-policy", "passed")
        except BenchmarkAssuranceError as exc:
            security_events.record("authority-policy", "failed")
            raise BenchmarkExecutionError(str(exc)) from exc
    isolation_runtime_proof: dict[str, Any] | None = None
    if _is_enhanced_manifest(manifest) and manifest["isolation"]["mode"] == "oci":
        try:
            isolation_runtime_proof = verify_oci_runtime_capabilities(
                manifest["isolation"]["oci"]
            )
            _prepare_oci_output_directory(work)
            security_events.record("oci-runtime-capabilities", "passed")
        except BenchmarkRuntimeError as exc:
            security_events.record("oci-runtime-capabilities", "failed")
            raise BenchmarkExecutionError(str(exc)) from exc
    _verify_adapter_contract_inputs(manifest, work, registered_contract)
    corpus = _resolve_workspace_file(
        work, Path(manifest["corpus"]["path"]), "benchmark corpus"
    )
    corpus_sha256 = _sha256_file(corpus)
    if corpus_sha256 != manifest["corpus"]["sha256"]:
        raise BenchmarkExecutionError("benchmark corpus digest does not match manifest")

    subject_sha256 = _benchmark_subject_sha256(manifest, corpus_sha256)
    if _is_enhanced_manifest(manifest):
        if (
            receipt_signing_key is None
            and receipt_signing_provider is None
            or trust_policy is None
        ):
            raise BenchmarkExecutionError(
                "deployment receipt signing configuration is unavailable"
            )
        try:
            # Validate private-key integrity and policy admission before consuming
            # the single-use replay nonce or launching untrusted code.
            _sign_receipt(
                {
                    "schema_version": "1.1-signing-preflight",
                    "benchmark_subject_sha256": subject_sha256,
                },
                signing_key_path=receipt_signing_key,
                signing_key_sha256=receipt_signing_key_sha256,
                workspace=work,
                trust_policy=trust_policy,
                signing_provider=receipt_signing_provider,
            )
        except BenchmarkAssuranceError as exc:
            security_events.record("receipt-signer", "failed")
            raise BenchmarkExecutionError(str(exc)) from exc
    tracker.advance(BenchmarkExecutionPhase.TRUST_ADMITTED)
    verified_attestations = _verify_attestations(
        manifest,
        work,
        subject_sha256,
        trust_policy=trust_policy,
    )
    verified_trusted_time: dict[str, str] | None = None
    if _is_enhanced_manifest(manifest):
        if trusted_time_context is None:
            raise BenchmarkExecutionError(
                "schema 1.1 requires a raw trusted-time context"
            )
        try:
            verified_trusted_time = verify_benchmark_trusted_time(
                trusted_time_context,
                trusted_time_context_sha256,
                workspace=work,
                subject_sha256=subject_sha256,
                claims=_required_claims(verified_attestations, "trusted_time"),
            )
        except BenchmarkEvidenceError as exc:
            security_events.record("evidence-replay", "failed")
            raise BenchmarkExecutionError(str(exc)) from exc
    _verify_evidence_bindings(manifest, verified_attestations, corpus_sha256)
    verified_evidence_documents: dict[str, Any] | None = None
    if _is_enhanced_manifest(manifest):
        if trust_policy is None:
            raise BenchmarkExecutionError(
                "deployment authority trust policy is unavailable"
            )
        try:
            verified_evidence_documents = verify_benchmark_evidence_documents(
                work,
                manifest,
                verified_attestations,
                trust_policy=trust_policy,
            )
            security_events.record("evidence-replay", "passed")
        except BenchmarkEvidenceError as exc:
            security_events.record("evidence-replay", "failed")
            raise BenchmarkExecutionError(str(exc)) from exc
    immutable_snapshot = _execution_input_snapshot(
        manifest_file,
        work,
        manifest,
        verified_attestations,
        deployment_inputs=tuple(
            item
            for item in (
                authority_trust_policy,
                authority_trust_policy_signature,
                authority_trust_root,
                trusted_time_context,
                receipt_signing_key,
            )
            if item is not None
        )
        if _is_enhanced_manifest(manifest)
        else (),
    )
    tracker.advance(BenchmarkExecutionPhase.EVIDENCE_VERIFIED)
    replay_receipt: dict[str, Any] | None = None
    retained_replay_checkpoint: dict[str, Any] | None = None
    if _is_enhanced_manifest(manifest):
        if (
            replay_ledger is None
            or replay_checkpoint_state is None
            or (receipt_signing_key is None and receipt_signing_provider is None)
            or trust_policy is None
        ):
            raise BenchmarkExecutionError(
                "schema 1.1 replay continuity configuration is unavailable"
            )
        replay_claims = _required_claims(verified_attestations, "replay_protection")
        replay_lease = BenchmarkReplayLease(
            replay_checkpoint_state.with_name(replay_checkpoint_state.name + ".lock"),
            workspace=work,
        )
        replay_lease.acquire()
        try:
            retained_replay_checkpoint = load_benchmark_replay_checkpoint(
                replay_checkpoint_state,
                ledger=replay_ledger,
                workspace=work,
                trust_policy=trust_policy,
            )
            if retained_replay_checkpoint is None and not initialize_replay_checkpoint:
                raise BenchmarkAssuranceError(
                    "benchmark replay checkpoint is absent; explicit initialization "
                    "is required"
                )
            minimum_sequence = (
                int(retained_replay_checkpoint["sequence"])
                if retained_replay_checkpoint is not None
                else replay_minimum_sequence
            )
            expected_checkpoint = (
                str(retained_replay_checkpoint["checkpoint_sha256"])
                if retained_replay_checkpoint is not None
                else replay_checkpoint_sha256
            )
            nonce_sha256 = _claim_digest(replay_claims, "nonce_sha256")
            replay_signer_key_id = verified_attestations["replay_protection"][
                "signer_key_id"
            ]
            replay_intent_path = replay_checkpoint_state.with_name(
                replay_checkpoint_state.name + ".intent"
            )
            replay_intent: dict[str, Any] | None = None
            if manifest["schema_version"] == "1.2":
                reconcile_completed_benchmark_replay_intent(
                    replay_intent_path,
                    ledger=replay_ledger,
                    workspace=work,
                    trust_policy=trust_policy,
                    retained_checkpoint=retained_replay_checkpoint,
                )
                replay_intent = load_benchmark_replay_intent(
                    replay_intent_path,
                    ledger=replay_ledger,
                    workspace=work,
                    trust_policy=trust_policy,
                    sequence=minimum_sequence,
                    checkpoint_sha256=expected_checkpoint,
                    nonce_sha256=nonce_sha256,
                    subject_sha256=subject_sha256,
                    signer_key_id=replay_signer_key_id,
                )
                if replay_intent is None:
                    replay_intent = write_benchmark_replay_intent(
                        replay_intent_path,
                        ledger=replay_ledger,
                        sequence=minimum_sequence,
                        checkpoint_sha256=expected_checkpoint,
                        nonce_sha256=nonce_sha256,
                        subject_sha256=subject_sha256,
                        signer_key_id=replay_signer_key_id,
                        signing_key_path=receipt_signing_key,
                        signing_key_sha256=receipt_signing_key_sha256,
                        workspace=work,
                        trust_policy=trust_policy,
                        signing_provider=receipt_signing_provider,
                    )
                replay_receipt = recover_benchmark_replay_intent(
                    replay_intent, ledger=replay_ledger, workspace=work
                )
            if replay_receipt is None:
                replay_receipt = consume_benchmark_replay(
                    replay_ledger,
                    workspace=work,
                    nonce_sha256=nonce_sha256,
                    subject_sha256=subject_sha256,
                    signer_key_id=replay_signer_key_id,
                    minimum_sequence=minimum_sequence,
                    expected_checkpoint_sha256=expected_checkpoint,
                    require_current_head=manifest["schema_version"] == "1.2",
                )
            retained_replay_checkpoint = write_benchmark_replay_checkpoint(
                replay_checkpoint_state,
                replay_receipt,
                ledger=replay_ledger,
                signing_key_path=receipt_signing_key,
                signing_key_sha256=receipt_signing_key_sha256,
                workspace=work,
                trust_policy=trust_policy,
                signing_provider=receipt_signing_provider,
            )
            if manifest["schema_version"] == "1.2":
                remove_benchmark_replay_intent(replay_intent_path, workspace=work)
            security_events.record(
                "replay-continuity",
                "passed",
                details={"sequence": replay_receipt["sequence"]},
            )
        except BenchmarkAssuranceError as exc:
            security_events.record("replay-continuity", "failed")
            raise BenchmarkExecutionError(str(exc)) from exc
        finally:
            replay_lease.release()
    tracker.advance(BenchmarkExecutionPhase.REPLAY_COMMITTED)
    execution_id = hashlib.sha256(
        canonical_bytes(manifest) + corpus_sha256.encode("ascii")
    ).hexdigest()
    started = datetime.now(UTC).isoformat()
    stage_result = run_benchmark_stages(
        manifest["stages"],
        lambda stage: _execute_stage(stage, work, corpus, manifest["isolation"]),
    )
    stages = stage_result.stages
    decision = stage_result.decision
    failure_reason = stage_result.failure_reason
    tracker.advance(BenchmarkExecutionPhase.STAGES_EXECUTED)

    input_integrity_gaps = _runtime_input_integrity_gaps(
        manifest,
        work,
        corpus,
        immutable_snapshot,
    )
    if input_integrity_gaps:
        decision = "fail"
        failure_reason = "; ".join(input_integrity_gaps)
    tracker.advance(BenchmarkExecutionPhase.INPUTS_REVERIFIED)

    metrics: dict[str, Any] | None = None
    statistical_sufficiency = {
        "enforced": _is_enhanced_manifest(manifest),
        "complete": not _is_enhanced_manifest(manifest),
        "gaps": [],
    }
    normalized_sha256: str | None = None
    case_count = 0
    if decision == "pass":
        result_path = _resolve_workspace_file(
            work,
            Path(manifest["normalized_result"]["path"]),
            "normalized benchmark result",
        )
        _, result_payload = read_regular_file(
            result_path,
            "normalized benchmark result",
            maximum_bytes=_MAX_RESULT_BYTES,
            boundary=work,
        )
        normalized_sha256 = hashlib.sha256(result_payload).hexdigest()
        expected_result_digest = manifest["normalized_result"].get("sha256")
        if expected_result_digest and normalized_sha256 != expected_result_digest:
            decision = "fail"
            failure_reason = "normalized result digest does not match manifest"
        else:
            evaluation = evaluate_normalized_payload(
                result_payload,
                manifest=manifest,
                enhanced=_is_enhanced_manifest(manifest),
            )
            metrics = evaluation.metrics
            case_count = evaluation.case_count
            statistical_sufficiency = evaluation.statistical_sufficiency
            if evaluation.failure_reason is not None:
                decision = "fail"
                failure_reason = evaluation.failure_reason
    tracker.advance(BenchmarkExecutionPhase.SCORED)

    receipt = build_benchmark_execution_receipt(
        manifest=manifest,
        execution_id=execution_id,
        manifest_sha256=hashlib.sha256(payload).hexdigest(),
        manifest_path=str(manifest_file),
        corpus_sha256=corpus_sha256,
        normalized_result_sha256=normalized_sha256,
        started_at=started,
        case_count=case_count,
        metrics=metrics,
        statistical_sufficiency=statistical_sufficiency,
        input_integrity_gaps=input_integrity_gaps,
        subject_sha256=subject_sha256,
        attestations=verified_attestations,
        evidence_documents=verified_evidence_documents,
        replay_receipt=replay_receipt,
        replay_checkpoint_state=retained_replay_checkpoint,
        trust_policy=trust_policy,
        trusted_time_proof=verified_trusted_time,
        stages=stages,
        isolation_runtime_proof=isolation_runtime_proof,
        decision=decision,
        failure_reason=failure_reason,
    )
    if manifest["schema_version"] == "1.2":
        security_events.record(
            "benchmark-decision",
            "passed" if decision == "pass" else "failed",
            details={"decision": decision},
        )
        receipt["security_events"] = security_events.export()
    receipt.update(_canonical_industry_evidence(receipt, manifest))
    receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    tracker.advance(BenchmarkExecutionPhase.RECEIPT_ASSEMBLED)
    if _is_enhanced_manifest(manifest):
        if (
            receipt_signing_key is None
            and receipt_signing_provider is None
            or trust_policy is None
        ):
            raise BenchmarkExecutionError(
                "deployment receipt signing configuration is unavailable"
            )
        try:
            receipt["receipt_signature"] = _sign_receipt(
                receipt,
                signing_key_path=receipt_signing_key,
                signing_key_sha256=receipt_signing_key_sha256,
                workspace=work,
                trust_policy=trust_policy,
                signing_provider=receipt_signing_provider,
            )
        except BenchmarkAssuranceError as exc:
            raise BenchmarkExecutionError(str(exc)) from exc
        tracker.advance(BenchmarkExecutionPhase.RECEIPT_SIGNED)
    tracker.advance(BenchmarkExecutionPhase.COMPLETED)
    return receipt


def _sign_receipt(
    receipt: dict[str, Any],
    *,
    signing_key_path: Path | None,
    signing_key_sha256: str,
    workspace: Path,
    trust_policy: dict[str, Any],
    signing_provider: ReceiptSigningProvider | None,
) -> dict[str, str]:
    if signing_provider is not None:
        return sign_execution_receipt_with_provider(
            receipt,
            provider=signing_provider,
            trust_policy=trust_policy,
        )
    if signing_key_path is None:
        raise BenchmarkAssuranceError("receipt signing provider is unavailable")
    return sign_execution_receipt(
        receipt,
        signing_key_path=signing_key_path,
        signing_key_sha256=signing_key_sha256,
        workspace=workspace,
        trust_policy=trust_policy,
    )


def _validate_manifest(
    value: object,
    *,
    known_benchmark_ids: set[str] | None,
    benchmark_contracts: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        raise BenchmarkExecutionError("benchmark adapter manifest must be an object")
    required = {
        "schema_version",
        "benchmark_id",
        "benchmark_version",
        "adapter_version",
        "protocol",
        "corpus",
        "stages",
        "normalized_result",
        "thresholds",
        "isolation",
        "attestations",
    }
    if _is_enhanced_manifest(value):
        required |= {"adapter_contract", "evaluation", "authority_policy"}
    if set(value) != required:
        raise BenchmarkExecutionError(
            "benchmark adapter manifest properties do not match its schema contract"
        )
    if value["schema_version"] not in {"1.0", "1.1", "1.2"}:
        raise BenchmarkExecutionError("unsupported benchmark adapter schema version")
    identifier = value["benchmark_id"]
    if not isinstance(identifier, str) or not _IDENTIFIER.fullmatch(identifier):
        raise BenchmarkExecutionError("benchmark_id is invalid")
    if known_benchmark_ids is not None and identifier not in known_benchmark_ids:
        raise BenchmarkExecutionError("benchmark_id is not registered")
    registered_contract = (
        benchmark_contracts.get(identifier) if benchmark_contracts is not None else None
    )
    if benchmark_contracts is not None and registered_contract is None:
        raise BenchmarkExecutionError(
            "benchmark_id has no registered execution contract"
        )
    for field in ("benchmark_version", "adapter_version"):
        if not isinstance(value[field], str) or not 1 <= len(value[field]) <= 128:
            raise BenchmarkExecutionError(f"{field} is invalid")
    if value["protocol"] not in _PROTOCOLS:
        raise BenchmarkExecutionError("benchmark protocol is invalid")
    if registered_contract is not None:
        if value["protocol"] != registered_contract.get("protocol"):
            raise BenchmarkExecutionError("benchmark protocol does not match registry")
        if value["benchmark_version"] != registered_contract.get("version"):
            raise BenchmarkExecutionError("benchmark version does not match registry")
    _validate_corpus(value["corpus"])
    stages = value["stages"]
    if not isinstance(stages, list) or not 1 <= len(stages) <= 12:
        raise BenchmarkExecutionError("stages must contain between 1 and 12 entries")
    names: list[str] = []
    for stage in stages:
        _validate_stage(stage)
        names.append(stage["name"])
    if len(names) != len(set(names)):
        raise BenchmarkExecutionError("benchmark stage names must be unique")
    if "run" not in names:
        raise BenchmarkExecutionError("benchmark adapter requires a run stage")
    _validate_result(value["normalized_result"])
    _validate_thresholds(value["thresholds"], value["protocol"])
    if _is_enhanced_manifest(value):
        _validate_adapter_contract(value["adapter_contract"], registered_contract)
        _validate_evaluation(value["evaluation"], value["protocol"])
        _validate_authority_policy(value["authority_policy"])
    attestations = value["attestations"]
    expected_attestations = set(_ATTESTATION_KINDS)
    if _is_enhanced_manifest(value):
        expected_attestations.update(_ASSURANCE_ATTESTATION_KINDS)
    if (
        _is_enhanced_manifest(value)
        and isinstance(value.get("isolation"), dict)
        and value["isolation"].get("mode") == "external-sandbox"
    ):
        expected_attestations.add("external_isolation")
    if (
        _is_enhanced_manifest(value)
        and registered_contract is not None
        and registered_contract.get("lane") == "authorized-companion"
    ):
        expected_attestations.add("cleanup_capability")
    if not isinstance(attestations, dict) or set(attestations) != expected_attestations:
        raise BenchmarkExecutionError("benchmark attestations are invalid")
    for reference in attestations.values():
        _validate_attestation_reference(
            reference, schema_version=str(value["schema_version"])
        )
    isolation = value["isolation"]
    if not isinstance(isolation, dict) or set(isolation) != {
        "mode",
        "network_policy",
        "disposable_target",
        "external_receipt_sha256",
        "oci",
    }:
        raise BenchmarkExecutionError("isolation contract is invalid")
    if isolation["mode"] not in {"process", "external-sandbox", "oci"}:
        raise BenchmarkExecutionError("unsupported isolation mode")
    if isolation["network_policy"] not in {
        "deny",
        "authorized-target-only",
        "inherited",
    }:
        raise BenchmarkExecutionError("unsupported network policy")
    receipt_digest = isolation["external_receipt_sha256"]
    if receipt_digest is not None and not (
        isinstance(receipt_digest, str) and _DIGEST.fullmatch(receipt_digest)
    ):
        raise BenchmarkExecutionError("external isolation receipt digest is invalid")
    if isolation["mode"] == "process" and isolation["network_policy"] != "inherited":
        raise BenchmarkExecutionError(
            "process mode cannot claim an enforced network policy"
        )
    if isolation["mode"] == "external-sandbox" and receipt_digest is None:
        raise BenchmarkExecutionError(
            "external-sandbox mode requires a digest-bound isolation receipt"
        )
    if (
        _is_enhanced_manifest(value)
        and isolation["mode"] == "external-sandbox"
        and attestations["external_isolation"]["sha256"] != receipt_digest
    ):
        raise BenchmarkExecutionError(
            "external isolation attestation does not match the isolation receipt"
        )
    if isolation["mode"] == "oci":
        _validate_oci(isolation["oci"], enhanced=_is_enhanced_manifest(value))
        if isolation["network_policy"] != "deny":
            raise BenchmarkExecutionError(
                "OCI mode currently requires denied networking"
            )
        if _is_enhanced_manifest(value):
            normalized_path = Path(value["normalized_result"]["path"])
            if (
                normalized_path.is_absolute()
                or not normalized_path.parts
                or normalized_path.parts[0] != ".pysec-output"
            ):
                raise BenchmarkExecutionError(
                    "schema 1.1 OCI output must remain under .pysec-output"
                )
    elif isolation["oci"] is not None:
        raise BenchmarkExecutionError("OCI configuration is only valid in OCI mode")
    if not isinstance(isolation["disposable_target"], bool):
        raise BenchmarkExecutionError("disposable_target must be boolean")
    if (
        registered_contract is not None
        and registered_contract.get("lane") == "authorized-companion"
    ):
        if not _is_enhanced_manifest(value):
            raise BenchmarkExecutionError(
                "authorized-companion benchmarks require manifest schema 1.1"
            )
        if isolation["mode"] == "process":
            raise BenchmarkExecutionError(
                "authorized-companion benchmarks require OCI or an external sandbox"
            )
        if isolation["network_policy"] == "inherited":
            raise BenchmarkExecutionError(
                "authorized-companion benchmarks cannot inherit network access"
            )
        if isolation["disposable_target"] is not True:
            raise BenchmarkExecutionError(
                "authorized-companion benchmarks require a disposable target"
            )
        if "cleanup" not in names:
            raise BenchmarkExecutionError(
                "authorized-companion benchmarks require a cleanup stage"
            )
    return registered_contract


def _validate_adapter_contract(
    value: object, registered_contract: dict[str, Any] | None
) -> None:
    required = {"id", "version", "sha256", "normalizer", "required_inputs"}
    if not isinstance(value, dict) or set(value) != required:
        raise BenchmarkExecutionError("adapter contract binding is invalid")
    if (
        not isinstance(value["id"], str)
        or not _IDENTIFIER.fullmatch(value["id"])
        or not isinstance(value["version"], str)
        or not value["version"]
        or not isinstance(value["sha256"], str)
        or not _DIGEST.fullmatch(value["sha256"])
        or not isinstance(value["normalizer"], str)
        or not value["normalizer"]
    ):
        raise BenchmarkExecutionError("adapter contract identity is invalid")
    inputs = value["required_inputs"]
    if not isinstance(inputs, list) or not 4 <= len(inputs) <= 128:
        raise BenchmarkExecutionError("adapter contract inputs are incomplete")
    names: set[str] = set()
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {
            "name",
            "path",
            "sha256",
            "validation",
        }:
            raise BenchmarkExecutionError("adapter contract input is invalid")
        if (
            not isinstance(item["name"], str)
            or not 1 <= len(item["name"]) <= 256
            or item["name"] in names
            or not isinstance(item["path"], str)
            or not item["path"]
            or not isinstance(item["sha256"], str)
            or not _DIGEST.fullmatch(item["sha256"])
            or not isinstance(item["validation"], dict)
            or item["validation"].get("validated") is not True
        ):
            raise BenchmarkExecutionError("adapter contract input identity is invalid")
        _validate_input_validation(item["validation"])
        names.add(item["name"])
    if registered_contract is None:
        return
    expected_digest = registered_contract.get("adapter_spec_sha256")
    expected_inputs = set(registered_contract.get("required_inputs", []))
    if expected_digest is not None and value["sha256"] != expected_digest:
        raise BenchmarkExecutionError("adapter contract digest does not match registry")
    if expected_inputs and names != expected_inputs:
        raise BenchmarkExecutionError(
            "adapter required inputs do not match the maintained contract"
        )
    expected_normalizer = registered_contract.get("normalizer")
    if expected_normalizer is not None and value["normalizer"] != expected_normalizer:
        raise BenchmarkExecutionError("adapter normalizer does not match registry")


def _validate_input_validation(value: object) -> None:
    if not isinstance(value, dict):
        raise BenchmarkExecutionError("adapter input validation is invalid")
    format_name = value.get("format")
    expected = {"format", "size_bytes", "entries", "validated"}
    if format_name in {"zip", "tar"}:
        expected.add("expanded_bytes")
    if (
        format_name not in {"opaque", "json", "zip", "tar"}
        or set(value) != expected
        or value.get("validated") is not True
    ):
        raise BenchmarkExecutionError("adapter input validation is invalid")
    for field in expected - {"format", "validated"}:
        item = value[field]
        if not isinstance(item, int) or isinstance(item, bool) or item < 1:
            raise BenchmarkExecutionError("adapter input validation count is invalid")


def _validate_evaluation(value: object, protocol: str) -> None:
    required = {
        "minimum_cases",
        "split_strategy",
        "positive_controls",
        "negative_controls",
        "acceptance_criteria_sha256",
        "independent_reviewers",
        "random_seeds",
        "required_strata",
        "power_analysis_sha256",
        "minimum_power",
        "confidence_level",
        "maximum_confidence_interval_width",
        "minimum_repetitions",
        "leakage_check_sha256",
        "duplicate_check_sha256",
        "holdout_sequestered",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise BenchmarkExecutionError("benchmark evaluation design is invalid")
    minimum_cases = value["minimum_cases"]
    if (
        not isinstance(minimum_cases, int)
        or isinstance(minimum_cases, bool)
        or minimum_cases < PROTOCOL_MINIMUM_CASES[protocol]
        or minimum_cases > 1_000_000
    ):
        raise BenchmarkExecutionError(
            f"benchmark minimum_cases must be at least {PROTOCOL_MINIMUM_CASES[protocol]}"
        )
    if value["split_strategy"] not in {
        "official-fixed",
        "project-split",
        "time-split",
    }:
        raise BenchmarkExecutionError("benchmark split strategy is invalid")
    for field in ("positive_controls", "negative_controls"):
        count = value[field]
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise BenchmarkExecutionError(f"benchmark {field} is invalid")
    if not isinstance(
        value["acceptance_criteria_sha256"], str
    ) or not _DIGEST.fullmatch(value["acceptance_criteria_sha256"]):
        raise BenchmarkExecutionError("acceptance criteria digest is invalid")
    for field in (
        "power_analysis_sha256",
        "leakage_check_sha256",
        "duplicate_check_sha256",
    ):
        if not isinstance(value[field], str) or not _DIGEST.fullmatch(value[field]):
            raise BenchmarkExecutionError(f"benchmark {field} is invalid")
    for field, minimum, maximum in (
        ("minimum_power", 0.8, 1.0),
        ("maximum_confidence_interval_width", 0.001, 0.5),
    ):
        item = value[field]
        if (
            not isinstance(item, (int, float))
            or isinstance(item, bool)
            or not minimum <= float(item) <= maximum
        ):
            raise BenchmarkExecutionError(f"benchmark {field} is invalid")
    if value["confidence_level"] != 0.95:
        raise BenchmarkExecutionError(
            "benchmark confidence_level must be 0.95 for Wilson 95% metrics"
        )
    repetitions = value["minimum_repetitions"]
    required_repetitions = 5 if protocol == "stochastic-adversarial" else 3
    if (
        not isinstance(repetitions, int)
        or isinstance(repetitions, bool)
        or not required_repetitions <= repetitions <= 1000
    ):
        raise BenchmarkExecutionError(
            f"benchmark minimum_repetitions must be at least {required_repetitions}"
        )
    if value["holdout_sequestered"] is not True:
        raise BenchmarkExecutionError("benchmark holdout must be sequestered")
    reviewers = value["independent_reviewers"]
    if (
        not isinstance(reviewers, int)
        or isinstance(reviewers, bool)
        or reviewers < (2 if protocol == "assessor-agreement" else 0)
    ):
        raise BenchmarkExecutionError("independent reviewer count is invalid")
    seeds = value["random_seeds"]
    if (
        not isinstance(seeds, list)
        or not seeds
        or len(seeds) != len(set(seeds))
        or not all(
            isinstance(seed, int) and not isinstance(seed, bool) and seed >= 0
            for seed in seeds
        )
        or (protocol == "stochastic-adversarial" and len(seeds) < 5)
    ):
        raise BenchmarkExecutionError("benchmark random seed plan is invalid")
    strata = value["required_strata"]
    if (
        not isinstance(strata, list)
        or len(strata) > 32
        or len(strata) != len(set(strata))
        or not all(isinstance(item, str) and 1 <= len(item) <= 128 for item in strata)
    ):
        raise BenchmarkExecutionError("benchmark required strata are invalid")


def _validate_authority_policy(value: object) -> None:
    required = {
        "minimum_distinct_signers",
        "minimum_distinct_organizations",
        "key_separation_groups",
        "organization_separation_groups",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise BenchmarkExecutionError("benchmark authority policy is invalid")
    for field, minimum in (
        ("minimum_distinct_signers", 4),
        ("minimum_distinct_organizations", 2),
    ):
        item = value[field]
        if (
            not isinstance(item, int)
            or isinstance(item, bool)
            or not minimum <= item <= 32
        ):
            raise BenchmarkExecutionError(f"benchmark {field} is invalid")
    known = (
        set(_ATTESTATION_KINDS)
        | set(_ASSURANCE_ATTESTATION_KINDS)
        | {
            "external_isolation",
            "cleanup_capability",
        }
    )
    for field in ("key_separation_groups", "organization_separation_groups"):
        groups = value[field]
        if not isinstance(groups, list) or not groups or len(groups) > 16:
            raise BenchmarkExecutionError(f"benchmark {field} is invalid")
        normalized: set[tuple[str, ...]] = set()
        for group in groups:
            if (
                not isinstance(group, list)
                or not 2 <= len(group) <= 8
                or len(group) != len(set(group))
                or any(item not in known for item in group)
            ):
                raise BenchmarkExecutionError(f"benchmark {field} is invalid")
            identity = tuple(sorted(group))
            if identity in normalized:
                raise BenchmarkExecutionError(f"benchmark {field} contains duplicates")
            normalized.add(identity)


def _verify_adapter_contract_inputs(
    manifest: dict[str, Any],
    workspace: Path,
    registered_contract: dict[str, Any] | None,
) -> None:
    if not _is_enhanced_manifest(manifest):
        return
    contract = manifest["adapter_contract"]
    for item in contract["required_inputs"]:
        path = _resolve_workspace_file(
            workspace, Path(item["path"]), f"adapter input {item['name']}"
        )
        if _sha256_file(path) != item["sha256"]:
            raise BenchmarkExecutionError(
                f"adapter input {item['name']} digest does not match"
            )
        try:
            validation = validate_benchmark_input(path)
        except BenchmarkInputError as exc:
            raise BenchmarkExecutionError(
                f"adapter input {item['name']} failed structural validation: {exc}"
            ) from exc
        if validation != item["validation"]:
            raise BenchmarkExecutionError(
                f"adapter input {item['name']} validation evidence changed"
            )
    if registered_contract is not None and contract["id"] != manifest["benchmark_id"]:
        raise BenchmarkExecutionError(
            "adapter contract identity does not match benchmark"
        )


def _validate_corpus(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "path",
        "sha256",
        "license_sha256",
        "label_authority_sha256",
        "organization_approved",
    }:
        raise BenchmarkExecutionError("corpus contract is invalid")
    if not isinstance(value["path"], str) or not value["path"]:
        raise BenchmarkExecutionError("corpus path is invalid")
    for field in ("sha256", "license_sha256", "label_authority_sha256"):
        if not isinstance(value[field], str) or not _DIGEST.fullmatch(value[field]):
            raise BenchmarkExecutionError(f"corpus {field} is invalid")
    if value["organization_approved"] is not True:
        raise BenchmarkExecutionError("benchmark corpus requires organization approval")


def _validate_stage(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "name",
        "executable",
        "executable_sha256",
        "arguments",
        "environment",
        "timeout_seconds",
        "expected_exit_codes",
    }:
        raise BenchmarkExecutionError("benchmark stage contract is invalid")
    if value["name"] not in _STAGE_NAMES:
        raise BenchmarkExecutionError("benchmark stage name is invalid")
    executable = value["executable"]
    if not isinstance(executable, str) or not Path(executable).is_absolute():
        raise BenchmarkExecutionError("stage executable must be an absolute path")
    if not isinstance(value["executable_sha256"], str) or not _DIGEST.fullmatch(
        value["executable_sha256"]
    ):
        raise BenchmarkExecutionError("stage executable digest is invalid")
    arguments = value["arguments"]
    if (
        not isinstance(arguments, list)
        or len(arguments) > 256
        or not all(
            isinstance(item, str) and len(item) <= 8192 and "\x00" not in item
            for item in arguments
        )
    ):
        raise BenchmarkExecutionError("stage arguments are invalid")
    environment = value["environment"]
    if not isinstance(environment, dict) or len(environment) > 64:
        raise BenchmarkExecutionError("stage environment is invalid")
    for key, item in environment.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", key):
            raise BenchmarkExecutionError("stage environment key is invalid")
        if not isinstance(item, str) or len(item) > 8192 or "\x00" in item:
            raise BenchmarkExecutionError("stage environment value is invalid")
    timeout = value["timeout_seconds"]
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 86400
    ):
        raise BenchmarkExecutionError("stage timeout is invalid")
    exit_codes = value["expected_exit_codes"]
    if (
        not isinstance(exit_codes, list)
        or not 1 <= len(exit_codes) <= 16
        or not all(
            isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255
            for item in exit_codes
        )
    ):
        raise BenchmarkExecutionError("stage expected exit codes are invalid")


def _validate_result(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise BenchmarkExecutionError("normalized result contract is invalid")
    if not isinstance(value["path"], str) or not value["path"]:
        raise BenchmarkExecutionError("normalized result path is invalid")
    if value["sha256"] is not None and not (
        isinstance(value["sha256"], str) and _DIGEST.fullmatch(value["sha256"])
    ):
        raise BenchmarkExecutionError("normalized result digest is invalid")


def _validate_attestation_reference(value: object, *, schema_version: str) -> None:
    required = {
        "path",
        "sha256",
        "media_type",
        "public_key_path",
        "public_key_sha256",
        "signature_path",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise BenchmarkExecutionError("attestation reference contract is invalid")
    for field in ("path", "public_key_path", "signature_path"):
        if not isinstance(value[field], str) or not value[field]:
            raise BenchmarkExecutionError(f"attestation {field} is invalid")
    expected_media_type = (
        f"application/vnd.pysec.attestation+json;version={schema_version}"
    )
    if value["media_type"] != expected_media_type:
        raise BenchmarkExecutionError("attestation media type is unsupported")
    for field in ("sha256", "public_key_sha256"):
        if not isinstance(value[field], str) or not _DIGEST.fullmatch(value[field]):
            raise BenchmarkExecutionError(f"attestation {field} is invalid")


def _validate_oci(value: object, *, enhanced: bool = False) -> None:
    expected = {
        "runtime",
        "runtime_sha256",
        "image",
        "memory_bytes",
        "cpu_count",
        "pids_limit",
        "seccomp_profile",
        "apparmor_profile",
    }
    if enhanced:
        expected |= {
            "runtime_name",
            "runtime_version",
            "runtime_capabilities_sha256",
            "runtime_trust_sha256",
            "seccomp_profile_sha256",
            "maximum_output_bytes",
            "maximum_output_files",
        }
    if not isinstance(value, dict) or set(value) != expected:
        raise BenchmarkExecutionError("OCI isolation contract is invalid")
    if (
        not isinstance(value["runtime"], str)
        or not Path(value["runtime"]).is_absolute()
    ):
        raise BenchmarkExecutionError("OCI runtime must be an absolute path")
    if not isinstance(value["runtime_sha256"], str) or not _DIGEST.fullmatch(
        value["runtime_sha256"]
    ):
        raise BenchmarkExecutionError("OCI runtime digest is invalid")
    if enhanced:
        if value["runtime_name"] not in {"docker", "podman", "nerdctl"}:
            raise BenchmarkExecutionError("OCI runtime identity is unsupported")
        if (
            not isinstance(value["runtime_version"], str)
            or not 1 <= len(value["runtime_version"]) <= 128
        ):
            raise BenchmarkExecutionError("OCI runtime version is invalid")
        for field in ("runtime_capabilities_sha256", "runtime_trust_sha256"):
            if not isinstance(value[field], str) or not _DIGEST.fullmatch(value[field]):
                raise BenchmarkExecutionError(f"OCI {field} is invalid")
        for field, minimum, maximum in (
            ("maximum_output_bytes", 1024 * 1024, 16 * 1024**3),
            ("maximum_output_files", 1, 100_000),
        ):
            item = value[field]
            if (
                not isinstance(item, int)
                or isinstance(item, bool)
                or not minimum <= item <= maximum
            ):
                raise BenchmarkExecutionError(f"OCI {field} is invalid")
    image = value["image"]
    if not isinstance(image, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9._/:~-]{0,511}@sha256:[0-9a-f]{64}", image
    ):
        raise BenchmarkExecutionError("OCI image must use an immutable sha256 digest")
    for field, minimum, maximum in (
        ("memory_bytes", 64 * 1024 * 1024, 1024**4),
        ("pids_limit", 16, 65536),
    ):
        item = value[field]
        if (
            not isinstance(item, int)
            or isinstance(item, bool)
            or not minimum <= item <= maximum
        ):
            raise BenchmarkExecutionError(f"OCI {field} is invalid")
    cpu_count = value["cpu_count"]
    if (
        not isinstance(cpu_count, (int, float))
        or isinstance(cpu_count, bool)
        or not 0.1 <= float(cpu_count) <= 256
    ):
        raise BenchmarkExecutionError("OCI cpu_count is invalid")
    profile = value["seccomp_profile"]
    if profile is not None and (
        not isinstance(profile, str) or not Path(profile).is_absolute()
    ):
        raise BenchmarkExecutionError("OCI seccomp profile must be an absolute path")
    if enhanced:
        profile_sha256 = value["seccomp_profile_sha256"]
        if profile is None:
            if profile_sha256 is not None:
                raise BenchmarkExecutionError(
                    "OCI seccomp digest requires a seccomp profile"
                )
        elif not isinstance(profile_sha256, str) or not _DIGEST.fullmatch(
            profile_sha256
        ):
            raise BenchmarkExecutionError("OCI seccomp profile digest is invalid")
    apparmor = value["apparmor_profile"]
    if apparmor is not None and (
        not isinstance(apparmor, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", apparmor)
    ):
        raise BenchmarkExecutionError("OCI AppArmor profile is invalid")


def _benchmark_subject_sha256(manifest: dict[str, Any], corpus_sha256: str) -> str:
    isolation = dict(manifest["isolation"])
    # The signed external-isolation attestation is itself the receipt. Excluding its
    # digest from the subject avoids a cryptographic fixed-point while every other
    # isolation property remains subject-bound.
    if isolation.get("mode") == "external-sandbox":
        isolation["external_receipt_sha256"] = None
    subject = {
        "benchmark_id": manifest["benchmark_id"],
        "benchmark_version": manifest["benchmark_version"],
        "adapter_version": manifest["adapter_version"],
        "protocol": manifest["protocol"],
        "corpus_sha256": corpus_sha256,
        "stage_executable_sha256": [
            {"name": item["name"], "sha256": item["executable_sha256"]}
            for item in manifest["stages"]
        ],
        "isolation": isolation,
    }
    if _is_enhanced_manifest(manifest):
        subject["adapter_contract"] = manifest["adapter_contract"]
        subject["evaluation"] = manifest["evaluation"]
        subject["authority_policy"] = manifest["authority_policy"]
    return hashlib.sha256(canonical_bytes(subject)).hexdigest()


def _verify_attestations(
    manifest: dict[str, Any],
    workspace: Path,
    subject_sha256: str,
    *,
    trust_policy: dict[str, Any] | None,
) -> dict[str, Any]:
    references = manifest["attestations"]
    results: dict[str, Any] = {}
    signer_ids: set[str] = set()
    organization_ids: set[str] = set()
    trusted_validation_time: datetime | None = None
    kinds = {
        **_ATTESTATION_KINDS,
        **(_ASSURANCE_ATTESTATION_KINDS if _is_enhanced_manifest(manifest) else {}),
        **(
            {"external_isolation": "external-isolation"}
            if "external_isolation" in references
            else {}
        ),
        **(
            {"cleanup_capability": "cleanup-capability"}
            if "cleanup_capability" in references
            else {}
        ),
    }
    for name, kind in kinds.items():
        reference = references[name]
        artifact = _resolve_workspace_file(workspace, Path(reference["path"]), kind)
        _, payload = read_regular_file(
            artifact, kind, maximum_bytes=_MAX_MANIFEST_BYTES, boundary=workspace
        )
        digest = hashlib.sha256(payload).hexdigest()
        if digest != reference["sha256"]:
            raise BenchmarkExecutionError(f"{kind} digest does not match manifest")
        key_path = _resolve_workspace_file(
            workspace, Path(reference["public_key_path"]), f"{kind} public key"
        )
        _, key_payload = read_regular_file(
            key_path, f"{kind} public key", maximum_bytes=64 * 1024, boundary=workspace
        )
        if hashlib.sha256(key_payload).hexdigest() != reference["public_key_sha256"]:
            raise BenchmarkExecutionError(f"{kind} public key digest does not match")
        signature_path = _resolve_workspace_file(
            workspace, Path(reference["signature_path"]), f"{kind} signature"
        )
        _, signature_payload = read_regular_file(
            signature_path, f"{kind} signature", maximum_bytes=4096, boundary=workspace
        )
        try:
            key = serialization.load_pem_public_key(key_payload)
            if not isinstance(key, Ed25519PublicKey):
                raise TypeError("not Ed25519")
            signature = base64.b64decode(signature_payload.strip(), validate=True)
            key.verify(signature, payload)
            document = strict_loads(payload)
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise BenchmarkExecutionError(f"{kind} signature is invalid") from exc
        authority = _validate_attestation_document(
            document,
            kind,
            subject_sha256,
            require_authority=_is_enhanced_manifest(manifest),
            schema_version=str(manifest["schema_version"]),
            validation_time=trusted_validation_time,
        )
        if kind == "trusted-time" and _is_enhanced_manifest(manifest):
            trusted_validation_time = _trusted_attestation_time(document["claims"])
        if _is_enhanced_manifest(manifest):
            if trust_policy is None:
                raise BenchmarkExecutionError(
                    "deployment authority trust policy is unavailable"
                )
            try:
                validate_trusted_authority(
                    kind=kind,
                    public_key_payload=key_payload,
                    authority=authority,
                    trust_policy=trust_policy,
                )
            except BenchmarkAssuranceError as exc:
                raise BenchmarkExecutionError(str(exc)) from exc
        signer = hashlib.sha256(
            key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).hexdigest()
        signer_ids.add(signer)
        if authority:
            organization_ids.add(str(authority["organization_id"]))
        results[name] = {
            "kind": kind,
            "sha256": digest,
            "signature_verified": True,
            "signer_key_id": signer,
            "subject_sha256": subject_sha256,
            "authority": authority,
            **_attestation_outcome(kind, document["claims"]),
        }
    if _is_enhanced_manifest(manifest):
        _enforce_authority_policy(results, manifest["authority_policy"])
    results["authority_summary"] = {
        "distinct_signers": len(signer_ids),
        "distinct_organizations": len(organization_ids),
        "all_signatures_verified": True,
        "policy_satisfied": _is_enhanced_manifest(manifest),
        "deployment_policy_id": (
            trust_policy["policy_id"] if trust_policy is not None else None
        ),
        "deployment_policy_sha256": (
            trust_policy["sha256"] if trust_policy is not None else None
        ),
    }
    return results


def _validate_attestation_document(
    value: object,
    kind: str,
    subject_sha256: str,
    *,
    require_authority: bool,
    schema_version: str = "1.1",
    validation_time: datetime | None = None,
) -> dict[str, Any]:
    if require_authority:
        _validate_enhanced_attestation_schema(value, kind, schema_version)
    required_fields = {
        "schema_version",
        "kind",
        "subject_sha256",
        "valid",
        "claims",
    }
    if require_authority:
        required_fields.add("authority")
    if not isinstance(value, dict) or set(value) != required_fields:
        raise BenchmarkExecutionError(f"{kind} attestation contract is invalid")
    if (
        value["schema_version"] != (schema_version if require_authority else "1.0")
        or value["kind"] != kind
        or value["subject_sha256"] != subject_sha256
        or value["valid"] is not True
        or not isinstance(value["claims"], dict)
    ):
        raise BenchmarkExecutionError(f"{kind} attestation is detached or invalid")
    authority: dict[str, Any] = {}
    if require_authority:
        authority = _validate_attestation_authority(
            value["authority"], kind, validation_time=validation_time
        )
    claims = value["claims"]
    required: dict[str, dict[str, object]] = {
        "trusted-time": {"rfc3161_verified": True, "monotonic_state_verified": True},
        "replay-protection": {"ledger_consumed": True, "nonce_unique": True},
        "contamination-manifest": {"checked": True, "contaminated": False},
        "runner-sbom": {"validated": True},
        "runner-provenance": {
            "signature_verified": True,
            "predicate_type": "https://slsa.dev/provenance/v1",
        },
        "environment": {"captured": True},
        "acceptance-criteria": {
            "pre_registered": True,
            "approved": True,
        },
        "adapter-conformance": {
            "passed": True,
            **(
                {
                    "parser_negative_controls_passed": True,
                    "semantic_inversion_controls_passed": True,
                }
                if schema_version == "1.2"
                else {
                    "golden_passed": True,
                    "malformed_rejected": True,
                    "label_inversion_detected": True,
                }
            ),
        },
        "runtime-observation": {
            "resource_limits_observed": True,
            "network_policy_observed": True,
            "egress_transcript_complete": True,
            "leakage_detected": False,
            "duplicate_count": 0,
        },
        "external-isolation": {
            "isolation_enforced": True,
            "network_policy_enforced": True,
            "disposable_target": True,
            "receipt_subject_verified": True,
            "runner_image_pinned": True,
            "runner_sbom_matches_image": True,
            "runner_provenance_verified": True,
            "provenance_subject_matches_image": True,
            "resource_limits_enforced": True,
            "egress_transcript_complete": True,
        },
        "cleanup-capability": {
            "cleanup_plan_validated": True,
            "destructive_scope_validated": True,
            "target_destroyed": True,
            "cleanup_validated": True,
        },
    }
    if any(claims.get(name) != expected for name, expected in required[kind].items()):
        raise BenchmarkExecutionError(f"{kind} required claims are not verified")
    required_digests = {
        "external-isolation": (
            "runner_image_sha256",
            "resource_limits_sha256",
            "network_policy_sha256",
            "egress_transcript_sha256",
        ),
        "cleanup-capability": ("cleanup_receipt_sha256",),
    }.get(kind, ())
    if any(
        not isinstance(claims.get(field), str) or not _DIGEST.fullmatch(claims[field])
        for field in required_digests
    ):
        raise BenchmarkExecutionError(f"{kind} required evidence digests are invalid")
    if kind == "runner-sbom" and claims.get("format") not in {
        "CycloneDX-1.6",
        "SPDX-2.3",
    }:
        raise BenchmarkExecutionError("runner SBOM format is unsupported")
    for field in (
        "trusted_time_receipt_sha256",
        "trusted_time_sha256",
        "ledger_receipt_sha256",
        "nonce_sha256",
        "runner_image_sha256",
        "resource_limits_sha256",
        "network_policy_sha256",
        "egress_transcript_sha256",
        "cleanup_receipt_sha256",
        "criteria_sha256",
        "thresholds_sha256",
        "approval_record_sha256",
        "adapter_spec_sha256",
        "runner_executable_sha256",
        "golden_fixture_sha256",
        "malformed_fixture_sha256",
        "semantic_oracle_sha256",
        "fixture_set_sha256",
        "output_sha256",
        "sbom_document_sha256",
        "sbom_subject_sha256",
        "provenance_subject_sha256",
        "provenance_document_sha256",
        "environment_sha256",
        "target_sha256",
        "destruction_probe_sha256",
        "conformance_report_sha256",
        "observation_report_sha256",
        "contamination_manifest_sha256",
        "environment_document_sha256",
        "provenance_signature_sha256",
        "provenance_public_key_sha256",
        "source_revision_sha256",
    ):
        if field in claims and (
            not isinstance(claims[field], str) or not _DIGEST.fullmatch(claims[field])
        ):
            raise BenchmarkExecutionError(f"{kind} {field} is invalid")
    return authority


@lru_cache(maxsize=2)
def _enhanced_attestation_validator(schema_version: str) -> Draft202012Validator:
    if schema_version not in _ENHANCED_SCHEMA_VERSIONS:
        raise BenchmarkExecutionError("unsupported enhanced attestation schema")
    schema_path = Path(__file__).with_name("schemas") / (
        f"benchmark-attestation-{schema_version}.schema.json"
    )
    _, payload = read_regular_file(
        schema_path,
        "bundled benchmark attestation schema",
        maximum_bytes=_MAX_MANIFEST_BYTES,
    )
    schema = strict_loads(payload)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _validate_enhanced_attestation_schema(
    value: object, kind: str, schema_version: str
) -> None:
    errors = sorted(
        _enhanced_attestation_validator(schema_version).iter_errors(value),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path)
        suffix = f" at {location}" if location else ""
        raise BenchmarkExecutionError(
            f"{kind} attestation violates schema{suffix}: {errors[0].message}"
        )


def _attestation_outcome(kind: str, claims: dict[str, Any]) -> dict[str, Any]:
    if kind == "replay-protection":
        return {
            "replay_protected": claims["ledger_consumed"] is True
            and claims["nonce_unique"] is True,
            "ledger_receipt_sha256": claims.get("ledger_receipt_sha256"),
            "claims": claims,
        }
    if kind == "trusted-time":
        return {
            "trusted_time_verified": True,
            "trusted_time_receipt_sha256": claims.get("trusted_time_receipt_sha256"),
            "claims": claims,
        }
    return {"claims_valid": True, "claims": claims}


def _validate_attestation_authority(
    value: object, kind: str, *, validation_time: datetime | None
) -> dict[str, Any]:
    required = {
        "organization_id",
        "role",
        "issued_at",
        "expires_at",
        "revocation_status_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise BenchmarkExecutionError(f"{kind} authority contract is invalid")
    organization = value["organization_id"]
    if not isinstance(organization, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9._-]{1,127}", organization
    ):
        raise BenchmarkExecutionError(f"{kind} authority organization is invalid")
    if value["role"] != kind:
        raise BenchmarkExecutionError(f"{kind} authority role is invalid")
    if not isinstance(value["revocation_status_sha256"], str) or not _DIGEST.fullmatch(
        value["revocation_status_sha256"]
    ):
        raise BenchmarkExecutionError(f"{kind} revocation evidence is invalid")
    try:
        issued = datetime.fromisoformat(str(value["issued_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(
            str(value["expires_at"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise BenchmarkExecutionError(f"{kind} authority time is invalid") from exc
    now = validation_time or datetime.now(UTC)
    if (
        issued.tzinfo is None
        or expires.tzinfo is None
        or issued > now
        or expires <= now
        or expires <= issued
        or (expires - issued).total_seconds() > 31 * 24 * 60 * 60
    ):
        raise BenchmarkExecutionError(f"{kind} authority validity is invalid")
    return dict(value)


def _trusted_attestation_time(claims: dict[str, Any]) -> datetime:
    try:
        observed = datetime.fromisoformat(
            str(claims["observed_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise BenchmarkExecutionError("trusted time observation is invalid") from exc
    age_seconds = (datetime.now(UTC) - observed).total_seconds()
    if observed.tzinfo is None or age_seconds < -60 or age_seconds > 15 * 60:
        raise BenchmarkExecutionError(
            "trusted time observation is stale or in the future"
        )
    return observed


def _enforce_authority_policy(results: dict[str, Any], policy: dict[str, Any]) -> None:
    evidence = {
        name: value
        for name, value in results.items()
        if name != "authority_summary" and isinstance(value, dict)
    }
    signer_ids = {str(value["signer_key_id"]) for value in evidence.values()}
    organization_ids = {
        str(value["authority"]["organization_id"]) for value in evidence.values()
    }
    if len(signer_ids) < policy["minimum_distinct_signers"]:
        raise BenchmarkExecutionError("attestation signer quorum is not satisfied")
    if len(organization_ids) < policy["minimum_distinct_organizations"]:
        raise BenchmarkExecutionError(
            "attestation organization quorum is not satisfied"
        )
    for field, identity in (
        ("key_separation_groups", "signer_key_id"),
        ("organization_separation_groups", "organization_id"),
    ):
        for group in policy[field]:
            if any(name not in evidence for name in group):
                raise BenchmarkExecutionError(
                    f"authority separation group references absent evidence: {group}"
                )
            values = [
                evidence[name][identity]
                if identity == "signer_key_id"
                else evidence[name]["authority"][identity]
                for name in group
            ]
            if len(values) != len(set(values)):
                raise BenchmarkExecutionError(
                    f"authority separation is not satisfied for: {', '.join(group)}"
                )


def _verify_evidence_bindings(
    manifest: dict[str, Any], attestations: dict[str, Any], corpus_sha256: str
) -> None:
    if not _is_enhanced_manifest(manifest):
        return
    evaluation = manifest["evaluation"]
    acceptance = _required_claims(attestations, "acceptance_criteria")
    conformance = _required_claims(attestations, "adapter_conformance")
    observation = _required_claims(attestations, "runtime_observation")
    sbom = _required_claims(attestations, "runner_sbom")
    provenance = _required_claims(attestations, "runner_provenance")
    environment = _required_claims(attestations, "environment")
    thresholds_sha256 = hashlib.sha256(
        canonical_bytes(manifest["thresholds"])
    ).hexdigest()
    run_stage = next(item for item in manifest["stages"] if item["name"] == "run")
    oci = manifest["isolation"].get("oci")
    image_sha256 = (
        str(oci["image"]).rsplit("@sha256:", 1)[-1]
        if isinstance(oci, dict)
        else _claim_digest(observation, "runner_image_sha256")
    )
    required_acceptance = {
        "criteria_sha256": evaluation["acceptance_criteria_sha256"],
        "thresholds_sha256": thresholds_sha256,
        "protocol": manifest["protocol"],
        "approved_before_execution": True,
    }
    if any(
        acceptance.get(name) != expected
        for name, expected in required_acceptance.items()
    ):
        raise BenchmarkExecutionError(
            "acceptance criteria are not bound to the manifest"
        )
    _claim_digest(acceptance, "approval_record_sha256")
    required_conformance = {
        "adapter_spec_sha256": manifest["adapter_contract"]["sha256"],
        "runner_executable_sha256": run_stage["executable_sha256"],
        "normalizer": manifest["adapter_contract"]["normalizer"],
    }
    if any(
        conformance.get(name) != expected
        for name, expected in required_conformance.items()
    ):
        raise BenchmarkExecutionError("adapter conformance is not bound to the runner")
    if (
        not isinstance(conformance.get("deterministic_runs"), int)
        or isinstance(conformance["deterministic_runs"], bool)
        or conformance["deterministic_runs"] < 3
    ):
        raise BenchmarkExecutionError("adapter conformance lacks deterministic repeats")
    conformance_digests = (
        ("semantic_oracle_sha256", "fixture_set_sha256", "output_sha256")
        if manifest.get("schema_version") == "1.2"
        else ("golden_fixture_sha256", "malformed_fixture_sha256")
    )
    for field in conformance_digests:
        _claim_digest(conformance, field)
    if manifest.get("schema_version") == "1.2":
        fixture_counts = conformance.get("fixture_counts")
        if (
            not isinstance(fixture_counts, dict)
            or set(fixture_counts) != {"golden", "malformed", "label_inverted"}
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 3 <= value <= 1000
                for value in fixture_counts.values()
            )
            or not isinstance(conformance.get("semantic_oracle_identity"), str)
            or not conformance["semantic_oracle_identity"]
        ):
            raise BenchmarkExecutionError(
                "adapter conformance suite or semantic oracle identity is invalid"
            )

    expected_network_sha256 = hashlib.sha256(
        canonical_bytes(manifest["isolation"]["network_policy"])
    ).hexdigest()
    required_observation = {
        "isolation_mode": manifest["isolation"]["mode"],
        "target_sha256": corpus_sha256,
        "runner_image_sha256": image_sha256,
        "network_policy_sha256": expected_network_sha256,
        "minimum_repetitions": evaluation["minimum_repetitions"],
        "power_analysis_sha256": evaluation["power_analysis_sha256"],
        "leakage_check_sha256": evaluation["leakage_check_sha256"],
        "duplicate_check_sha256": evaluation["duplicate_check_sha256"],
        "holdout_sequestered": True,
    }
    if any(
        observation.get(name) != expected
        for name, expected in required_observation.items()
    ):
        raise BenchmarkExecutionError(
            "runtime observation is not bound to the manifest"
        )
    for field in (
        "resource_limits_sha256",
        "egress_transcript_sha256",
        "environment_sha256",
    ):
        _claim_digest(observation, field)
    if isinstance(oci, dict):
        for claim, expected in (
            ("runtime_binary_sha256", oci["runtime_sha256"]),
            ("runtime_capabilities_sha256", oci["runtime_capabilities_sha256"]),
            ("runtime_trust_sha256", oci["runtime_trust_sha256"]),
        ):
            if observation.get(claim) != expected:
                raise BenchmarkExecutionError(
                    f"runtime observation {claim} does not match OCI contract"
                )
        if (
            observation.get("runtime_name") != oci["runtime_name"]
            or observation.get("runtime_version") != oci["runtime_version"]
        ):
            raise BenchmarkExecutionError(
                "runtime observation identity does not match OCI contract"
            )
    if environment.get("environment_sha256") != observation["environment_sha256"]:
        raise BenchmarkExecutionError("environment evidence is not bound to runtime")

    for claims, field, label in (
        (sbom, "sbom_subject_sha256", "runner SBOM"),
        (provenance, "provenance_subject_sha256", "runner provenance"),
    ):
        if (
            claims.get("runner_image_sha256") != image_sha256
            or claims.get(field) != image_sha256
        ):
            raise BenchmarkExecutionError(
                f"{label} subject does not match runner image"
            )
    _claim_digest(sbom, "sbom_document_sha256")
    _claim_digest(provenance, "provenance_document_sha256")
    if (
        not isinstance(provenance.get("builder_id"), str)
        or not provenance["builder_id"]
    ):
        raise BenchmarkExecutionError("runner provenance builder identity is missing")
    if manifest.get("schema_version") == "1.2" and (
        not isinstance(provenance.get("build_type"), str)
        or not str(provenance["build_type"]).startswith("https://")
        or not isinstance(provenance.get("source_repository_uri"), str)
        or not str(provenance["source_repository_uri"]).startswith("https://")
    ):
        raise BenchmarkExecutionError(
            "runner provenance build and source identities are missing"
        )

    if "external_isolation" in attestations:
        external = _required_claims(attestations, "external_isolation")
        for field in (
            "runner_image_sha256",
            "resource_limits_sha256",
            "network_policy_sha256",
            "egress_transcript_sha256",
            "target_sha256",
        ):
            if external.get(field) != observation.get(field):
                raise BenchmarkExecutionError(
                    f"external isolation {field} is detached from runtime observation"
                )
    if "cleanup_capability" in attestations:
        cleanup = _required_claims(attestations, "cleanup_capability")
        if cleanup.get("target_sha256") != corpus_sha256:
            raise BenchmarkExecutionError(
                "cleanup evidence targets a different subject"
            )
        _claim_digest(cleanup, "cleanup_receipt_sha256")
        _claim_digest(cleanup, "destruction_probe_sha256")


def _required_claims(attestations: dict[str, Any], name: str) -> dict[str, Any]:
    value = attestations.get(name)
    claims = value.get("claims") if isinstance(value, dict) else None
    if not isinstance(claims, dict):
        raise BenchmarkExecutionError(f"{name} claims are missing")
    return claims


def _claim_digest(claims: dict[str, Any], field: str) -> str:
    value = claims.get(field)
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise BenchmarkExecutionError(f"evidence claim {field} is invalid")
    return value


def _validate_thresholds(value: object, protocol: str) -> None:
    gaps = validate_protocol_thresholds(protocol, value)
    if gaps:
        raise BenchmarkExecutionError("; ".join(gaps))


def _execute_stage(
    stage: dict[str, Any],
    workspace: Path,
    corpus: Path,
    isolation: dict[str, Any],
) -> dict[str, Any]:
    executable = resolve_regular_file(Path(stage["executable"]), "stage executable")
    actual_digest = _sha256_file(executable)
    started_at = datetime.now(UTC).isoformat()
    if actual_digest != stage["executable_sha256"]:
        return {
            "name": stage["name"],
            "status": "digest-mismatch",
            "started_at": started_at,
            "completed_at": datetime.now(UTC).isoformat(),
            "duration_seconds": 0.0,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "executable_sha256": actual_digest,
            "launcher_sha256": actual_digest,
            "isolation_mode": isolation["mode"],
        }
    environment = _minimal_environment()
    environment.update(stage["environment"])
    environment.update(
        {
            "PYSEC_BENCHMARK_WORKSPACE": str(workspace),
            "PYSEC_BENCHMARK_CORPUS": str(corpus),
        }
    )
    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        creationflags = (
            int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
            if os.name == "nt"
            else 0
        )
        argv, executed_sha256 = _stage_argv(
            executable, stage, isolation, workspace, corpus
        )
        process = subprocess.Popen(  # noqa: S603 -- digest-pinned executable, no shell
            argv,
            cwd=workspace,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            shell=False,
            close_fds=True,
            start_new_session=os.name != "nt",
            creationflags=creationflags,
        )
        status = "passed"
        try:
            exit_code = process.wait(timeout=stage["timeout_seconds"])
            if exit_code not in stage["expected_exit_codes"]:
                status = "failed"
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process.pid)
            exit_code = None
            status = "timed-out"
        stdout_text, stdout_truncated = _bounded_capture(stdout)
        stderr_text, stderr_truncated = _bounded_capture(stderr)
    return {
        "name": stage["name"],
        "status": status,
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "duration_seconds": round(time.monotonic() - started, 6),
        "exit_code": exit_code,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "executable_sha256": actual_digest,
        "launcher_sha256": executed_sha256,
        "isolation_mode": isolation["mode"],
    }


def _stage_argv(
    executable: Path,
    stage: dict[str, Any],
    isolation: dict[str, Any],
    workspace: Path,
    corpus: Path,
) -> tuple[list[str], str]:
    try:
        return build_stage_argv(executable, stage, isolation, workspace, corpus)
    except (BenchmarkRuntimeError, OSError, ValueError) as exc:
        raise BenchmarkExecutionError(str(exc)) from exc


def _prepare_oci_output_directory(workspace: Path) -> None:
    try:
        prepare_oci_output_directory(workspace)
    except (BenchmarkRuntimeError, OSError, ValueError) as exc:
        raise BenchmarkExecutionError(str(exc)) from exc


def _runtime_input_integrity_gaps(
    manifest: dict[str, Any],
    workspace: Path,
    corpus: Path,
    immutable_snapshot: dict[str, str],
) -> list[str]:
    gaps: list[str] = []
    if _sha256_file(corpus) != manifest["corpus"]["sha256"]:
        gaps.append("benchmark corpus changed during execution")
    if _is_enhanced_manifest(manifest):
        for item in manifest["adapter_contract"]["required_inputs"]:
            try:
                path = _resolve_workspace_file(
                    workspace,
                    Path(item["path"]),
                    f"adapter input {item['name']}",
                )
                digest = _sha256_file(path)
            except (BenchmarkExecutionError, OSError):
                gaps.append(
                    f"adapter input {item['name']} disappeared during execution"
                )
                continue
            if digest != item["sha256"]:
                gaps.append(f"adapter input {item['name']} changed during execution")
        oci = manifest["isolation"].get("oci")
        if isinstance(oci, dict):
            gaps.extend(_oci_output_gaps(workspace / ".pysec-output", oci))
    for stage in manifest["stages"]:
        try:
            executable = resolve_regular_file(
                Path(stage["executable"]), "stage executable"
            )
            digest = _sha256_file(executable)
        except (OSError, ValueError):
            gaps.append(
                f"stage executable {stage['name']} disappeared during execution"
            )
            continue
        if digest != stage["executable_sha256"]:
            gaps.append(f"stage executable {stage['name']} changed during execution")
    for path_value, expected_digest in immutable_snapshot.items():
        path = Path(path_value)
        try:
            if path.is_symlink():
                raise OSError("symbolic link")
            actual_digest = _sha256_file(resolve_regular_file(path, "immutable input"))
        except (OSError, ValueError):
            gaps.append(f"immutable evidence disappeared during execution: {path.name}")
            continue
        if actual_digest != expected_digest:
            gaps.append(f"immutable evidence changed during execution: {path.name}")
    return gaps


def _oci_output_gaps(output: Path, oci: dict[str, Any]) -> list[str]:
    return oci_output_gaps(output, oci)


def _execution_input_snapshot(
    manifest_file: Path,
    workspace: Path,
    manifest: dict[str, Any],
    attestations: dict[str, Any],
    *,
    deployment_inputs: tuple[Path | None, ...] = (),
) -> dict[str, str]:
    paths = {manifest_file.resolve()}
    for reference in manifest["attestations"].values():
        for field in ("path", "public_key_path", "signature_path"):
            paths.add(
                _resolve_workspace_file(
                    workspace,
                    Path(reference[field]),
                    f"attestation {field}",
                )
            )
    for value in attestations.values():
        claims = value.get("claims") if isinstance(value, dict) else None
        if not isinstance(claims, dict):
            continue
        for field, path_value in claims.items():
            if field.endswith("_path") and isinstance(path_value, str):
                paths.add(
                    _resolve_workspace_file(
                        workspace, Path(path_value), f"evidence {field}"
                    )
                )
    for deployment_input in deployment_inputs:
        if deployment_input is None:
            raise BenchmarkExecutionError(
                "required deployment input is unavailable for immutability tracking"
            )
        try:
            paths.add(resolve_regular_file(deployment_input, "deployment input"))
        except (OSError, ValueError) as exc:
            raise BenchmarkExecutionError(
                "deployment input is not a safe regular file"
            ) from exc
    return {str(path): _sha256_file(path) for path in sorted(paths)}


def _minimal_environment() -> dict[str, str]:
    retained = {"LANG", "LC_ALL", "SYSTEMROOT", "WINDIR", "COMSPEC", "TMP", "TEMP"}
    return {name: value for name, value in os.environ.items() if name in retained}


def _bounded_capture(handle: Any) -> tuple[str, bool]:
    size = handle.tell()
    handle.seek(0)
    payload = handle.read(_MAX_CAPTURE_BYTES + 1)
    return payload[:_MAX_CAPTURE_BYTES].decode(
        "utf-8", errors="replace"
    ), size > _MAX_CAPTURE_BYTES


def _terminate_process_tree(pid: int) -> None:
    try:
        parent = psutil.Process(pid)
    except psutil.Error:
        return
    descendants = parent.children(recursive=True)
    for process in descendants:
        try:
            process.terminate()
        except psutil.Error:
            pass
    try:
        parent.terminate()
    except psutil.Error:
        pass
    _, alive = psutil.wait_procs([*descendants, parent], timeout=3)
    for process in alive:
        try:
            process.kill()
        except psutil.Error:
            pass


def _resolve_workspace_file(workspace: Path, path: Path, label: str) -> Path:
    candidate = path if path.is_absolute() else workspace / path
    resolved = resolve_regular_file(candidate, label)
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise BenchmarkExecutionError(
            f"{label} must remain inside the workspace"
        ) from exc
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_industry_evidence(
    receipt: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    """Project an execution receipt into the governed scorecard evidence contract."""
    metrics = receipt.get("metrics")
    metrics = metrics if isinstance(metrics, dict) else {}
    protocol = str(manifest["protocol"])
    case_count = int(receipt.get("case_count") or 0)
    protocol_metrics = {**metrics, "cases": case_count}
    if protocol == "stochastic-adversarial":
        protocol_metrics.update(
            {
                "repetitions": case_count,
                "utility_retention": metrics.get("mean_utility", 0.0),
                "variance": metrics.get("utility_variance", 0.0),
            }
        )
    elif protocol == "assessor-agreement":
        protocol_metrics.update(
            {
                "reviewers": metrics.get("reviewers", 0),
                "inter_rater_agreement": metrics.get("agreement", 0.0),
            }
        )
    elif protocol == "conformance":
        protocol_metrics.update(
            {
                "passed_cases": metrics.get("passed_cases", 0),
                "failed_cases": metrics.get("failed_cases", 0),
                "negative_cases": metrics.get("negative_cases", 0),
            }
        )
    elif protocol == "biometric-performance":
        protocol_metrics["threshold_locked"] = True
    elif protocol == "proficiency-testing":
        protocol_metrics["blinded"] = True
    elif protocol == "fuzzing-statistical":
        protocol_metrics["trials"] = case_count

    normalized_sha256 = str(receipt.get("normalized_result_sha256") or "")
    thresholds_sha256 = hashlib.sha256(
        canonical_bytes(manifest["thresholds"])
    ).hexdigest()
    acceptance_sha256 = (
        manifest.get("evaluation", {}).get("acceptance_criteria_sha256")
        if _is_enhanced_manifest(manifest)
        else thresholds_sha256
    )
    stage_digest = hashlib.sha256(
        canonical_bytes(
            [
                {"name": item["name"], "sha256": item["executable_sha256"]}
                for item in manifest["stages"]
            ]
        )
    ).hexdigest()
    isolation_digest = hashlib.sha256(
        canonical_bytes(manifest["isolation"])
    ).hexdigest()
    stages = receipt.get("stages", [])
    cleanup = next(
        (
            item
            for item in stages
            if isinstance(item, dict) and item.get("name") == "cleanup"
        ),
        None,
    )
    cleanup_sha256 = (
        hashlib.sha256(canonical_bytes(cleanup)).hexdigest()
        if isinstance(cleanup, dict)
        else ""
    )
    attestations = receipt.get("attestations", {})
    attestations = attestations if isinstance(attestations, dict) else {}
    external_claims = _attestation_claims(attestations, "external_isolation")
    cleanup_claims = _attestation_claims(attestations, "cleanup_capability")
    runtime_claims = _attestation_claims(attestations, "runtime_observation")
    acceptance_evidence = attestations.get("acceptance_criteria", {})
    isolation_mode = manifest["isolation"]["mode"]
    isolation_validated = isolation_mode == "oci" or (
        isolation_mode == "external-sandbox"
        and isinstance(attestations.get("external_isolation"), dict)
        and attestations["external_isolation"].get("signature_verified") is True
    )
    network_validated = (
        isolation_validated
        and manifest["isolation"]["network_policy"]
        in {"deny", "authorized-target-only"}
        and (
            not _is_enhanced_manifest(manifest)
            or runtime_claims.get("network_policy_observed") is True
        )
    )
    cleanup_validated = (
        isinstance(cleanup, dict)
        and cleanup.get("status") == "passed"
        and (
            not _is_enhanced_manifest(manifest)
            or isinstance(attestations.get("cleanup_capability"), dict)
        )
        and (
            not _is_enhanced_manifest(manifest)
            or cleanup_claims.get("cleanup_validated") is True
        )
    )
    oci = manifest["isolation"].get("oci")
    image_sha256 = (
        str(oci["image"]).rsplit("@sha256:", 1)[-1]
        if isinstance(oci, dict) and "@sha256:" in str(oci.get("image"))
        else str(runtime_claims.get("runner_image_sha256") or "")
    )
    evaluation = manifest.get("evaluation", {})
    confusion_matrix = (
        {
            "true_positive": metrics.get("true_positive", 0),
            "true_negative": metrics.get("true_negative", 0),
            "false_positive": metrics.get("false_positive", 0),
            "false_negative": metrics.get("false_negative", 0),
        }
        if protocol == "classification"
        else None
    )
    return {
        "report": {
            "checksums_sha256": normalized_sha256,
            "artifact_kind": "normalized-benchmark-result",
        },
        "time_authority": {
            "validated": isinstance(attestations.get("trusted_time"), dict)
            and attestations["trusted_time"].get("signature_verified") is True
        },
        "confusion_matrix": confusion_matrix,
        "protocol_metrics": protocol_metrics,
        "acceptance": {
            "criteria_sha256": acceptance_sha256,
            "met": receipt.get("decision") == "pass",
            "authority": {
                "organization_approved": isinstance(acceptance_evidence, dict)
                and acceptance_evidence.get("signature_verified") is True,
                "organization_id": (
                    acceptance_evidence.get("authority", {}).get("organization_id")
                    if isinstance(acceptance_evidence, dict)
                    and isinstance(acceptance_evidence.get("authority"), dict)
                    else None
                ),
            },
        },
        "execution_context": {
            "target_sha256": receipt["corpus_sha256"],
            "environment_sha256": _attestation_digest(attestations, "environment"),
            "toolset_sha256": stage_digest,
            "oracle_sha256": manifest["corpus"]["label_authority_sha256"],
            "isolation_receipt_sha256": _attestation_digest(
                attestations, "external_isolation", fallback=isolation_digest
            ),
            "runner_oci_image_sha256": image_sha256,
            "runner_sbom_sha256": _attestation_digest(attestations, "runner_sbom"),
            "runner_provenance_sha256": _attestation_digest(
                attestations, "runner_provenance"
            ),
            "resource_limits_sha256": (
                str(runtime_claims.get("resource_limits_sha256") or "")
                if _is_enhanced_manifest(manifest)
                else isolation_digest
            ),
            "network_policy_sha256": (
                str(runtime_claims.get("network_policy_sha256") or "")
                if _is_enhanced_manifest(manifest)
                else hashlib.sha256(
                    canonical_bytes(manifest["isolation"]["network_policy"])
                ).hexdigest()
            ),
            "egress_transcript_sha256": (
                str(runtime_claims.get("egress_transcript_sha256") or "")
                if _is_enhanced_manifest(manifest)
                else isolation_digest
                if network_validated
                else ""
            ),
            "cleanup_receipt_sha256": str(
                cleanup_claims.get("cleanup_receipt_sha256") or cleanup_sha256
            ),
            "dataset_license_sha256": manifest["corpus"]["license_sha256"],
            "label_authority_sha256": manifest["corpus"]["label_authority_sha256"],
            "contamination_manifest_sha256": _attestation_digest(
                attestations, "contamination_manifest"
            ),
            "runner_identity": manifest.get("adapter_contract", {}).get(
                "id", manifest["benchmark_id"]
            ),
            "runner_version": manifest["adapter_version"],
            "isolation_validated": isolation_validated,
            "network_isolation_validated": network_validated,
            "target_destroyed": cleanup_validated
            and cleanup_claims.get("target_destroyed", True) is True,
            "runner_image_pinned": isolation_mode == "oci"
            or external_claims.get("runner_image_pinned") is True,
            "runner_sbom_matches_image": (
                _attestation_claims(attestations, "runner_sbom").get(
                    "sbom_subject_sha256"
                )
                == image_sha256
                if _is_enhanced_manifest(manifest)
                else isinstance(attestations.get("runner_sbom"), dict)
            ),
            "runner_provenance_verified": isinstance(
                attestations.get("runner_provenance"), dict
            )
            and (
                isolation_mode == "oci"
                or external_claims.get("runner_provenance_verified") is True
            ),
            "provenance_subject_matches_image": (
                _attestation_claims(attestations, "runner_provenance").get(
                    "provenance_subject_sha256"
                )
                == image_sha256
                if _is_enhanced_manifest(manifest)
                else isolation_mode == "oci"
                or external_claims.get("provenance_subject_matches_image") is True
            ),
            "resource_limits_enforced": (
                runtime_claims.get("resource_limits_observed") is True
                if _is_enhanced_manifest(manifest)
                else isolation_mode == "oci"
                or external_claims.get("resource_limits_enforced") is True
            ),
            "network_policy_enforced": network_validated,
            "egress_transcript_complete": network_validated
            and (
                runtime_claims.get("egress_transcript_complete") is True
                if _is_enhanced_manifest(manifest)
                else isolation_mode == "oci"
                or external_claims.get("egress_transcript_complete") is True
            ),
            "cleanup_validated": cleanup_validated,
            "positive_controls": evaluation.get("positive_controls", 0),
            "negative_controls": evaluation.get("negative_controls", 0),
            "split_strategy": evaluation.get("split_strategy"),
            "independent_reviewers": evaluation.get("independent_reviewers", 0),
            "repetitions": evaluation.get("minimum_repetitions", 1),
            "power_analysis_sha256": evaluation.get("power_analysis_sha256", ""),
            "leakage_check_sha256": evaluation.get("leakage_check_sha256", ""),
            "duplicate_check_sha256": evaluation.get("duplicate_check_sha256", ""),
            "holdout_sequestered": evaluation.get("holdout_sequestered", False),
        },
    }


def _attestation_digest(
    attestations: dict[str, Any], name: str, *, fallback: str = ""
) -> str:
    value = attestations.get(name)
    return str(value.get("sha256")) if isinstance(value, dict) else fallback


def _attestation_claims(attestations: dict[str, Any], name: str) -> dict[str, Any]:
    value = attestations.get(name)
    claims = value.get("claims") if isinstance(value, dict) else None
    return claims if isinstance(claims, dict) else {}
