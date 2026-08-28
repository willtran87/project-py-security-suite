from __future__ import annotations

import hashlib
import base64
import os
import re
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .path_safety import read_regular_file, resolve_regular_file, resolve_unlinked_path
from .strict_json import canonical_bytes, loads as strict_loads


_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_MAX_RESULT_BYTES = 64 * 1024 * 1024
_MAX_CAPTURE_BYTES = 128 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_STAGE_NAMES = {"prepare", "build", "run", "normalize", "verify", "cleanup"}
_PROTOCOLS = {
    "classification",
    "temporal-calibration",
    "verification-competition",
    "test-generation",
    "fuzzing-statistical",
    "stochastic-adversarial",
    "assessor-agreement",
    "biometric-performance",
    "proficiency-testing",
    "conformance",
    "detection-evaluation",
}
_ATTESTATION_KINDS = {
    "trusted_time": "trusted-time",
    "replay_protection": "replay-protection",
    "contamination_manifest": "contamination-manifest",
    "runner_sbom": "runner-sbom",
    "runner_provenance": "runner-provenance",
    "environment": "environment",
}


class BenchmarkExecutionError(ValueError):
    """Raised when a benchmark cannot be executed without weakening its contract."""


def execute_benchmark_manifest(
    manifest_path: Path,
    workspace: Path,
    *,
    authorized: bool,
    known_benchmark_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Execute a digest-pinned benchmark adapter and score normalized cases.

    The manifest is deliberately an execution authorization boundary. Commands are
    never passed through a shell, inherited environment variables are minimized,
    executables and the input corpus are verified immediately before execution, and
    every stage is bounded by a timeout and captured-output limit.
    """
    if not authorized:
        raise BenchmarkExecutionError(
            "benchmark execution requires explicit --authorize-execution"
        )
    manifest_file, payload = read_regular_file(
        manifest_path,
        "benchmark adapter manifest",
        maximum_bytes=_MAX_MANIFEST_BYTES,
    )
    try:
        manifest = strict_loads(payload)
    except (ValueError, TypeError) as exc:
        raise BenchmarkExecutionError(
            "benchmark adapter manifest is invalid JSON"
        ) from exc
    _validate_manifest(manifest, known_benchmark_ids=known_benchmark_ids)

    work = resolve_unlinked_path(workspace, "benchmark workspace")
    if not work.is_dir():
        raise BenchmarkExecutionError(f"benchmark workspace is not a directory: {work}")
    corpus = _resolve_workspace_file(
        work, Path(manifest["corpus"]["path"]), "benchmark corpus"
    )
    corpus_sha256 = _sha256_file(corpus)
    if corpus_sha256 != manifest["corpus"]["sha256"]:
        raise BenchmarkExecutionError("benchmark corpus digest does not match manifest")

    subject_sha256 = _benchmark_subject_sha256(manifest, corpus_sha256)
    verified_attestations = _verify_attestations(
        manifest["attestations"], work, subject_sha256
    )
    execution_id = hashlib.sha256(
        canonical_bytes(manifest) + corpus_sha256.encode("ascii")
    ).hexdigest()
    stages: list[dict[str, Any]] = []
    decision = "pass"
    failure_reason: str | None = None
    started = datetime.now(UTC).isoformat()
    try:
        for stage in manifest["stages"]:
            stage_receipt = _execute_stage(stage, work, corpus, manifest["isolation"])
            stages.append(stage_receipt)
            if stage_receipt["status"] != "passed":
                decision = "fail"
                failure_reason = f"stage {stage['name']} {stage_receipt['status']}"
                break
    finally:
        # A cleanup stage is an obligation even after an earlier failure. It may not
        # conceal the primary failure, but its own failure is retained in the receipt.
        completed_names = {item["name"] for item in stages}
        for cleanup in (
            item
            for item in manifest["stages"]
            if item["name"] == "cleanup" and "cleanup" not in completed_names
        ):
            cleanup_receipt = _execute_stage(
                cleanup, work, corpus, manifest["isolation"]
            )
            stages.append(cleanup_receipt)
            if cleanup_receipt["status"] != "passed" and decision == "pass":
                decision = "fail"
                failure_reason = f"cleanup stage {cleanup_receipt['status']}"

    metrics: dict[str, Any] | None = None
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
            try:
                result = strict_loads(result_payload)
                metrics = _score_normalized_result(
                    result,
                    benchmark_id=manifest["benchmark_id"],
                    protocol=manifest["protocol"],
                )
                case_count = metrics.pop("case_count")
                threshold_failures = _threshold_failures(
                    metrics, manifest["thresholds"]
                )
                if threshold_failures:
                    decision = "fail"
                    failure_reason = "; ".join(threshold_failures)
            except (TypeError, ValueError) as exc:
                decision = "fail"
                failure_reason = f"normalized result is invalid: {exc}"

    receipt: dict[str, Any] = {
        "schema_version": "1.0",
        "analysis": "benchmark-adapter-execution",
        "execution_id": execution_id,
        "benchmark_id": manifest["benchmark_id"],
        "protocol": manifest["protocol"],
        "benchmark_version": manifest["benchmark_version"],
        "adapter_version": manifest["adapter_version"],
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "manifest_path": str(manifest_file),
        "corpus_sha256": corpus_sha256,
        "corpus": {
            "sha256": corpus_sha256,
            "authority": {
                "organization_approved": manifest["corpus"]["organization_approved"],
                "license_sha256": manifest["corpus"]["license_sha256"],
                "label_authority_sha256": manifest["corpus"]["label_authority_sha256"],
            },
        },
        "normalized_result_sha256": normalized_sha256,
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "case_count": case_count,
        "metrics": metrics,
        "thresholds": manifest["thresholds"],
        "benchmark_subject_sha256": subject_sha256,
        "attestations": verified_attestations,
        "replay_protected": verified_attestations["replay_protection"][
            "replay_protected"
        ],
        "stages": stages,
        "isolation": manifest["isolation"],
        "decision": decision,
        "verdict": decision,
        "failure_reason": failure_reason,
        "claim_boundary": (
            "This receipt proves execution of the digest-pinned adapter and corpus. "
            "Process mode does not prove network isolation. OCI mode enforces the "
            "recorded runtime controls; external-sandbox claims remain dependent on "
            "their separately verified isolation evidence."
        ),
    }
    receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    return receipt


def _validate_manifest(value: object, *, known_benchmark_ids: set[str] | None) -> None:
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
    if set(value) != required:
        raise BenchmarkExecutionError(
            "benchmark adapter manifest properties do not match the 1.0 contract"
        )
    if value["schema_version"] != "1.0":
        raise BenchmarkExecutionError("unsupported benchmark adapter schema version")
    identifier = value["benchmark_id"]
    if not isinstance(identifier, str) or not _IDENTIFIER.fullmatch(identifier):
        raise BenchmarkExecutionError("benchmark_id is invalid")
    if known_benchmark_ids is not None and identifier not in known_benchmark_ids:
        raise BenchmarkExecutionError("benchmark_id is not registered")
    for field in ("benchmark_version", "adapter_version"):
        if not isinstance(value[field], str) or not 1 <= len(value[field]) <= 128:
            raise BenchmarkExecutionError(f"{field} is invalid")
    if value["protocol"] not in _PROTOCOLS:
        raise BenchmarkExecutionError("benchmark protocol is invalid")
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
    attestations = value["attestations"]
    if not isinstance(attestations, dict) or set(attestations) != set(
        _ATTESTATION_KINDS
    ):
        raise BenchmarkExecutionError("benchmark attestations are invalid")
    for reference in attestations.values():
        _validate_attestation_reference(reference)
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
    if isolation["mode"] == "oci":
        _validate_oci(isolation["oci"])
        if isolation["network_policy"] != "deny":
            raise BenchmarkExecutionError(
                "OCI mode currently requires denied networking"
            )
    elif isolation["oci"] is not None:
        raise BenchmarkExecutionError("OCI configuration is only valid in OCI mode")
    if not isinstance(isolation["disposable_target"], bool):
        raise BenchmarkExecutionError("disposable_target must be boolean")


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


def _validate_attestation_reference(value: object) -> None:
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
    if value["media_type"] != "application/vnd.pysec.attestation+json;version=1.0":
        raise BenchmarkExecutionError("attestation media type is unsupported")
    for field in ("sha256", "public_key_sha256"):
        if not isinstance(value[field], str) or not _DIGEST.fullmatch(value[field]):
            raise BenchmarkExecutionError(f"attestation {field} is invalid")


def _validate_oci(value: object) -> None:
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
    apparmor = value["apparmor_profile"]
    if apparmor is not None and (
        not isinstance(apparmor, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", apparmor)
    ):
        raise BenchmarkExecutionError("OCI AppArmor profile is invalid")


def _benchmark_subject_sha256(manifest: dict[str, Any], corpus_sha256: str) -> str:
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
        "isolation": manifest["isolation"],
    }
    return hashlib.sha256(canonical_bytes(subject)).hexdigest()


def _verify_attestations(
    references: dict[str, Any], workspace: Path, subject_sha256: str
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    signer_ids: set[str] = set()
    for name, kind in _ATTESTATION_KINDS.items():
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
        _validate_attestation_document(document, kind, subject_sha256)
        signer = hashlib.sha256(
            key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).hexdigest()
        signer_ids.add(signer)
        results[name] = {
            "kind": kind,
            "sha256": digest,
            "signature_verified": True,
            "signer_key_id": signer,
            "subject_sha256": subject_sha256,
            **_attestation_outcome(kind, document["claims"]),
        }
    results["authority_summary"] = {
        "distinct_signers": len(signer_ids),
        "all_signatures_verified": True,
    }
    return results


def _validate_attestation_document(
    value: object, kind: str, subject_sha256: str
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "kind",
        "subject_sha256",
        "valid",
        "claims",
    }:
        raise BenchmarkExecutionError(f"{kind} attestation contract is invalid")
    if (
        value["schema_version"] != "1.0"
        or value["kind"] != kind
        or value["subject_sha256"] != subject_sha256
        or value["valid"] is not True
        or not isinstance(value["claims"], dict)
    ):
        raise BenchmarkExecutionError(f"{kind} attestation is detached or invalid")
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
    }
    if any(claims.get(name) != expected for name, expected in required[kind].items()):
        raise BenchmarkExecutionError(f"{kind} required claims are not verified")
    if kind == "runner-sbom" and claims.get("format") not in {
        "CycloneDX-1.6",
        "SPDX-2.3",
        "SPDX-3.0",
    }:
        raise BenchmarkExecutionError("runner SBOM format is unsupported")
    for field in (
        "trusted_time_receipt_sha256",
        "ledger_receipt_sha256",
        "nonce_sha256",
    ):
        if field in claims and (
            not isinstance(claims[field], str) or not _DIGEST.fullmatch(claims[field])
        ):
            raise BenchmarkExecutionError(f"{kind} {field} is invalid")


def _attestation_outcome(kind: str, claims: dict[str, Any]) -> dict[str, Any]:
    if kind == "replay-protection":
        return {
            "replay_protected": claims["ledger_consumed"] is True
            and claims["nonce_unique"] is True,
            "ledger_receipt_sha256": claims.get("ledger_receipt_sha256"),
        }
    if kind == "trusted-time":
        return {
            "trusted_time_verified": True,
            "trusted_time_receipt_sha256": claims.get("trusted_time_receipt_sha256"),
        }
    return {"claims_valid": True}


def _validate_thresholds(value: object, protocol: str) -> None:
    expected_by_protocol = {
        "classification": {
            "minimum_precision",
            "minimum_recall",
            "minimum_f1",
            "maximum_false_positive_rate",
        },
        "detection-evaluation": {
            "minimum_precision",
            "minimum_recall",
            "minimum_f1",
            "maximum_false_positive_rate",
        },
        "verification-competition": {"minimum_accuracy"},
        "test-generation": {"minimum_accuracy"},
        "conformance": {"minimum_outcome_accuracy", "minimum_conformance_rate"},
        "temporal-calibration": {"maximum_brier_score"},
        "stochastic-adversarial": {
            "maximum_attack_success_rate",
            "minimum_mean_utility",
        },
        "assessor-agreement": {
            "minimum_agreement",
            "minimum_chance_corrected_agreement",
        },
        "biometric-performance": {
            "maximum_fmr_wilson_upper_95",
            "maximum_fnmr_wilson_upper_95",
            "maximum_iapar_wilson_upper_95",
            "maximum_worst_group_fmr_wilson_upper_95",
            "maximum_worst_group_fnmr_wilson_upper_95",
        },
        "proficiency-testing": {
            "minimum_agreement",
            "minimum_chance_corrected_agreement",
            "minimum_reference_accuracy",
        },
        "fuzzing-statistical": {
            "minimum_executions",
            "minimum_coverage_gain",
        },
    }
    expected = expected_by_protocol[protocol]
    if not isinstance(value, dict) or set(value) != expected:
        raise BenchmarkExecutionError("benchmark thresholds are invalid")
    for name, item in value.items():
        if (
            not isinstance(item, (int, float))
            or isinstance(item, bool)
            or float(item) < 0
            or (name != "minimum_executions" and float(item) > 1)
        ):
            raise BenchmarkExecutionError(f"benchmark threshold {name} is invalid")


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
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
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
    if isolation["mode"] != "oci":
        return [str(executable), *stage["arguments"]], _sha256_file(executable)
    oci = isolation["oci"]
    runtime = resolve_regular_file(Path(oci["runtime"]), "OCI runtime executable")
    runtime_sha256 = _sha256_file(runtime)
    if runtime_sha256 != oci["runtime_sha256"]:
        raise BenchmarkExecutionError("OCI runtime digest does not match manifest")
    command = [
        str(runtime),
        "run",
        "--rm",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=none",
        f"--pids-limit={oci['pids_limit']}",
        f"--memory={oci['memory_bytes']}",
        f"--cpus={oci['cpu_count']}",
        "--user=65532:65532",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
        f"--volume={workspace}:/workspace:rw",
        f"--volume={corpus}:/corpus/input:ro",
        f"--volume={executable}:/pysec/stage-executable:ro",
        "--workdir=/workspace",
    ]
    if oci["seccomp_profile"] is not None:
        profile = resolve_regular_file(Path(oci["seccomp_profile"]), "seccomp profile")
        command.append(f"--security-opt=seccomp={profile}")
    if oci["apparmor_profile"] is not None:
        command.append(f"--security-opt=apparmor={oci['apparmor_profile']}")
    command.extend([oci["image"], "/pysec/stage-executable", *stage["arguments"]])
    return command, runtime_sha256


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


def _score_normalized_result(
    value: object, *, benchmark_id: str, protocol: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "benchmark_id",
        "protocol",
        "cases",
    }:
        raise ValueError("expected schema_version, benchmark_id, protocol, and cases")
    if (
        value["schema_version"] != "1.0"
        or value["benchmark_id"] != benchmark_id
        or value["protocol"] != protocol
    ):
        raise ValueError("normalized result identity does not match the manifest")
    cases = value["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 1_000_000:
        raise ValueError("cases must be a non-empty bounded array")
    if protocol in {"classification", "detection-evaluation"}:
        return _score_classification(cases)
    if protocol in {"verification-competition", "test-generation"}:
        return _score_outcome_accuracy(cases)
    if protocol == "conformance":
        return _score_conformance(cases)
    if protocol == "temporal-calibration":
        return _score_temporal_calibration(cases)
    if protocol == "stochastic-adversarial":
        return _score_stochastic(cases)
    if protocol == "assessor-agreement":
        return _score_assessor_agreement(cases)
    if protocol == "biometric-performance":
        return _score_biometric_performance(cases)
    if protocol == "proficiency-testing":
        return _score_proficiency_testing(cases)
    if protocol == "fuzzing-statistical":
        return _score_fuzzing(cases)
    raise ValueError("normalized result protocol is unsupported")


def _validate_case_identity(case: object, seen: set[str]) -> dict[str, Any]:
    if not isinstance(case, dict):
        raise ValueError("case must be an object")
    case_id = case.get("id")
    if not isinstance(case_id, str) or not 1 <= len(case_id) <= 512 or case_id in seen:
        raise ValueError("case identifiers must be unique bounded strings")
    seen.add(case_id)
    return case


def _validate_strata(value: object) -> None:
    if (
        not isinstance(value, dict)
        or len(value) > 32
        or any(
            not isinstance(key, str)
            or not isinstance(item, str)
            or len(key) > 128
            or len(item) > 512
            for key, item in value.items()
        )
    ):
        raise ValueError("case strata are invalid")


def _score_classification(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    tp = fp = tn = fn = 0
    for case in cases:
        case = _validate_case_identity(case, seen)
        if set(case) != {
            "id",
            "expected_positive",
            "observed_positive",
            "strata",
        }:
            raise ValueError("case does not match the normalized case contract")
        expected = case["expected_positive"]
        observed = case["observed_positive"]
        if not isinstance(expected, bool) or not isinstance(observed, bool):
            raise ValueError("case labels must be boolean")
        _validate_strata(case["strata"])
        if expected and observed:
            tp += 1
        elif not expected and observed:
            fp += 1
        elif not expected and not observed:
            tn += 1
        else:
            fn += 1
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    f1 = _ratio(2 * precision * recall, precision + recall)
    return {
        "case_count": len(cases),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "false_positive_rate": _ratio(fp, fp + tn),
        "balanced_accuracy": (recall + specificity) / 2,
    }


def _score_outcome_accuracy(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    correct = 0
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "expected", "observed", "strata"}:
            raise ValueError("outcome case contract is invalid")
        _validate_strata(case["strata"])
        if not isinstance(case["expected"], str) or not isinstance(
            case["observed"], str
        ):
            raise ValueError("outcome labels must be strings")
        correct += case["expected"] == case["observed"]
    return {"case_count": len(cases), "accuracy": _ratio(correct, len(cases))}


def _score_conformance(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    outcomes = {"pass", "fail", "not-applicable"}
    correct = passed = applicable = 0
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "expected_outcome", "observed_outcome", "strata"}:
            raise ValueError("conformance case contract is invalid")
        _validate_strata(case["strata"])
        if (
            case["expected_outcome"] not in outcomes
            or case["observed_outcome"] not in outcomes
        ):
            raise ValueError("conformance outcome is invalid")
        correct += case["expected_outcome"] == case["observed_outcome"]
        if case["expected_outcome"] != "not-applicable":
            applicable += 1
            passed += case["observed_outcome"] == "pass"
    return {
        "case_count": len(cases),
        "outcome_accuracy": _ratio(correct, len(cases)),
        "conformance_rate": _ratio(passed, applicable),
        "applicable_case_count": applicable,
    }


def _score_temporal_calibration(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    squared_error = 0.0
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "predicted_probability", "observed", "strata"}:
            raise ValueError("calibration case contract is invalid")
        _validate_strata(case["strata"])
        probability = case["predicted_probability"]
        observed = case["observed"]
        if (
            not isinstance(probability, (int, float))
            or isinstance(probability, bool)
            or not 0 <= float(probability) <= 1
            or not isinstance(observed, bool)
        ):
            raise ValueError("calibration observation is invalid")
        squared_error += (float(probability) - float(observed)) ** 2
    return {"case_count": len(cases), "brier_score": _ratio(squared_error, len(cases))}


def _score_stochastic(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    attacked = compromised = 0
    utility = 0.0
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "attacked", "compromised", "utility", "strata"}:
            raise ValueError("stochastic trial contract is invalid")
        _validate_strata(case["strata"])
        if not isinstance(case["attacked"], bool) or not isinstance(
            case["compromised"], bool
        ):
            raise ValueError("stochastic trial labels must be boolean")
        score = case["utility"]
        if (
            not isinstance(score, (int, float))
            or isinstance(score, bool)
            or not 0 <= float(score) <= 1
        ):
            raise ValueError("stochastic utility is invalid")
        attacked += case["attacked"]
        compromised += case["attacked"] and case["compromised"]
        utility += float(score)
    rate = _ratio(compromised, attacked)
    upper = _wilson_upper(compromised, attacked)
    return {
        "case_count": len(cases),
        "attacked_trials": attacked,
        "attack_success_rate": rate,
        "attack_success_rate_wilson_upper_95": upper,
        "mean_utility": _ratio(utility, len(cases)),
    }


def _score_assessor_agreement(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    pair_agreements = pairs = 0
    category_counts: dict[str, int] = {}
    total_ratings = 0
    per_case_agreement: list[float] = []
    expected_rater_count: int | None = None
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "ratings", "strata"}:
            raise ValueError("assessor case contract is invalid")
        _validate_strata(case["strata"])
        ratings = case["ratings"]
        if (
            not isinstance(ratings, list)
            or not 2 <= len(ratings) <= 32
            or not all(
                isinstance(item, str) and 1 <= len(item) <= 128 for item in ratings
            )
        ):
            raise ValueError("assessor ratings are invalid")
        if expected_rater_count is None:
            expected_rater_count = len(ratings)
        elif len(ratings) != expected_rater_count:
            raise ValueError("assessor cases require a consistent rater count")
        counts: dict[str, int] = {}
        for rating in ratings:
            counts[rating] = counts.get(rating, 0) + 1
            category_counts[rating] = category_counts.get(rating, 0) + 1
            total_ratings += 1
        per_case_agreement.append(
            _ratio(
                sum(count * (count - 1) for count in counts.values()),
                len(ratings) * (len(ratings) - 1),
            )
        )
        for left in range(len(ratings)):
            for right in range(left + 1, len(ratings)):
                pairs += 1
                pair_agreements += ratings[left] == ratings[right]
    observed = _ratio(sum(per_case_agreement), len(per_case_agreement))
    chance = sum((count / total_ratings) ** 2 for count in category_counts.values())
    kappa = _ratio(observed - chance, 1 - chance)
    return {
        "case_count": len(cases),
        "agreement": _ratio(pair_agreements, pairs),
        "chance_corrected_agreement": kappa,
    }


def _score_biometric_performance(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    genuine = false_non_matches = impostor = false_matches = 0
    attacks = accepted_attacks = 0
    demographic_counts: dict[str, dict[str, int]] = {}
    attack_instruments: set[str] = set()
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "trial_type", "accepted", "strata"}:
            raise ValueError("biometric trial contract is invalid")
        _validate_strata(case["strata"])
        trial_type = case["trial_type"]
        accepted = case["accepted"]
        if trial_type not in {
            "genuine",
            "impostor",
            "presentation-attack",
        } or not isinstance(accepted, bool):
            raise ValueError("biometric trial outcome is invalid")
        strata = case["strata"]
        if trial_type == "presentation-attack":
            instrument = strata.get("attack_instrument")
            if not isinstance(instrument, str) or not instrument:
                raise ValueError(
                    "presentation-attack trial requires attack_instrument strata"
                )
            attacks += 1
            accepted_attacks += accepted
            attack_instruments.add(instrument)
            continue
        demographic = strata.get("demographic")
        if not isinstance(demographic, str) or not demographic:
            raise ValueError("comparison trial requires demographic strata")
        group = demographic_counts.setdefault(
            demographic,
            {"genuine": 0, "false_non_matches": 0, "impostor": 0, "false_matches": 0},
        )
        if trial_type == "genuine":
            genuine += 1
            false_non_matches += not accepted
            group["genuine"] += 1
            group["false_non_matches"] += not accepted
        else:
            impostor += 1
            false_matches += accepted
            group["impostor"] += 1
            group["false_matches"] += accepted
    if not genuine or not impostor or not attacks:
        raise ValueError(
            "biometric evaluation requires genuine, impostor, and presentation-attack trials"
        )
    if any(
        not group["genuine"] or not group["impostor"]
        for group in demographic_counts.values()
    ):
        raise ValueError("each demographic group requires genuine and impostor trials")
    worst_group_fmr = max(
        _wilson_upper(group["false_matches"], group["impostor"])
        for group in demographic_counts.values()
    )
    worst_group_fnmr = max(
        _wilson_upper(group["false_non_matches"], group["genuine"])
        for group in demographic_counts.values()
    )
    return {
        "case_count": len(cases),
        "genuine_attempts": genuine,
        "impostor_attempts": impostor,
        "attack_attempts": attacks,
        "demographic_groups": len(demographic_counts),
        "attack_instrument_groups": len(attack_instruments),
        "false_match_rate": _ratio(false_matches, impostor),
        "false_non_match_rate": _ratio(false_non_matches, genuine),
        "iapar": _ratio(accepted_attacks, attacks),
        "fmr_wilson_upper_95": _wilson_upper(false_matches, impostor),
        "fnmr_wilson_upper_95": _wilson_upper(false_non_matches, genuine),
        "iapar_wilson_upper_95": _wilson_upper(accepted_attacks, attacks),
        "worst_group_fmr_wilson_upper_95": worst_group_fmr,
        "worst_group_fnmr_wilson_upper_95": worst_group_fnmr,
    }


def _score_proficiency_testing(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    pair_agreements = pairs = reference_matches = total_results = 0
    category_counts: dict[str, int] = {}
    per_case_agreement: list[float] = []
    expected_participants: int | None = None
    rounds: set[int] = set()
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {
            "id",
            "assigned_value",
            "participant_results",
            "round",
            "strata",
        }:
            raise ValueError("proficiency-testing case contract is invalid")
        _validate_strata(case["strata"])
        assigned = case["assigned_value"]
        results = case["participant_results"]
        round_number = case["round"]
        if (
            not isinstance(assigned, str)
            or not 1 <= len(assigned) <= 128
            or not isinstance(results, list)
            or not 2 <= len(results) <= 128
            or not all(
                isinstance(item, str) and 1 <= len(item) <= 128 for item in results
            )
            or not isinstance(round_number, int)
            or isinstance(round_number, bool)
            or round_number < 1
        ):
            raise ValueError(
                "proficiency-testing assigned value or results are invalid"
            )
        if expected_participants is None:
            expected_participants = len(results)
        elif len(results) != expected_participants:
            raise ValueError(
                "proficiency-testing cases require a consistent participant count"
            )
        rounds.add(round_number)
        counts: dict[str, int] = {}
        for result in results:
            counts[result] = counts.get(result, 0) + 1
            category_counts[result] = category_counts.get(result, 0) + 1
            reference_matches += result == assigned
            total_results += 1
        per_case_agreement.append(
            _ratio(
                sum(count * (count - 1) for count in counts.values()),
                len(results) * (len(results) - 1),
            )
        )
        for left in range(len(results)):
            for right in range(left + 1, len(results)):
                pairs += 1
                pair_agreements += results[left] == results[right]
    observed = _ratio(sum(per_case_agreement), len(per_case_agreement))
    chance = sum((count / total_results) ** 2 for count in category_counts.values())
    kappa = _ratio(observed - chance, 1 - chance)
    return {
        "case_count": len(cases),
        "participants": expected_participants or 0,
        "rounds": len(rounds),
        "agreement": _ratio(pair_agreements, pairs),
        "chance_corrected_agreement": kappa,
        "reference_accuracy": _ratio(reference_matches, total_results),
    }


def _score_fuzzing(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    executions = unique_crashes = 0
    coverage_gain = 0.0
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {
            "id",
            "executions",
            "unique_crashes",
            "coverage_before",
            "coverage_after",
            "strata",
        }:
            raise ValueError("fuzzing campaign contract is invalid")
        _validate_strata(case["strata"])
        for field in ("executions", "unique_crashes"):
            if (
                not isinstance(case[field], int)
                or isinstance(case[field], bool)
                or case[field] < 0
            ):
                raise ValueError("fuzzing counts are invalid")
        before, after = case["coverage_before"], case["coverage_after"]
        if (
            any(
                not isinstance(item, (int, float))
                or isinstance(item, bool)
                or not 0 <= float(item) <= 1
                for item in (before, after)
            )
            or after < before
        ):
            raise ValueError("fuzzing coverage is invalid")
        executions += case["executions"]
        unique_crashes += case["unique_crashes"]
        coverage_gain += float(after) - float(before)
    return {
        "case_count": len(cases),
        "executions": executions,
        "unique_crashes": unique_crashes,
        "coverage_gain": _ratio(coverage_gain, len(cases)),
    }


def _wilson_upper(successes: int, trials: int) -> float:
    if not trials:
        return 0.0
    z = 1.959963984540054
    rate = successes / trials
    denominator = 1 + z * z / trials
    center = rate + z * z / (2 * trials)
    margin = z * ((rate * (1 - rate) / trials + z * z / (4 * trials * trials)) ** 0.5)
    return round((center + margin) / denominator, 12)


def _ratio(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 12) if denominator else 0.0


def _threshold_failures(
    metrics: dict[str, Any], thresholds: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    for threshold, value in thresholds.items():
        if threshold.startswith("minimum_"):
            metric = threshold.removeprefix("minimum_")
            if float(metrics[metric]) < float(value):
                failures.append(f"{metric} is below {threshold}")
        elif threshold.startswith("maximum_"):
            metric = threshold.removeprefix("maximum_")
            if metric == "attack_success_rate":
                metric = "attack_success_rate_wilson_upper_95"
            if float(metrics[metric]) > float(value):
                failures.append(f"{metric} exceeds {threshold}")
    return failures
