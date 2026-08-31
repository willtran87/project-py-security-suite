from __future__ import annotations

import base64
import hashlib
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from .execution import (
    CommandEnvironment,
    RawExecution,
    native_runtime_closure_sha256,
    resolve_executable,
    run_command,
    sanitize_diagnostic,
    sha256_file,
)
from .operation_receipt import verify_operation_receipt
from .path_safety import read_regular_file
from .strict_json import canonical_bytes, loads as strict_loads
from .attestation_formats import verify_format_evidence
from .failure_domain import (
    require_independent_failure_domains,
    verify_registered_failure_domain,
)


def run_pinned_json_command(
    prefix: str,
    request: dict[str, Any],
    *,
    timeout_seconds: int = 30,
    maximum_output_bytes: int = 1024 * 1024,
) -> dict[str, Any]:
    """Execute a deployment-pinned argv protocol and return strict JSON."""

    raw_command = os.environ.get(f"{prefix}_COMMAND_JSON", "").strip()
    expected_executable = (
        os.environ.get(f"{prefix}_EXECUTABLE_SHA256", "").strip().casefold()
    )
    try:
        command = strict_loads(raw_command)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{prefix} command is invalid") from exc
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(item, str) or not item for item in command)
        or not _digest(expected_executable)
    ):
        raise ValueError(f"{prefix} command configuration is incomplete")
    resolved = resolve_executable(command[0])
    if resolved is None or sha256_file(Path(resolved)) != expected_executable:
        raise ValueError(f"{prefix} executable does not match its deployment pin")
    _verify_assets(prefix)
    raw_endpoints = os.environ.get(f"{prefix}_ALLOWED_ENDPOINTS_JSON", "").strip()
    mtls_identity = (
        os.environ.get(f"{prefix}_MTLS_IDENTITY_SHA256", "").strip().casefold()
    )
    sandbox_identity = (
        os.environ.get(f"{prefix}_SANDBOX_IDENTITY_SHA256", "").strip().casefold()
    )
    raw_sandbox = os.environ.get(f"{prefix}_SANDBOX_COMMAND_JSON", "").strip()
    sandbox_executable_sha256 = (
        os.environ.get(f"{prefix}_SANDBOX_EXECUTABLE_SHA256", "").strip().casefold()
    )
    attestor_key_sha256 = (
        os.environ.get(f"{prefix}_EXECUTION_ATTESTATION_KEY_SHA256", "")
        .strip()
        .casefold()
    )
    remote_attestation_key_sha256 = (
        os.environ.get(f"{prefix}_REMOTE_ATTESTATION_KEY_SHA256", "").strip().casefold()
    )
    try:
        allowed_endpoints = strict_loads(raw_endpoints)
        sandbox_command = strict_loads(raw_sandbox)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{prefix} transport policy is invalid") from exc
    if (
        not isinstance(allowed_endpoints, list)
        or allowed_endpoints != sorted(set(allowed_endpoints))
        or any(not isinstance(item, str) or not item for item in allowed_endpoints)
        or any(not item.startswith("https://") for item in allowed_endpoints)
        or not _digest(mtls_identity)
        or not _digest(sandbox_identity)
        or not isinstance(sandbox_command, list)
        or not sandbox_command
        or any(not isinstance(item, str) or not item for item in sandbox_command)
        or not _digest(sandbox_executable_sha256)
        or not _digest(attestor_key_sha256)
        or not _digest(remote_attestation_key_sha256)
        or remote_attestation_key_sha256 == attestor_key_sha256
    ):
        raise ValueError(f"{prefix} transport and sandbox policy is incomplete")
    resolved_sandbox = resolve_executable(sandbox_command[0])
    if (
        resolved_sandbox is None
        or sha256_file(Path(resolved_sandbox)) != sandbox_executable_sha256
    ):
        raise ValueError(f"{prefix} sandbox launcher does not match its pin")
    enforced_sandbox_identity = hashlib.sha256(
        canonical_bytes(
            {
                "launcher_sha256": sandbox_executable_sha256,
                "launcher_argv": sandbox_command[1:],
                "allowed_endpoints": allowed_endpoints,
                "mtls_identity_sha256": mtls_identity,
            }
        )
    ).hexdigest()
    if sandbox_identity != enforced_sandbox_identity:
        raise ValueError(f"{prefix} sandbox identity does not match its policy")
    runtime_pin = os.environ.get(f"{prefix}_RUNTIME_SHA256", "").strip().casefold()
    if runtime_pin and (
        not _digest(runtime_pin)
        or native_runtime_closure_sha256(Path(resolved)) != runtime_pin
    ):
        raise ValueError(f"{prefix} runtime closure does not match its deployment pin")
    if "command_context" in request:
        raise ValueError(f"{prefix} request reserved fields are already present")
    request["command_context"] = {
        "schema_version": "1.0",
        "executable_sha256": expected_executable,
        "allowed_endpoints": allowed_endpoints,
        "mtls_identity_sha256": mtls_identity,
        "sandbox_identity_sha256": sandbox_identity,
        "sandbox_executable_sha256": sandbox_executable_sha256,
        "sandbox_launcher_argv": [str(item) for item in sandbox_command[1:]],
        "effective_policy_attestor_key_sha256": attestor_key_sha256,
        "remote_attestation_key_sha256": remote_attestation_key_sha256,
    }
    encoded_request = base64.b64encode(canonical_bytes(request)).decode("ascii")
    nonce = os.urandom(32).hex()
    attestation_base = {
        "schema_version": "1.0",
        "request_sha256": hashlib.sha256(canonical_bytes(request)).hexdigest(),
        "command_context_sha256": hashlib.sha256(
            canonical_bytes(request["command_context"])
        ).hexdigest(),
        "execution_nonce": nonce,
        "launcher_sha256": sandbox_executable_sha256,
        "executable_sha256": expected_executable,
        "attestor_key_sha256": attestor_key_sha256,
        "sandbox_identity_sha256": sandbox_identity,
        "remote_attestation_key_sha256": remote_attestation_key_sha256,
    }
    with tempfile.TemporaryDirectory(prefix="pysec-pinned-attestation-") as temporary:
        attestation_path = Path(temporary) / "effective-policy.json"
        result = run_command(
            [str(resolved), *command[1:], encoded_request],
            cwd=Path(resolved).parent,
            timeout_seconds=timeout_seconds,
            max_output_bytes=maximum_output_bytes,
            environment=CommandEnvironment(
                extra={
                    "PYSEC_PINNED_ATTESTATION_PATH": str(attestation_path),
                    "PYSEC_PINNED_ATTESTATION_SUBJECT_BASE64": base64.b64encode(
                        canonical_bytes(attestation_base)
                    ).decode("ascii"),
                    "PYSEC_PINNED_ATTESTATION_CHALLENGE_SHA256": os.environ.get(
                        "PYSEC_SCAN_TIME_CHALLENGE_SHA256", ""
                    ),
                    "PYSEC_SCAN_TIME_CONTEXT_SHA256": os.environ.get(
                        "PYSEC_SCAN_TIME_CONTEXT_SHA256", ""
                    ),
                },
                sandbox_prefix=tuple(str(item) for item in sandbox_command),
                sandbox_executable_sha256=sandbox_executable_sha256,
                max_scratch_bytes=16 * 1024 * 1024,
            ),
        )
        failure_detail = _execution_failure_detail(result)
        if failure_detail:
            raise ValueError(
                f"{prefix} command failed its governed execution contract: "
                f"{failure_detail}"
            )
        execution_attestation = _verify_execution_attestation(
            attestation_path,
            attestation_base,
            result.exit_code,
            attestor_key_sha256,
        )
    if sha256_file(Path(resolved)) != expected_executable:
        raise ValueError(f"{prefix} executable changed during governed execution")
    _verify_assets(prefix)
    try:
        value = strict_loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{prefix} command returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{prefix} command response must be an object")
    if "_effective_policy_attestation" in value:
        raise ValueError(f"{prefix} command response used a reserved field")
    value["_effective_policy_attestation"] = execution_attestation
    return value


def _execution_failure_detail(result: RawExecution) -> str:
    failures: list[str] = []
    if result.exit_code != 0:
        failures.append(f"exit code {result.exit_code}")
    if result.timed_out:
        failures.append("timed out")
    if result.output_limit_exceeded:
        failures.append("output limit exceeded")
    if result.scratch_limit_exceeded:
        failures.append("scratch limit exceeded")
    if result.resident_memory_limit_exceeded:
        failures.append("resident-memory limit exceeded")
    if result.resource_limit_errors:
        failures.append("resource limits were not enforced")
    diagnostic = sanitize_diagnostic(result.stderr, maximum=1024)
    if diagnostic:
        failures.append(diagnostic)
    return "; ".join(failures)


def _verify_execution_attestation(
    path: Path,
    base: dict[str, Any],
    exit_code: int | None,
    expected_key_sha256: str,
) -> dict[str, Any]:
    _, payload = read_regular_file(
        path,
        "pinned command effective-policy attestation",
        maximum_bytes=1024 * 1024,
    )
    value = strict_loads(payload)
    if not isinstance(value, dict) or set(value) != {"subject", "operation_receipt"}:
        raise ValueError("pinned command effective-policy attestation is invalid")
    subject = value["subject"]
    if (
        not isinstance(subject, dict)
        or set(subject)
        != {
            *base,
            "exit_code",
            "attestor_process_id",
            "policy_observations",
        }
        or any(subject[name] != item for name, item in base.items())
        or subject["exit_code"] != exit_code
        or isinstance(subject["attestor_process_id"], bool)
        or not isinstance(subject["attestor_process_id"], int)
        or subject["attestor_process_id"] < 1
    ):
        raise ValueError("pinned command effective policy was not enforced")
    verify_effective_policy_subject(subject)
    receipt = value["operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        observed_at = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("pinned command attestation time is invalid") from exc
    verify_operation_receipt(
        subject,
        receipt,
        purpose="pinned-command-effective-policy",
        observed_at=observed_at,
        challenge_sha256=os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "")
        .strip()
        .casefold(),
        expected_key_sha256=expected_key_sha256,
    )
    return dict(value)


def verify_effective_policy_subject(subject: object) -> None:
    if not isinstance(subject, dict):
        raise ValueError("effective-policy attestation subject is invalid")
    policy = subject.get("policy_observations")
    if not isinstance(policy, dict) or set(policy) != {
        "network_allowlist_enforced",
        "filesystem_read_only",
        "credentials_isolated",
        "child_process_confined",
        "measurement_source",
        "measurement_artifact",
        "measurement_artifact_sha256",
        "remote_attestation",
    }:
        raise ValueError("effective-policy measurements are incomplete")
    controls = {
        "network_allowlist_enforced": policy["network_allowlist_enforced"],
        "filesystem_read_only": policy["filesystem_read_only"],
        "credentials_isolated": policy["credentials_isolated"],
        "child_process_confined": policy["child_process_confined"],
    }
    measurement = policy["measurement_artifact"]
    remote_attestation = policy["remote_attestation"]
    expected_source = {
        "linux": "linux-procfs-seccomp",
        "win32": "windows-job-object-query",
        "darwin": "macos-sandbox-audit",
    }
    if (
        any(item is not True for item in controls.values())
        or policy["measurement_source"] not in set(expected_source.values())
        or not isinstance(measurement, dict)
        or set(measurement)
        != {
            "schema_version",
            "platform",
            "child_process_id",
            "child_exit_code",
            "kernel_identity_sha256",
            "sandbox_identity_sha256",
            "controls",
        }
        or measurement.get("schema_version") != "1.0"
        or expected_source.get(str(measurement.get("platform")))
        != policy["measurement_source"]
        or isinstance(measurement.get("child_process_id"), bool)
        or not isinstance(measurement.get("child_process_id"), int)
        or measurement["child_process_id"] < 1
        or measurement.get("child_exit_code") != subject.get("exit_code")
        or not _digest(str(measurement.get("kernel_identity_sha256") or ""))
        or measurement.get("sandbox_identity_sha256")
        != subject.get("sandbox_identity_sha256")
        or measurement.get("controls") != controls
        or policy["measurement_artifact_sha256"]
        != hashlib.sha256(canonical_bytes(measurement)).hexdigest()
    ):
        raise ValueError("effective-policy kernel measurement is invalid")
    _verify_remote_attestation(subject, remote_attestation)


def remote_attested_failure_domain(attestation: object) -> dict[str, str]:
    """Return the hardware-attested host failure domain for a pinned execution."""

    subject = attestation.get("subject") if isinstance(attestation, dict) else None
    if not isinstance(subject, dict):
        raise ValueError("effective-policy attestation subject is invalid")
    verify_effective_policy_subject(subject)
    policy = subject["policy_observations"]
    remote = policy["remote_attestation"]
    remote_subject = remote["subject"]
    return {
        name: str(remote_subject[name]).strip().casefold()
        for name in (
            "organization",
            "host_identity_sha256",
            "control_plane_sha256",
            "implementation_sha256",
        )
    }


def verify_retained_effective_policy_attestation(
    attestation: object,
) -> dict[str, str]:
    """Fully reverify a retained execution and its hardware-attested domain."""

    if not isinstance(attestation, dict) or set(attestation) != {
        "subject",
        "operation_receipt",
    }:
        raise ValueError("retained effective-policy attestation is invalid")
    subject = attestation["subject"]
    if not isinstance(subject, dict):
        raise ValueError("retained effective-policy subject is invalid")
    verify_effective_policy_subject(subject)
    receipt = attestation["operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        observed = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("retained effective-policy time is invalid") from exc
    challenge = (
        os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    )
    verify_operation_receipt(
        subject,
        receipt,
        purpose="pinned-command-effective-policy",
        observed_at=observed,
        challenge_sha256=challenge,
        expected_key_sha256=str(subject.get("attestor_key_sha256") or ""),
    )
    return remote_attested_failure_domain(attestation)


def _verify_remote_attestation(
    execution_subject: dict[str, Any], value: object
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "subject",
        "operation_receipt",
    }:
        raise ValueError("sandbox remote attestation fields do not match")
    subject = value["subject"]
    fields = {
        "schema_version",
        "format",
        "purpose",
        "challenge_sha256",
        "host_identity_sha256",
        "organization",
        "control_plane_sha256",
        "implementation_sha256",
        "secure_boot",
        "measured_boot",
        "pcrs_sha256",
        "quote_base64",
        "quote_sha256",
    }
    if not isinstance(subject, dict) or set(subject) != fields:
        raise ValueError("sandbox remote attestation subject is invalid")
    try:
        quote = base64.b64decode(str(subject["quote_base64"]), validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("sandbox remote attestation quote is invalid") from exc
    expected_key = str(execution_subject.get("remote_attestation_key_sha256") or "")
    challenge = (
        os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    )
    if (
        subject.get("schema_version") != "1.0"
        or subject.get("format") not in {"tpm2-quote", "nitro-attestation", "sev-snp"}
        or subject.get("purpose") != "sandbox-effective-policy"
        or subject.get("challenge_sha256") != challenge
        or not _digest(str(subject.get("host_identity_sha256") or ""))
        or not str(subject.get("organization") or "").strip()
        or not _digest(str(subject.get("control_plane_sha256") or ""))
        or not _digest(str(subject.get("implementation_sha256") or ""))
        or subject.get("secure_boot") is not True
        or subject.get("measured_boot") is not True
        or not _digest(str(subject.get("pcrs_sha256") or ""))
        or not quote
        or hashlib.sha256(quote).hexdigest() != subject.get("quote_sha256")
        or not _digest(expected_key)
    ):
        raise ValueError("sandbox remote attestation trust binding is invalid")
    verify_format_evidence(
        quote,
        format_name=str(subject["format"]),
        challenge_sha256=challenge,
        host_identity_sha256=str(subject["host_identity_sha256"]),
        pcrs_sha256=str(subject["pcrs_sha256"]),
        implementation_sha256=str(subject["implementation_sha256"]),
        normalized_authority_key_sha256=expected_key,
        normalized_failure_domain={
            "organization": subject["organization"],
            "host_identity_sha256": subject["host_identity_sha256"],
            "control_plane_sha256": subject["control_plane_sha256"],
            "implementation_sha256": subject["implementation_sha256"],
        },
        native_replay_verifier=_verify_native_raw_attestation_replay,
    )
    verify_registered_failure_domain(
        {
            "organization": subject["organization"],
            "host_identity_sha256": subject["host_identity_sha256"],
            "control_plane_sha256": subject["control_plane_sha256"],
            "implementation_sha256": subject["implementation_sha256"],
        },
        expected_key,
        "remote attestation authority",
    )
    receipt = value["operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        observed = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("sandbox remote attestation time is invalid") from exc
    verify_operation_receipt(
        subject,
        receipt,
        purpose="sandbox-remote-attestation",
        observed_at=observed,
        challenge_sha256=challenge,
        expected_key_sha256=expected_key,
    )


def _verify_native_raw_attestation_replay(
    *,
    claims: dict[str, Any],
    format_name: str,
    expected_statement: dict[str, Any],
    implementation_sha256: str,
    replay_domain: object,
    replay_key_sha256: str,
    normalized_failure_domain: dict[str, object],
    verification_method: str,
    required: bool,
) -> None:
    """Execute and bind the independently pinned native format verifier."""

    require_independent_failure_domains(
        normalized_failure_domain,
        replay_domain,
        labels=("normalized attestation authority", "raw replay verifier"),
    )
    verify_registered_failure_domain(
        replay_domain, replay_key_sha256, "raw attestation replay verifier"
    )
    prefix = "PYSEC_RAW_ATTESTATION_NATIVE_REPLAY"
    if not command_configured(prefix):
        if required:
            raise ValueError("native raw attestation verifier is unavailable")
        return
    statement_sha256 = hashlib.sha256(canonical_bytes(expected_statement)).hexdigest()
    response = run_pinned_json_command(
        prefix,
        {
            "schema_version": "1.0",
            "operation": "verify-raw-hardware-attestation",
            "format": format_name,
            "raw_evidence_base64": claims["raw_evidence_base64"],
            "raw_evidence_sha256": expected_statement["raw_evidence_sha256"],
            "expected_statement": expected_statement,
            "expected_statement_sha256": statement_sha256,
        },
        timeout_seconds=60,
        maximum_output_bytes=1024 * 1024,
    )
    attestation = response.pop("_effective_policy_attestation", None)
    expected_response = {
        "schema_version": "1.0",
        "verified": True,
        "format": format_name,
        "raw_evidence_sha256": expected_statement["raw_evidence_sha256"],
        "normalized_claims_sha256": expected_statement["normalized_claims_sha256"],
        "verification_statement_sha256": statement_sha256,
        "verification_method": verification_method,
        "trust_root_sha256": expected_statement["trust_root_sha256"],
    }
    attested_subject = (
        attestation.get("subject") if isinstance(attestation, dict) else None
    )
    if (
        response != expected_response
        or not isinstance(attested_subject, dict)
        or attested_subject.get("executable_sha256") != implementation_sha256
        or remote_attested_failure_domain(attestation) != replay_domain
    ):
        raise ValueError("native raw attestation replay result is detached or invalid")


def command_configured(prefix: str) -> bool:
    return bool(os.environ.get(f"{prefix}_COMMAND_JSON", "").strip())


def _verify_assets(prefix: str) -> None:
    raw = os.environ.get(f"{prefix}_ASSETS_JSON", "[]").strip()
    try:
        assets = strict_loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{prefix} command assets are invalid") from exc
    if not isinstance(assets, list) or len(assets) > 100:
        raise ValueError(f"{prefix} command assets are invalid")
    paths: set[Path] = set()
    for item in assets:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValueError(f"{prefix} command asset fields do not match")
        path = Path(str(item["path"])).expanduser().resolve()
        digest = str(item["sha256"]).casefold()
        if path in paths or not _digest(digest) or sha256_file(path) != digest:
            raise ValueError(f"{prefix} command asset does not match its pin")
        paths.add(path)


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
