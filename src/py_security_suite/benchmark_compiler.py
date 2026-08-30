from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .benchmark_adapters import benchmark_adapter_spec, benchmark_execution_contracts
from .benchmark_execution import (
    BenchmarkExecutionError,
    _benchmark_subject_sha256,
    _validate_manifest,
)
from .benchmark_input_validation import (
    BenchmarkInputError,
    validate_benchmark_input,
)
from .path_safety import read_regular_file, resolve_regular_file
from .strict_json import loads as strict_loads


_MAX_REQUEST_BYTES = 2 * 1024 * 1024


def compile_benchmark_manifest(request_path: Path, workspace: Path) -> dict[str, Any]:
    """Compile a maintained adapter request into a registry-bound 1.2 manifest."""
    _, payload = read_regular_file(
        request_path,
        "benchmark preparation request",
        maximum_bytes=_MAX_REQUEST_BYTES,
    )
    try:
        request = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise BenchmarkExecutionError(
            "benchmark preparation request is invalid JSON"
        ) from exc
    _validate_request(request)
    work = workspace.expanduser().absolute().resolve()
    if not work.is_dir():
        raise BenchmarkExecutionError(
            "benchmark preparation workspace is not a directory"
        )

    contracts = benchmark_execution_contracts()
    identifier = str(request["benchmark_id"])
    contract = contracts.get(identifier)
    if contract is None:
        raise BenchmarkExecutionError("benchmark has no registered execution contract")
    try:
        adapter = benchmark_adapter_spec(identifier)
    except ValueError as exc:
        raise BenchmarkExecutionError(
            "benchmark has no maintained adapter specification"
        ) from exc

    corpus = _workspace_file(work, request["corpus"]["path"], "benchmark corpus")
    required_inputs = []
    requested_inputs = request["required_inputs"]
    expected_inputs = set(adapter["required_inputs"])
    if set(requested_inputs) != expected_inputs:
        missing = sorted(expected_inputs - set(requested_inputs))
        extra = sorted(set(requested_inputs) - expected_inputs)
        raise BenchmarkExecutionError(
            "benchmark required input identities do not match maintained contract"
            + (f"; missing: {', '.join(missing)}" if missing else "")
            + (f"; unexpected: {', '.join(extra)}" if extra else "")
        )
    for name in adapter["required_inputs"]:
        path = _workspace_file(work, requested_inputs[name], f"adapter input {name}")
        try:
            validation = validate_benchmark_input(path)
        except BenchmarkInputError as exc:
            raise BenchmarkExecutionError(
                f"adapter input {name} is invalid: {exc}"
            ) from exc
        required_inputs.append(
            {
                "name": name,
                "path": path.relative_to(work).as_posix(),
                "sha256": _sha256(path),
                "validation": validation,
            }
        )

    stages = []
    for item in request["stages"]:
        executable = resolve_regular_file(
            Path(item["executable"]), "benchmark stage executable"
        )
        stages.append(
            {
                **item,
                "executable": str(executable),
                "executable_sha256": _sha256(executable),
            }
        )

    manifest: dict[str, Any] = {
        "schema_version": "1.2",
        "benchmark_id": identifier,
        "benchmark_version": contract["version"],
        "adapter_version": request["adapter_version"],
        "protocol": contract["protocol"],
        "adapter_contract": {
            "id": identifier,
            "version": "1.0",
            "sha256": contract["adapter_spec_sha256"],
            "normalizer": adapter["normalizer"],
            "required_inputs": required_inputs,
        },
        "corpus": {
            **request["corpus"],
            "path": corpus.relative_to(work).as_posix(),
            "sha256": _sha256(corpus),
        },
        "stages": stages,
        "normalized_result": request["normalized_result"],
        "thresholds": request["thresholds"],
        "evaluation": request["evaluation"],
        "authority_policy": request["authority_policy"],
        "isolation": request["isolation"],
        "attestations": request["attestations"],
    }
    _validate_manifest(
        manifest,
        known_benchmark_ids=None,
        benchmark_contracts=contracts,
    )
    subject_sha256 = _benchmark_subject_sha256(manifest, manifest["corpus"]["sha256"])
    return {
        "schema_version": "1.0",
        "analysis": "maintained-benchmark-manifest-compilation",
        "benchmark_id": identifier,
        "adapter_contract_sha256": contract["adapter_spec_sha256"],
        "benchmark_subject_sha256": subject_sha256,
        "manifest": manifest,
        "next_step": (
            "Issue the subject-bound independent attestations named by the manifest, "
            "update their reference digests, then run pysec benchmark-run."
        ),
        "claim_boundary": (
            "Compilation binds identities, inputs, versions and safety policy. It does "
            "not acquire licensed content or issue independent attestations."
        ),
    }


def _validate_request(value: object) -> None:
    required = {
        "schema_version",
        "benchmark_id",
        "adapter_version",
        "corpus",
        "stages",
        "normalized_result",
        "thresholds",
        "evaluation",
        "authority_policy",
        "isolation",
        "attestations",
        "required_inputs",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise BenchmarkExecutionError(
            "benchmark preparation request fields are invalid"
        )
    if value["schema_version"] != "1.0":
        raise BenchmarkExecutionError(
            "unsupported benchmark preparation request version"
        )
    if not isinstance(value["required_inputs"], dict):
        raise BenchmarkExecutionError("benchmark preparation inputs are invalid")
    corpus = value["corpus"]
    if not isinstance(corpus, dict) or set(corpus) != {
        "path",
        "license_sha256",
        "label_authority_sha256",
        "organization_approved",
    }:
        raise BenchmarkExecutionError("benchmark preparation corpus is invalid")
    stages = value["stages"]
    expected_stage_fields = {
        "name",
        "executable",
        "arguments",
        "environment",
        "timeout_seconds",
        "expected_exit_codes",
    }
    if (
        not isinstance(stages, list)
        or not stages
        or any(
            not isinstance(item, dict) or set(item) != expected_stage_fields
            for item in stages
        )
    ):
        raise BenchmarkExecutionError("benchmark preparation stages are invalid")


def _workspace_file(workspace: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise BenchmarkExecutionError(f"{label} path is invalid")
    candidate = Path(value)
    candidate = candidate if candidate.is_absolute() else workspace / candidate
    resolved = resolve_regular_file(candidate, label)
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise BenchmarkExecutionError(
            f"{label} must remain inside the workspace"
        ) from exc
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
