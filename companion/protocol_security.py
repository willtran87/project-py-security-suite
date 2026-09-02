from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import os
import socket
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from companion.assurance_context import load_context
    from companion.provenance import inline_provenance
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
except ModuleNotFoundError:  # Direct script execution.
    from assurance_context import load_context  # type: ignore[import-not-found,no-redef]
    from provenance import inline_provenance  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]

_MAX_CONTRACT_BYTES = 1024 * 1024


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute bounded gRPC, WebSocket, and TCP security contracts against loopback."
    )
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--valid-for-hours", type=float, default=24.0)
    args = parser.parse_args(argv)
    contract_bytes = _regular_bytes(args.contract)
    contract = strict_loads(contract_bytes)
    cases = _cases(contract)
    findings: list[dict[str, Any]] = []
    protocols: set[str] = set()
    roles: set[str] = set()
    for case in cases:
        protocols.add(case["protocol"])
        roles.add(case["role"])
        status, digest = _execute(case)
        if status not in case["expected_status"] or (
            case["expected_response_sha256"]
            and digest != case["expected_response_sha256"]
        ):
            findings.append(_finding(case, status, digest))
    context = load_context(args.context, [f"protocol:{case['id']}" for case in cases])
    generated = datetime.now(UTC)
    environment = "loopback-protocol-contracts"
    document = {
        "schema_version": "2.0",
        "kind": "protocol-security",
        "producer": "pysec-protocol-contract",
        "producer_version": "1",
        "producer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "revision": _text(args.revision, "revision", 200),
        "generated_at": generated.isoformat(),
        "expires_at": (generated + timedelta(hours=args.valid_for_hours)).isoformat(),
        "run_id": _context_run_id(args.run_id, context["run_id"]),
        "artifact_sha256": "",
        "ruleset_sha256": hashlib.sha256(b"protocol-contract-v1").hexdigest(),
        "config_sha256": hashlib.sha256(contract_bytes).hexdigest(),
        "environment": environment,
        "environment_sha256": hashlib.sha256(environment.encode()).hexdigest(),
        "context": {key: value for key, value in context.items() if key != "run_id"},
        "execution": {
            "status": "completed",
            "targets_discovered": len(cases),
            "targets_exercised": len(cases),
            "requests": len(cases),
            "coverage_percent": 100.0,
            "coverage_metric": "declared-protocol-contract-cases",
            "roles": sorted(roles),
            "features": [
                "protocol-inventory",
                "contract-cases",
                "fault-injection",
                *[f"protocol:{name}" for name in sorted(protocols)],
            ],
            "skipped_checks": [],
            "canaries_expected": 1,
            "canaries_observed": int(_boundary_canary()),
        },
        "findings": findings,
        "protocols": sorted(protocols),
    }
    # Protocol identities are retained as bounded feature labels so admission
    # and independent reviewers can distinguish the exercised transports.
    document.pop("protocols")
    document["provenance"] = inline_provenance(
        native_receipt={"execution": document["execution"], "findings": findings},
        builder_id="pysec-protocol-contract",
        builder=Path(__file__),
        invocation=contract_bytes,
        materials=document["context"],
    )
    _write(args.output, document)
    return 0


def _cases(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {"cases"}:
        raise ValueError("protocol contract root fields do not match")
    cases = value["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 500:
        raise ValueError("protocol contract requires 1 to 500 cases")
    result: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for item in cases:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "protocol",
            "endpoint",
            "method",
            "request_env",
            "role",
            "control",
            "expected_status",
            "expected_response_sha256",
        }:
            raise ValueError("protocol case fields do not match")
        identifier = _label(item["id"], "case id")
        if identifier in identifiers:
            raise ValueError("protocol case IDs must be unique")
        protocol = str(item["protocol"]).casefold()
        if protocol not in {"grpc", "tcp", "websocket"}:
            raise ValueError("protocol case uses an unsupported protocol")
        endpoint = _endpoint(str(item["endpoint"]), protocol)
        method = str(item["method"] or "")
        if protocol == "grpc" and (not method.startswith("/") or len(method) > 300):
            raise ValueError("gRPC cases require a bounded fully-qualified method")
        request_env = str(item["request_env"] or "")
        if (
            not request_env
            or len(request_env) > 100
            or request_env.upper() != request_env
            or not request_env.replace("_", "").isalnum()
        ):
            raise ValueError("protocol request_env must be an uppercase variable")
        control = _label(item["control"], "control")
        if control not in {"contract", "fault"}:
            raise ValueError("protocol control must be contract or fault")
        statuses = item["expected_status"]
        if not isinstance(statuses, list) or not 1 <= len(statuses) <= 20:
            raise ValueError("protocol expected_status must be a bounded list")
        digest = str(item["expected_response_sha256"] or "").casefold()
        if digest and (
            len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError("expected_response_sha256 is invalid")
        identifiers.add(identifier)
        result.append(
            {
                "id": identifier,
                "protocol": protocol,
                "endpoint": endpoint,
                "method": method,
                "request_env": request_env,
                "role": _label(item["role"], "role"),
                "control": control,
                "expected_status": {
                    _label(status, "expected status") for status in statuses
                },
                "expected_response_sha256": digest,
            }
        )
    if not any(item["control"] == "fault" for item in result):
        raise ValueError("protocol contract requires at least one fault-injection case")
    return result


def _endpoint(value: str, protocol: str) -> str:
    if protocol == "websocket":
        parsed = urlsplit(value)
        if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
            raise ValueError("WebSocket endpoint is invalid")
        host = parsed.hostname
    else:
        if value.count(":") != 1:
            raise ValueError("gRPC/TCP endpoint must be host:port")
        host, port = value.rsplit(":", 1)
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("protocol endpoint port is invalid")
    if host.casefold() != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("protocol endpoint must be loopback")
        except ValueError as exc:
            raise ValueError("protocol endpoint must use explicit loopback") from exc
    return value


def _execute(case: dict[str, Any]) -> tuple[str, str]:
    import grpc  # type: ignore[import-not-found,import-untyped]
    from websockets.sync.client import connect  # type: ignore[import-not-found,import-untyped]

    encoded = os.environ.get(case["request_env"])
    if encoded is None:
        raise ValueError(
            f"protocol payload environment is absent: {case['request_env']}"
        )
    try:
        payload = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ValueError("protocol payload is not valid base64") from exc
    if len(payload) > 1024 * 1024:
        raise ValueError("protocol payload exceeds 1 MiB")
    response = b""
    status = "OK"
    try:
        if case["protocol"] == "grpc":
            # This executor rejects every non-loopback endpoint in ``_endpoint``.
            # The plaintext channel is intentionally confined to an ephemeral
            # local adversarial-test server and never carries production traffic.
            with grpc.insecure_channel(  # nosemgrep: python.grpc-insecure-channel
                case["endpoint"]
            ) as channel:
                call = channel.unary_unary(
                    case["method"],
                    request_serializer=lambda value: value,
                    response_deserializer=lambda value: value,
                )
                response = bytes(call(payload, timeout=10))
        elif case["protocol"] == "websocket":
            with connect(case["endpoint"], open_timeout=10, close_timeout=5) as client:
                client.send(payload)
                received = client.recv(timeout=10)
                response = (
                    received.encode() if isinstance(received, str) else bytes(received)
                )
        else:
            host, port = case["endpoint"].rsplit(":", 1)
            with socket.create_connection((host, int(port)), timeout=10) as client:
                client.sendall(payload)
                response = client.recv(1024 * 1024)
    except grpc.RpcError as exc:
        status = exc.code().name
    except (OSError, TimeoutError) as exc:
        status = type(exc).__name__.upper()
    return status, hashlib.sha256(response).hexdigest()


def _finding(case: dict[str, Any], status: str, digest: str) -> dict[str, Any]:
    return {
        "rule_id": f"protocol-{case['control']}-failed",
        "title": "A protocol security contract failed",
        "message": "Observed protocol status or response identity did not satisfy the declared contract.",
        "path": "<runtime-protocol-contract>",
        "severity": "high" if case["control"] == "fault" else "medium",
        "classification": "CWE-20",
        "remediation": "Enforce protocol authentication, message validation, replay, and fault-handling invariants and retain a regression case.",
        "area": "non-http-protocol-security-testing",
        "domain": "security",
        "evidence": {
            "case_id": case["id"],
            "protocol": case["protocol"],
            "control": case["control"],
            "observed_status": status,
            "response_sha256": digest,
        },
    }


def _boundary_canary() -> bool:
    try:
        _endpoint("example.invalid:443", "grpc")
    except ValueError:
        return True
    return False


def _regular_bytes(path: Path) -> bytes:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > _MAX_CONTRACT_BYTES
    ):
        raise ValueError("protocol contract must be a regular file of at most 1 MiB")
    return path.read_bytes()


def _label(value: object, name: str) -> str:
    result = _text(value, name, 160)
    if not all(character.isalnum() or character in "._:-" for character in result):
        raise ValueError(f"{name} contains unsupported characters")
    return result


def _text(value: object, name: str, maximum: int) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum:
        raise ValueError(f"{name} must be between 1 and {maximum} characters")
    return result


def _run_id(value: str) -> str:
    return _label(value.strip() or str(uuid.uuid4()), "run id")


def _context_run_id(requested: str, expected: str) -> str:
    result = _run_id(requested or expected)
    if result != expected:
        raise ValueError("run-id does not match the organization-issued context")
    return result


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("protocol output is not replaceable")
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
