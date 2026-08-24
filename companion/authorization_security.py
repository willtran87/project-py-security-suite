from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import os
import tempfile
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from companion.assurance_context import load_context
    from companion.provenance import inline_provenance
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
    from companion.strict_json import canonical_bytes
except ModuleNotFoundError:  # Direct script execution.
    from assurance_context import load_context  # type: ignore[import-not-found,no-redef]
    from provenance import inline_provenance  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]
    from strict_json import canonical_bytes  # type: ignore[import-not-found,no-redef]


_MAX_CONTRACT_BYTES = 1024 * 1024


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run bounded multi-role authorization contracts against loopback."
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
    base_fields = {
        "schema_version",
        "base_url",
        "roles",
        "cases",
        "state_cases",
    }
    if not isinstance(contract, dict) or set(contract) not in {
        frozenset(base_fields),
        frozenset(base_fields | {"oracle", "recovery_checks"}),
    }:
        raise TypeError("authorization contract root fields do not match")
    version = str(contract.get("schema_version") or "")
    advanced = {"oracle", "recovery_checks"}.issubset(contract)
    if version not in {"2.0", "3.0"} or (version == "3.0") != advanced:
        raise ValueError("authorization contract version and oracle are inconsistent")
    base_url = _loopback_url(str(contract.get("base_url") or ""))
    roles = _roles(contract.get("roles"))
    oracle = (
        _oracle(contract.get("oracle"), base_url, roles) if version == "3.0" else None
    )
    cases = _cases(contract.get("cases"), roles)
    state_cases = _state_cases(contract.get("state_cases"), roles)
    recovery_checks = (
        _recovery_checks(contract.get("recovery_checks"), roles)
        if version == "3.0"
        else []
    )
    pending_recovery_receipts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    requests = 0
    exercised = 0
    exercised_ids: list[str] = []
    for case in cases:
        for expectation, names in (("allow", case["allow"]), ("deny", case["deny"])):
            for role in names:
                status = _request(base_url, case["path"], roles[role])
                requests += 1
                exercised += 1
                exercised_ids.append(f"auth:{case['id']}:{expectation}:{role}")
                expected = (
                    set(case["allowed_status"])
                    if expectation == "allow"
                    else set(case["denied_status"])
                )
                if status not in expected:
                    findings.append(_finding(case["id"], role, expectation, status))
    for case in state_cases:
        reset_status = _request(
            base_url,
            case["reset"]["path"],
            roles[case["reset"]["role"]],
            method=case["reset"]["method"],
            body_env=case["reset"]["body_env"],
        )
        requests += 1
        exercised += 1
        exercised_ids.append(f"reset:{case['id']}:out-of-order")
        if reset_status not in set(case["reset"]["expected_status"]):
            findings.append(
                _workflow_finding(
                    case["id"], "out-of-order", "state-reset", reset_status
                )
            )
        requests += _evaluate_postconditions(
            base_url,
            case,
            "after-reset-out-of-order",
            roles,
            findings,
            exercised_ids,
            oracle,
        )
        exercised = len(exercised_ids)

        out_of_order = case["out_of_order"]
        out_of_order_step = case["steps"][out_of_order["step_index"]]
        out_of_order_status = _request(
            base_url,
            out_of_order_step["path"],
            roles[out_of_order_step["role"]],
            method=out_of_order_step["method"],
            body_env=out_of_order_step["body_env"],
        )
        requests += 1
        exercised += 1
        exercised_ids.append(f"out-of-order:{case['id']}:{out_of_order_step['id']}")
        if out_of_order_status not in set(out_of_order["expected_status"]):
            findings.append(
                _workflow_finding(
                    case["id"],
                    out_of_order_step["id"],
                    "sequence-enforcement",
                    out_of_order_status,
                )
            )
        requests += _evaluate_postconditions(
            base_url,
            case,
            "after-out-of-order",
            roles,
            findings,
            exercised_ids,
            oracle,
        )
        exercised = len(exercised_ids)
        reset_status = _request(
            base_url,
            case["reset"]["path"],
            roles[case["reset"]["role"]],
            method=case["reset"]["method"],
            body_env=case["reset"]["body_env"],
        )
        requests += 1
        exercised += 1
        exercised_ids.append(f"reset:{case['id']}:sequence")
        if reset_status not in set(case["reset"]["expected_status"]):
            findings.append(
                _workflow_finding(case["id"], "sequence", "state-reset", reset_status)
            )
        requests += _evaluate_postconditions(
            base_url,
            case,
            "after-reset-sequence",
            roles,
            findings,
            exercised_ids,
            oracle,
        )
        exercised = len(exercised_ids)
        observed: list[int] = []
        for step in case["steps"]:
            status = _request(
                base_url,
                step["path"],
                roles[step["role"]],
                method=step["method"],
                body_env=step["body_env"],
            )
            requests += 1
            exercised += 1
            exercised_ids.append(f"state:{case['id']}:{step['id']}")
            observed.append(status)
            if status not in set(step["expected_status"]):
                findings.append(
                    _workflow_finding(
                        case["id"], step["id"], "state-transition", status
                    )
                )
        requests += _evaluate_postconditions(
            base_url,
            case,
            "after-sequence",
            roles,
            findings,
            exercised_ids,
            oracle,
        )
        exercised = len(exercised_ids)
        replay = case["replay"]
        replay_step = case["steps"][replay["step_index"]]
        replay_status = _request(
            base_url,
            replay_step["path"],
            roles[replay_step["role"]],
            method=replay_step["method"],
            body_env=replay_step["body_env"],
        )
        requests += 1
        exercised += 1
        exercised_ids.append(f"replay:{case['id']}:{replay_step['id']}")
        if replay_status not in set(replay["expected_status"]):
            findings.append(
                _workflow_finding(
                    case["id"], replay_step["id"], "replay-resistance", replay_status
                )
            )
        requests += _evaluate_postconditions(
            base_url,
            case,
            "after-replay",
            roles,
            findings,
            exercised_ids,
            oracle,
        )
        exercised = len(exercised_ids)
        reset_status = _request(
            base_url,
            case["reset"]["path"],
            roles[case["reset"]["role"]],
            method=case["reset"]["method"],
            body_env=case["reset"]["body_env"],
        )
        requests += 1
        exercised += 1
        exercised_ids.append(f"reset:{case['id']}:concurrency")
        if reset_status not in set(case["reset"]["expected_status"]):
            findings.append(
                _workflow_finding(
                    case["id"], "concurrency", "state-reset", reset_status
                )
            )
        requests += _evaluate_postconditions(
            base_url,
            case,
            "after-reset-concurrency",
            roles,
            findings,
            exercised_ids,
            oracle,
        )
        exercised = len(exercised_ids)
        concurrent = case["concurrency"]
        concurrent_step = case["steps"][concurrent["step_index"]]
        with ThreadPoolExecutor(max_workers=concurrent["attempts"]) as executor:
            statuses = list(
                executor.map(
                    lambda _, step=concurrent_step: _request(
                        base_url,
                        step["path"],
                        roles[step["role"]],
                        method=step["method"],
                        body_env=step["body_env"],
                    ),
                    range(concurrent["attempts"]),
                )
            )
        requests += len(statuses)
        exercised += len(statuses)
        exercised_ids.extend(
            f"concurrency:{case['id']}:{concurrent_step['id']}:{index}"
            for index in range(len(statuses))
        )
        successful = sum(status in concurrent["success_status"] for status in statuses)
        if successful > concurrent["maximum_successes"]:
            findings.append(
                _workflow_finding(
                    case["id"],
                    concurrent_step["id"],
                    "concurrency-limit",
                    successful,
                )
            )
        requests += _evaluate_postconditions(
            base_url,
            case,
            "after-concurrency",
            roles,
            findings,
            exercised_ids,
            oracle,
        )
        exercised = len(exercised_ids)

    if recovery_checks and oracle is None:
        raise ValueError("recovery checks require an independent state oracle")
    for check in recovery_checks:
        pending_receipt: dict[str, Any] | None = None
        postcondition = check["postcondition"]
        if oracle is None:
            raise ValueError("recovery checks require an independent state oracle")
        before_status, before_response = _request_observation(
            oracle["base_url"], postcondition["path"], oracle["role"]
        )
        requests += 1
        exercised_ids.append(f"recovery:{check['phase']}:{check['id']}:precondition")
        before_valid = before_status in set(postcondition["expected_status"])
        try:
            strict_loads(before_response)
        except (TypeError, ValueError):
            before_valid = False
        if not before_valid:
            findings.append(
                _workflow_finding(
                    check["id"], check["phase"], "recovery-precondition-oracle", 0
                )
            )
        trigger = check["trigger"]
        trigger_status, trigger_response = _request_observation(
            base_url,
            trigger["path"],
            roles[trigger["role"]],
            method=trigger["method"],
            body_env=trigger["body_env"],
        )
        requests += 1
        exercised_ids.append(f"recovery:{check['phase']}:{check['id']}:trigger")
        if trigger_status not in set(trigger["expected_status"]):
            findings.append(
                _workflow_finding(
                    check["id"], check["phase"], "recovery-trigger", trigger_status
                )
            )
        elif before_valid:
            pending_receipt = {
                "payload": trigger_response,
                "check": check,
                "precondition_response": before_response,
                "postcondition_response": b"",
            }
            pending_recovery_receipts.append(pending_receipt)
        if oracle is None:
            raise ValueError("recovery checks require an independent state oracle")
        observed_status, response = _request_observation(
            oracle["base_url"],
            postcondition["path"],
            oracle["role"],
        )
        requests += 1
        if pending_receipt is not None:
            pending_receipt["postcondition_response"] = response
        exercised_ids.append(f"recovery:{check['phase']}:{check['id']}:postcondition")
        if observed_status not in set(postcondition["expected_status"]):
            findings.append(
                _workflow_finding(
                    check["id"],
                    check["phase"],
                    "recovery-postcondition-status",
                    observed_status,
                )
            )
            continue
        try:
            body = strict_loads(response)
        except (TypeError, ValueError):
            findings.append(
                _workflow_finding(
                    check["id"], check["phase"], "recovery-postcondition-json", 0
                )
            )
            continue
        for assertion in postcondition["assertions"]:
            if not _assert_json(body, assertion):
                findings.append(
                    _workflow_finding(
                        check["id"],
                        check["phase"],
                        "recovery-postcondition-invariant",
                        0,
                    )
                )
                break

    exercised = len(exercised_ids)
    context = load_context(args.context, exercised_ids)
    recovery_receipts: list[dict[str, Any]] = []
    recovery_event_ids: set[str] = set()
    for pending in pending_recovery_receipts:
        payload = pending["payload"]
        check = pending["check"]
        try:
            receipt = _verify_recovery_receipt(
                payload,
                check_id=check["id"],
                phase=check["phase"],
                run_id=context["run_id"],
                deployment_sha256=context["deployment_sha256"],
                challenge_sha256=context["challenge_sha256"],
                contract_sha256=hashlib.sha256(contract_bytes).hexdigest(),
                request_sha256=hashlib.sha256(
                    canonical_bytes(check["trigger"])
                ).hexdigest(),
                oracle_identity_sha256=str((oracle or {}).get("identity_sha256") or ""),
                observed_at=context["trusted_time_observed_at"],
                precondition_response=pending["precondition_response"],
                postcondition_response=pending["postcondition_response"],
            )
            event_id = str(receipt["statement"]["event_id"])
            if event_id in recovery_event_ids:
                raise ValueError("authorization orchestration event was replayed")
            recovery_event_ids.add(event_id)
            recovery_receipts.append(receipt)
        except ValueError:
            findings.append(
                _workflow_finding(
                    check["id"], check["phase"], "orchestration-receipt", 0
                )
            )
    generated = datetime.now(UTC)
    environment = "loopback-multi-role-http-contract"
    producer_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    document = {
        "schema_version": "2.0",
        "kind": "authorization-security",
        "producer": "pysec-authorization-contract",
        "producer_version": "2",
        "producer_sha256": producer_sha256,
        "revision": _text(args.revision, "revision", 200),
        "generated_at": generated.isoformat(),
        "expires_at": (generated + timedelta(hours=args.valid_for_hours)).isoformat(),
        "run_id": _context_run_id(args.run_id, context["run_id"]),
        "artifact_sha256": "",
        "ruleset_sha256": hashlib.sha256(
            f"authorization-contract-v{version}".encode()
        ).hexdigest(),
        "config_sha256": hashlib.sha256(contract_bytes).hexdigest(),
        "environment": environment,
        "environment_sha256": hashlib.sha256(environment.encode()).hexdigest(),
        "context": {key: value for key, value in context.items() if key != "run_id"},
        "execution": {
            "status": "completed",
            "targets_discovered": exercised,
            "targets_exercised": exercised,
            "requests": requests,
            "coverage_percent": 100.0,
            "coverage_metric": "declared-role-resource-matrix",
            "roles": sorted(roles),
            "features": [
                "BOLA",
                "IDOR",
                "tenant-isolation",
                "unauthenticated-access",
                "state-transitions",
                "replay-resistance",
                "concurrency",
                "approval-limits",
                "sequence-enforcement",
                "idempotency",
                "atomicity",
                "business-logic-state-machine",
                "state-reset-isolation",
                *(
                    (
                        "durable-postconditions",
                        "response-body-invariants",
                        "independent-state-oracle",
                        "process-restart-postconditions",
                        "replica-failover-postconditions",
                        "signed-orchestration-events",
                    )
                    if oracle is not None
                    else ()
                ),
            ],
            "skipped_checks": (
                []
                if oracle is not None
                else [
                    "independent-state-oracle",
                    "durable-postconditions",
                    "process-restart-postconditions",
                    "replica-failover-postconditions",
                    "signed-orchestration-events",
                ]
            ),
            "canaries_expected": 1,
            "canaries_observed": int(_boundary_canary()),
            "recovery_receipts": recovery_receipts,
        },
        "findings": findings,
    }
    document["provenance"] = inline_provenance(
        native_receipt={"execution": document["execution"], "findings": findings},
        builder_id="pysec-authorization-contract",
        builder=Path(__file__),
        invocation=contract_bytes,
        materials=document["context"],
    )
    _write_json(args.output, document)
    return 0


def _loopback_url(value: str) -> str:
    target = urlsplit(value)
    if target.scheme not in {"http", "https"} or not target.hostname:
        raise ValueError("base_url must be absolute loopback HTTP(S)")
    if target.username or target.password or target.query or target.fragment:
        raise ValueError("base_url cannot contain credentials, query, or fragment")
    hostname = target.hostname.casefold()
    if hostname != "localhost":
        try:
            if not ipaddress.ip_address(hostname).is_loopback:
                raise ValueError("base_url must be loopback")
        except ValueError as exc:
            raise ValueError(
                "base_url must use localhost or an explicit loopback"
            ) from exc
    return value.rstrip("/") + "/"


def _oracle(
    value: object,
    application_url: str,
    roles: dict[str, dict[str, str]],
) -> dict[str, Any]:
    required = {"base_url", "authorization_env", "identity_sha256"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("independent state oracle fields do not match")
    base_url = _loopback_url(str(value["base_url"] or ""))
    application = urlsplit(application_url)
    observer = urlsplit(base_url)
    if (application.scheme, application.hostname, application.port) == (
        observer.scheme,
        observer.hostname,
        observer.port,
    ):
        raise ValueError("state oracle must use an independent network origin")
    authorization_env = str(value["authorization_env"] or "")
    if (
        not authorization_env
        or authorization_env.upper() != authorization_env
        or not authorization_env.replace("_", "").isalnum()
        or len(authorization_env) > 100
    ):
        raise ValueError("state oracle authorization environment is invalid")
    if authorization_env in {
        settings["authorization_env"]
        for settings in roles.values()
        if settings["authorization_env"]
    }:
        raise ValueError(
            "state oracle must use credentials distinct from application roles"
        )
    identity = str(value["identity_sha256"] or "")
    if len(identity) != 64 or any(
        character not in "0123456789abcdef" for character in identity
    ):
        raise ValueError("state oracle deployment identity is invalid")
    if (
        os.environ.get("PYSEC_AUTHORIZATION_ORACLE_IDENTITY_SHA256", "")
        .strip()
        .casefold()
        != identity
    ):
        raise ValueError("state oracle identity does not match its deployment pin")
    return {
        "base_url": base_url,
        "role": {"authorization_env": authorization_env},
        "identity_sha256": identity,
    }


def _roles(value: object) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict) or not 1 <= len(value) <= 32:
        raise TypeError("roles must contain between 1 and 32 entries")
    roles: dict[str, dict[str, str]] = {}
    for name, settings in value.items():
        role = _label(name, "role")
        if not isinstance(settings, dict) or set(settings) - {"authorization_env"}:
            raise TypeError("role settings may only contain authorization_env")
        environment = str(settings.get("authorization_env") or "")
        if environment and (
            len(environment) > 100
            or not environment.replace("_", "").isalnum()
            or environment.upper() != environment
        ):
            raise ValueError("authorization_env must be a bounded uppercase variable")
        roles[role] = {"authorization_env": environment}
    return roles


def _cases(value: object, roles: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 1000:
        raise TypeError("cases must contain between 1 and 1000 entries")
    result: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "path",
            "allow",
            "deny",
            "allowed_status",
            "denied_status",
        }:
            raise TypeError("authorization case fields do not match the contract")
        identifier = _label(item["id"], "case id")
        if identifier in identifiers:
            raise ValueError("authorization case IDs must be unique")
        path = str(item["path"])
        parsed = urlsplit(path)
        if (
            not path.startswith("/")
            or parsed.scheme
            or parsed.netloc
            or parsed.fragment
        ):
            raise ValueError(
                "authorization paths must be root-relative without fragments"
            )
        allow = _role_list(item["allow"], roles)
        deny = _role_list(item["deny"], roles)
        if not allow or not deny or set(allow) & set(deny):
            raise ValueError("each case needs disjoint allow and deny roles")
        allowed_status = _status_list(item["allowed_status"])
        denied_status = _status_list(item["denied_status"])
        identifiers.add(identifier)
        result.append(
            {
                "id": identifier,
                "path": path,
                "allow": allow,
                "deny": deny,
                "allowed_status": allowed_status,
                "denied_status": denied_status,
            }
        )
    return result


def _state_cases(
    value: object, roles: dict[str, dict[str, str]]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        raise TypeError("state_cases must contain between 1 and 100 entries")
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "steps",
            "replay",
            "concurrency",
            "out_of_order",
            "reset",
            "postconditions",
        }:
            raise TypeError("state case fields do not match the contract")
        steps_value = item["steps"]
        if not isinstance(steps_value, list) or not 2 <= len(steps_value) <= 50:
            raise TypeError("state case steps must contain between 2 and 50 entries")
        steps = [_state_step(step, roles) for step in steps_value]
        if len({step["id"] for step in steps}) != len(steps):
            raise ValueError("state step IDs must be unique within a case")
        if not any(step["control"] == "approval-limit" for step in steps):
            raise ValueError("every state case requires an approval-limit step")
        replay = _replay(item["replay"], len(steps))
        out_of_order = _replay(item["out_of_order"], len(steps))
        concurrency = _concurrency(item["concurrency"], len(steps))
        reset = _request_spec(item["reset"], roles, "state reset")
        postconditions = _postconditions(item["postconditions"], roles)
        result.append(
            {
                "id": _label(item["id"], "state case id"),
                "steps": steps,
                "replay": replay,
                "out_of_order": out_of_order,
                "concurrency": concurrency,
                "reset": reset,
                "postconditions": postconditions,
            }
        )
    return result


def _recovery_checks(
    value: object, roles: dict[str, dict[str, str]]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 2 <= len(value) <= 20:
        raise TypeError("recovery_checks must contain between 2 and 20 entries")
    result: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    phases: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "phase",
            "trigger",
            "postcondition",
        }:
            raise TypeError("recovery check fields do not match the contract")
        identifier = _label(item["id"], "recovery check id")
        phase = _label(item["phase"], "recovery check phase")
        if identifier in identifiers or phase not in {
            "process-restart",
            "replica-failover",
        }:
            raise ValueError("recovery check identity or phase is invalid")
        trigger = _request_spec(item["trigger"], roles, "recovery trigger")
        postcondition = _recovery_postcondition(item["postcondition"])
        identifiers.add(identifier)
        phases.add(phase)
        result.append(
            {
                "id": identifier,
                "phase": phase,
                "trigger": trigger,
                "postcondition": postcondition,
            }
        )
    if phases != {"process-restart", "replica-failover"}:
        raise ValueError("recovery_checks must exercise restart and replica failover")
    return result


def _recovery_postcondition(value: object) -> dict[str, Any]:
    required = {"path", "expected_status", "assertions"}
    if not isinstance(value, dict) or set(value) != required:
        raise TypeError("recovery postcondition fields do not match the contract")
    assertions = value["assertions"]
    if not isinstance(assertions, list) or not 1 <= len(assertions) <= 100:
        raise TypeError("recovery postcondition assertions must be bounded")
    return {
        "path": _relative_path(value["path"]),
        "expected_status": _status_list(value["expected_status"]),
        "assertions": [_json_assertion(assertion) for assertion in assertions],
    }


def _verify_recovery_receipt(
    payload: bytes,
    *,
    check_id: str,
    phase: str,
    run_id: str,
    deployment_sha256: str,
    challenge_sha256: str,
    contract_sha256: str,
    request_sha256: str,
    oracle_identity_sha256: str,
    observed_at: str,
    precondition_response: bytes,
    postcondition_response: bytes,
) -> dict[str, Any]:
    raw_key = os.environ.get("PYSEC_AUTHORIZATION_ORCHESTRATOR_KEY_PATH", "").strip()
    expected_key = (
        os.environ.get("PYSEC_AUTHORIZATION_ORCHESTRATOR_KEY_SHA256", "")
        .strip()
        .casefold()
    )
    if not raw_key or len(expected_key) != 64:
        raise ValueError("authorization orchestrator trust is unavailable")
    key_bytes = _regular_bytes(Path(raw_key))
    if hashlib.sha256(key_bytes).hexdigest() != expected_key:
        raise ValueError("authorization orchestrator key does not match its pin")
    key = serialization.load_pem_public_key(key_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("authorization orchestrator key must use Ed25519")
    value = strict_loads(payload)
    fields = {
        "schema_version",
        "check_id",
        "phase",
        "event_id",
        "before_instance_id",
        "after_instance_id",
        "orchestrator_identity_sha256",
        "run_id",
        "deployment_sha256",
        "challenge_sha256",
        "contract_sha256",
        "request_sha256",
        "oracle_identity_sha256",
        "issued_at",
        "expires_at",
        "before_state_sha256",
        "after_state_sha256",
        "postcondition_response_sha256",
        "signature_base64",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("authorization orchestration receipt fields do not match")
    signed = {name: value[name] for name in fields - {"signature_base64"}}
    if (
        value["schema_version"] != "1.0"
        or value["check_id"] != check_id
        or value["phase"] != phase
        or value["orchestrator_identity_sha256"] != expected_key
        or value["run_id"] != run_id
        or value["deployment_sha256"] != deployment_sha256
        or value["challenge_sha256"] != challenge_sha256
        or value["contract_sha256"] != contract_sha256
        or value["request_sha256"] != request_sha256
        or value["oracle_identity_sha256"] != oracle_identity_sha256
        or value["postcondition_response_sha256"]
        != hashlib.sha256(postcondition_response).hexdigest()
        or not _label(value["event_id"], "orchestration event")
        or not _label(value["before_instance_id"], "before instance")
        or not _label(value["after_instance_id"], "after instance")
        or value["before_instance_id"] == value["after_instance_id"]
    ):
        raise ValueError("authorization orchestration receipt policy failed")
    try:
        precondition_state = strict_loads(precondition_response)
        postcondition_state = strict_loads(postcondition_response)
    except (TypeError, ValueError) as exc:
        raise ValueError("authorization postcondition response is invalid") from exc
    if (
        value["before_state_sha256"]
        != hashlib.sha256(canonical_bytes(precondition_state)).hexdigest()
        or value["after_state_sha256"]
        != hashlib.sha256(canonical_bytes(postcondition_state)).hexdigest()
    ):
        raise ValueError("authorization recovery receipt does not bind oracle state")
    try:
        issued = datetime.fromisoformat(str(value["issued_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(
            str(value["expires_at"]).replace("Z", "+00:00")
        )
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("authorization orchestration receipt time is invalid") from exc
    if (
        issued.tzinfo is None
        or expires.tzinfo is None
        or observed.tzinfo is None
        or issued > observed
        or expires <= issued
        or expires - issued > timedelta(hours=24)
        or observed > expires
    ):
        raise ValueError("authorization orchestration receipt is outside its window")
    try:
        signature = base64.b64decode(str(value["signature_base64"]), validate=True)
        key.verify(signature, canonical_bytes(signed))
    except Exception as exc:
        raise ValueError(
            "authorization orchestration receipt signature failed"
        ) from exc
    return {
        "statement": signed,
        "signature_base64": value["signature_base64"],
        "public_key_pem_base64": base64.b64encode(key_bytes).decode("ascii"),
        "receipt_payload_base64": base64.b64encode(payload).decode("ascii"),
        "receipt_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _digest_label(value: object) -> bool:
    digest = str(value or "")
    return len(digest) == 64 and all(
        character in "0123456789abcdef" for character in digest
    )


def _state_step(value: object, roles: dict[str, dict[str, str]]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "id",
        "path",
        "role",
        "method",
        "body_env",
        "expected_status",
        "control",
    }:
        raise TypeError("state step fields do not match the contract")
    role = _label(value["role"], "state step role")
    if role not in roles:
        raise ValueError("state step references an unknown role")
    path = _relative_path(value["path"])
    method = str(value["method"]).upper()
    if method not in {"DELETE", "GET", "PATCH", "POST", "PUT"}:
        raise ValueError("state step HTTP method is unsupported")
    body_env = str(value["body_env"] or "")
    if body_env and (
        len(body_env) > 100
        or body_env.upper() != body_env
        or not body_env.replace("_", "").isalnum()
    ):
        raise ValueError("state step body_env must be an uppercase variable")
    control = _label(value["control"], "state step control")
    if control not in {"approval-limit", "state-transition"}:
        raise ValueError("state step control is unsupported")
    return {
        "id": _label(value["id"], "state step id"),
        "path": path,
        "role": role,
        "method": method,
        "body_env": body_env,
        "expected_status": _status_list(value["expected_status"]),
        "control": control,
    }


def _replay(value: object, step_count: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"step_index", "expected_status"}:
        raise TypeError("state replay fields do not match the contract")
    index = int(value["step_index"])
    if index < 0 or index >= step_count:
        raise ValueError("state replay step_index is invalid")
    return {
        "step_index": index,
        "expected_status": _status_list(value["expected_status"]),
    }


def _concurrency(value: object, step_count: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "step_index",
        "attempts",
        "maximum_successes",
        "success_status",
    }:
        raise TypeError("state concurrency fields do not match the contract")
    index = int(value["step_index"])
    attempts = int(value["attempts"])
    maximum = int(value["maximum_successes"])
    if index < 0 or index >= step_count or not 2 <= attempts <= 16:
        raise ValueError("state concurrency bounds are invalid")
    if maximum < 0 or maximum > attempts:
        raise ValueError("state concurrency maximum_successes is invalid")
    return {
        "step_index": index,
        "attempts": attempts,
        "maximum_successes": maximum,
        "success_status": _status_list(value["success_status"]),
    }


def _request_spec(
    value: object, roles: dict[str, dict[str, str]], label: str
) -> dict[str, Any]:
    required = {"path", "role", "method", "body_env", "expected_status"}
    if not isinstance(value, dict) or set(value) != required:
        raise TypeError(f"{label} fields do not match the contract")
    role = _label(value["role"], f"{label} role")
    if role not in roles:
        raise ValueError(f"{label} references an unknown role")
    method = str(value["method"]).upper()
    if method not in {"DELETE", "GET", "PATCH", "POST", "PUT"}:
        raise ValueError(f"{label} HTTP method is unsupported")
    body_env = str(value["body_env"] or "")
    if body_env and (
        len(body_env) > 100
        or body_env.upper() != body_env
        or not body_env.replace("_", "").isalnum()
    ):
        raise ValueError(f"{label} body_env must be an uppercase variable")
    return {
        "path": _relative_path(value["path"]),
        "role": role,
        "method": method,
        "body_env": body_env,
        "expected_status": _status_list(value["expected_status"]),
    }


def _postconditions(
    value: object, roles: dict[str, dict[str, str]]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 50:
        raise TypeError("state postconditions must be a bounded non-empty list")
    result: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for item in value:
        required = {
            "id",
            "phase",
            "path",
            "role",
            "expected_status",
            "assertions",
        }
        if not isinstance(item, dict) or set(item) != required:
            raise TypeError("state postcondition fields do not match the contract")
        identifier = _label(item["id"], "postcondition id")
        phase = _label(item["phase"], "postcondition phase")
        role = _label(item["role"], "postcondition role")
        assertions = item["assertions"]
        if phase not in _POSTCONDITION_PHASES:
            raise ValueError("state postcondition phase is invalid")
        compound_id = f"{phase}:{identifier}"
        if compound_id in identifiers or role not in roles:
            raise ValueError("state postcondition identity or role is invalid")
        if not isinstance(assertions, list) or not 1 <= len(assertions) <= 100:
            raise TypeError("state postcondition assertions must be bounded")
        normalized = [_json_assertion(assertion) for assertion in assertions]
        identifiers.add(compound_id)
        result.append(
            {
                "id": identifier,
                "phase": phase,
                "path": _relative_path(item["path"]),
                "role": role,
                "expected_status": _status_list(item["expected_status"]),
                "assertions": normalized,
            }
        )
    observed_phases = {item["phase"] for item in result}
    if observed_phases != _POSTCONDITION_PHASES:
        raise ValueError(
            "state postconditions must cover every reset, sequence, replay, and concurrency phase"
        )
    return result


_POSTCONDITION_PHASES = {
    "after-reset-out-of-order",
    "after-out-of-order",
    "after-reset-sequence",
    "after-sequence",
    "after-replay",
    "after-reset-concurrency",
    "after-concurrency",
}


def _evaluate_postconditions(
    base_url: str,
    case: dict[str, Any],
    phase: str,
    roles: dict[str, dict[str, str]],
    findings: list[dict[str, Any]],
    exercised_ids: list[str],
    oracle: dict[str, Any] | None,
) -> int:
    evaluated = 0
    for postcondition in case["postconditions"]:
        if postcondition["phase"] != phase:
            continue
        status, body = _request_observation(
            str(oracle["base_url"]) if oracle is not None else base_url,
            postcondition["path"],
            oracle["role"] if oracle is not None else roles[postcondition["role"]],
        )
        evaluated += 1
        exercised_ids.append(
            f"postcondition:{case['id']}:{phase}:{postcondition['id']}"
        )
        satisfied = status in set(postcondition["expected_status"])
        try:
            if len(body) > _MAX_CONTRACT_BYTES:
                raise ValueError("postcondition response exceeds its byte limit")
            document_body = strict_loads(body)
            satisfied = satisfied and all(
                _assert_json(document_body, assertion)
                for assertion in postcondition["assertions"]
            )
        except (TypeError, ValueError):
            satisfied = False
        if not satisfied:
            findings.append(
                _workflow_finding(
                    case["id"],
                    postcondition["id"],
                    f"durable-postcondition:{phase}",
                    status,
                )
            )
    return evaluated


def _json_assertion(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"pointer", "operator", "value"}:
        raise TypeError("JSON assertion fields do not match the contract")
    pointer = str(value["pointer"])
    operator = str(value["operator"])
    if not pointer.startswith("/") or len(pointer) > 500:
        raise ValueError("JSON assertion pointer is invalid")
    if operator not in {"equals", "not-equals", "gte", "lte"}:
        raise ValueError("JSON assertion operator is unsupported")
    expected = value["value"]
    if isinstance(expected, (dict, list)):
        raise TypeError("JSON assertion values must be scalar")
    return {"pointer": pointer, "operator": operator, "value": expected}


def _role_list(value: object, roles: dict[str, dict[str, str]]) -> list[str]:
    if not isinstance(value, list) or len(value) > len(roles):
        raise TypeError("case roles must be a bounded list")
    normalized = [_label(item, "case role") for item in value]
    if len(set(normalized)) != len(normalized) or not set(normalized) <= set(roles):
        raise ValueError("case roles must be unique declared roles")
    return normalized


def _status_list(value: object) -> list[int]:
    if not isinstance(value, list) or not 1 <= len(value) <= 10:
        raise TypeError("status expectations must be a non-empty bounded list")
    statuses = [int(item) for item in value]
    if any(status < 100 or status > 599 for status in statuses):
        raise ValueError("HTTP status expectations must be between 100 and 599")
    return statuses


def _request(
    base_url: str,
    path: str,
    role: dict[str, str],
    *,
    method: str = "GET",
    body_env: str = "",
) -> int:
    return _request_observation(base_url, path, role, method=method, body_env=body_env)[
        0
    ]


def _request_observation(
    base_url: str,
    path: str,
    role: dict[str, str],
    *,
    method: str = "GET",
    body_env: str = "",
) -> tuple[int, bytes]:
    target = urljoin(base_url, path.lstrip("/"))
    _loopback_url(target.split("?", 1)[0])
    headers = {"User-Agent": "py-security-suite-authorization-contract/1"}
    environment_name = role["authorization_env"]
    if environment_name:
        token = os.environ.get(environment_name)
        if not token:
            raise ValueError(
                f"required authorization environment is absent: {environment_name}"
            )
        headers["Authorization"] = f"Bearer {token}"
    # The absolute base and joined target are restricted to explicit loopback
    # HTTP(S) above; redirects are disabled by the dedicated opener below.
    data: bytes | None = None
    if body_env:
        body = os.environ.get(body_env)
        if body is None:
            raise ValueError(f"required request-body environment is absent: {body_env}")
        if len(body.encode()) > 64 * 1024:
            raise ValueError("state request body exceeds 64 KiB")
        data = body.encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(  # noqa: S310
        target, headers=headers, method=method, data=data
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=10) as response:
            return int(response.status), response.read(_MAX_CONTRACT_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(_MAX_CONTRACT_BYTES + 1)


def _assert_json(document: object, assertion: dict[str, Any]) -> bool:
    current = document
    for raw in assertion["pointer"].split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif (
            isinstance(current, list) and token.isdigit() and int(token) < len(current)
        ):
            current = current[int(token)]
        else:
            return False
    expected = assertion["value"]
    operator = assertion["operator"]
    if operator == "equals":
        return current == expected
    if operator == "not-equals":
        return current != expected
    if (
        isinstance(current, bool)
        or isinstance(expected, bool)
        or not isinstance(current, (int, float))
        or not isinstance(expected, (int, float))
    ):
        return False
    return current >= expected if operator == "gte" else current <= expected


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _finding(
    case_id: str, role: str, expectation: str, observed_status: int
) -> dict[str, Any]:
    denied = expectation == "deny"
    return {
        "rule_id": "authorization-denial-failed"
        if denied
        else "authorized-access-failed",
        "title": (
            "A denied role accessed a protected resource"
            if denied
            else "An allowed role could not access its declared resource"
        ),
        "message": "Observed HTTP status did not satisfy the declared role contract.",
        "path": "<runtime-authorization-contract>",
        "severity": "high" if denied else "medium",
        "classification": "CWE-639" if denied else "CWE-285",
        "remediation": "Enforce the declared authorization decision server-side and add a regression contract.",
        "area": "multi-role-authorization-security-testing",
        "domain": "security",
        "evidence": {
            "case_id": case_id,
            "role": role,
            "expectation": expectation,
            "observed_status": observed_status,
        },
    }


def _workflow_finding(
    case_id: str, step_id: str, control: str, observed: int
) -> dict[str, Any]:
    return {
        "rule_id": f"authorization-{control}-failed",
        "title": f"Authorization {control} contract failed",
        "message": "Observed behavior did not satisfy the declared business-logic security contract.",
        "path": "<runtime-authorization-contract>",
        "severity": "high",
        "classification": "CWE-841",
        "remediation": "Enforce the declared state, replay, concurrency, and approval invariant atomically and retain a regression contract.",
        "area": "multi-role-authorization-security-testing",
        "domain": "security",
        "evidence": {
            "case_id": case_id,
            "step_id": step_id,
            "control": control,
            "observed": observed,
        },
    }


def _relative_path(value: object) -> str:
    path = str(value)
    parsed = urlsplit(path)
    if not path.startswith("/") or parsed.scheme or parsed.netloc or parsed.fragment:
        raise ValueError("authorization paths must be root-relative without fragments")
    return path


def _boundary_canary() -> bool:
    try:
        _loopback_url("https://example.invalid/")
    except ValueError:
        return True
    return False


def _regular_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("contract is not a regular file")
    if path.stat().st_size > _MAX_CONTRACT_BYTES:
        raise ValueError("contract exceeds 1 MiB")
    return path.read_bytes()


def _label(value: object, name: str) -> str:
    result = _text(value, name, 100)
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


def _write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError(f"output is not a replaceable regular file: {path}")
    payload = (strict_dumps(document, indent=2) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
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
