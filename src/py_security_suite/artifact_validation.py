from __future__ import annotations

from importlib.resources import files
import hashlib
import base64
import os
import sqlite3
from collections import Counter
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any
from collections.abc import Callable

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .strict_json import loads as strict_loads
from .strict_json import canonical_bytes
from .deployment_receipt import verify_portable_receipt
from .operation_receipt import verify_operation_receipt
from .checkpoint_authority import publish_checkpoint, verify_retained_checkpoint
from .failure_domain import require_independent_failure_domains, verify_failure_domain


_ARTIFACT_SCHEMAS = {
    "admission-decisions.json": "admission-decisions.schema.json",
    "advanced-analysis.json": "advanced-analysis.schema.json",
    "application-contract-analysis.json": "application-contract-analysis-1.3.schema.json",
    "architecture-history.json": "architecture-history-1.0.schema.json",
    "artifact-manifest.json": "artifact-manifest.schema.json",
    "artifact-sbom.cdx.json": "cyclonedx-artifact.schema.json",
    "assurance-claims.json": "assurance-claims-1.1.schema.json",
    "boundary-graph.json": "boundary-graph-1.0.schema.json",
    "capability-manifest.json": "capability-manifest-1.0.schema.json",
    "closure-plan.json": "closure-plan.schema.json",
    "code-health.json": "code-health-1.4.schema.json",
    "data-exposure.json": "data-exposure-1.5.schema.json",
    "dependency-surface.json": "dependency-surface-1.1.schema.json",
    "domain-assurance.json": "domain-assurance-1.0.schema.json",
    "deptry-dependencies.json": "deptry-artifact.schema.json",
    "diff-coverage.json": "diff-coverage-artifact.schema.json",
    "effectiveness.json": "effectiveness-1.1.schema.json",
    "evidence-fusion.json": "evidence-fusion.schema.json",
    "graph-analysis.json": "graph-analysis.schema.json",
    "graphify.json": "graphify-evidence.schema.json",
    "git-sizer.json": "git-sizer-artifact.schema.json",
    "hypothesis-summary.json": "test-summary-artifact.schema.json",
    "intelligence-approval.json": "intelligence-approval.schema.json",
    "isolation-attestation.json": "isolation-attestation.schema.json",
    "isolation-boundary.json": "isolation-boundary-1.0.schema.json",
    "isolation-probe.json": "isolation-probe-1.0.schema.json",
    "osv-manifest-receipts.json": "osv-manifest-receipts-1.0.schema.json",
    "finding-delta.json": "finding-delta-1.1.schema.json",
    "finding-validation.json": "finding-validation-1.0.schema.json",
    "framework-model-coverage.json": "framework-model-coverage-1.0.schema.json",
    "checkov-iac.json": "checkov-artifact.schema.json",
    "coverage-summary.json": "coverage-artifact.schema.json",
    "junit-summary.json": "test-summary-artifact.schema.json",
    "kics-iac.json": "kics-artifact.schema.json",
    "llm-adversarial-plan.json": "llm-adversarial-plan-1.0.schema.json",
    "pipdeptree-summary.json": "pipdeptree-artifact.schema.json",
    "pylint-summary.json": "pylint-artifact.schema.json",
    "radon-complexity.json": "radon-artifact.schema.json",
    "reachability.json": "reachability-artifact.schema.json",
    "reuse-compliance.json": "reuse-artifact.schema.json",
    "risk-intelligence.json": "risk-intelligence-1.0.schema.json",
    "sbom.cdx.json": "cyclonedx-artifact.schema.json",
    "scancode-inventory.json": "scancode-artifact.schema.json",
    "scanner-trust.json": "scanner-trust-1.0.schema.json",
    "schemathesis-summary.json": "test-summary-artifact.schema.json",
    "portfolio-health.json": "portfolio-health-1.1.schema.json",
    "report-security.json": "report-security-1.0.schema.json",
    "resource-limits.json": "resource-limits-1.0.schema.json",
    "risk-paths.json": "risk-paths.schema.json",
    "runtime-closure.json": "runtime-closure-1.0.schema.json",
    "runtime-surface-binding.json": "runtime-surface-binding-1.0.schema.json",
    "runtime-trace-correlation.json": "runtime-trace-correlation-1.0.schema.json",
    "semantic-language-coverage.json": "semantic-language-coverage-1.0.schema.json",
    "security-requirements-coverage.json": "security-requirements-coverage-1.0.schema.json",
    "source-inventory.json": "source-inventory.schema.json",
    "static-architecture.json": "static-architecture-1.4.schema.json",
    "structural-synthesis.json": "structural-synthesis-1.2.schema.json",
    "trust-policy-attestation.json": "trust-policy-attestation-1.0.schema.json",
    "trust-policy.json": "trust-policy-1.0.schema.json",
}

_TYPED_VALIDATORS: dict[str, Callable[[object], None]] = {}
_OPERATION_STATE_GENESIS_SHA256 = hashlib.sha256(
    b"pysec-operation-receipt-state-genesis-v1"
).hexdigest()


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _typed_validator(
    name: str,
) -> Callable[[Callable[[object], None]], Callable[[object], None]]:
    def register(function: Callable[[object], None]) -> Callable[[object], None]:
        if name in _TYPED_VALIDATORS:
            raise RuntimeError(f"duplicate artifact validator registration: {name}")
        _TYPED_VALIDATORS[name] = function
        return function

    return register


def validate_governed_artifacts(artifacts: dict[str, Any] | None) -> dict[str, str]:
    """Validate every artifact with a bundled governed contract before sealing."""
    validated: dict[str, str] = {}
    for name, value in sorted((artifacts or {}).items()):
        schema_name = _ARTIFACT_SCHEMAS.get(name)
        if schema_name is None and _is_companion_assurance(value):
            schema_name = "companion-assurance-2.0.schema.json"
        if schema_name is None:
            raise ValueError(
                f"derived artifact {name} has no registered publication schema"
            )
        raw = files("py_security_suite").joinpath("schemas", schema_name).read_bytes()
        schema = strict_loads(raw)
        if not isinstance(schema, dict):
            raise TypeError(f"artifact schema root is invalid: {schema_name}")
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
                value
            ),
            key=lambda item: tuple(str(part) for part in item.absolute_path),
        )
        if errors:
            location = "/".join(str(part) for part in errors[0].absolute_path) or "/"
            raise ValueError(
                f"derived artifact {name} violates {schema_name} at {location}: "
                f"{errors[0].message}"
            )
        validator = _TYPED_VALIDATORS.get(name)
        companion = _is_companion_assurance(value)
        if validator is None and not companion and _contains_operation_receipt(value):
            raise ValueError(
                f"derived artifact {name} contains an operation receipt but has no "
                "registered semantic validator"
            )
        if validator is not None:
            validator(value)
        if companion:
            _validate_companion_recovery_receipts(value)
        validated[name] = schema_name
    receipts = _validate_operation_receipt_graph(artifacts or {})
    _consume_operation_receipts(receipts, artifacts or {})
    return validated


@_typed_validator("domain-assurance.json")
def _validate_domain_assurance_accounting(value: object) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("domains"), list):
        raise TypeError("domain assurance artifact is invalid")
    domains = value["domains"]
    names = [item.get("name") for item in domains]
    counts = Counter(str(item.get("status")) for item in domains)
    applicable = [item for item in domains if item.get("applicable") is True]
    covered = [item for item in applicable if item.get("status") == "covered"]
    score = round(100 * len(covered) / len(applicable)) if applicable else 100
    if (
        len(names) != len(set(names))
        or value.get("domains_detected") != len(domains)
        or value.get("applicable_domains") != len(applicable)
        or value.get("covered_domains") != len(covered)
        or value.get("status_counts") != dict(sorted(counts.items()))
        or value.get("coverage_score") != score
        or value.get("coverage_complete")
        is not all(
            item.get("status") in {"covered", "not-applicable"} for item in domains
        )
        or value.get("complete")
        is not (not value.get("parse_errors") and value.get("truncated") is not True)
        or (value.get("policy_path") is not None)
        is not (value.get("policy_present") is True)
    ):
        raise ValueError("domain assurance summary accounting does not match")
    for domain in domains:
        requirements = domain.get("requirements")
        gaps = domain.get("gaps")
        if not isinstance(requirements, list) or not isinstance(gaps, list):
            raise TypeError("domain assurance domain accounting is invalid")
        expected_status = (
            "not-applicable"
            if domain.get("applicable") is not True
            else "unmodeled"
            if domain.get("policy_present") is not True
            else "partial"
            if gaps
            else "covered"
        )
        satisfied = sum(item.get("status") == "satisfied" for item in requirements)
        if (
            domain.get("status") != expected_status
            or domain.get("requirements_detected") != len(requirements)
            or domain.get("requirements_satisfied") != satisfied
            or any(
                item.get("status") != ("satisfied" if not item.get("gaps") else "gap")
                for item in requirements
            )
        ):
            raise ValueError("domain assurance detail accounting does not match")


@_typed_validator("llm-adversarial-plan.json")
def _validate_llm_adversarial_accounting(value: object) -> None:
    if not isinstance(value, dict):
        raise TypeError("LLM adversarial plan must be an object")
    context = value.get("context")
    campaigns = value.get("campaigns")
    execution = value.get("execution_plan")
    counts = value.get("campaign_status_counts")
    evidence = value.get("evidence")
    if (
        not isinstance(context, list)
        or not isinstance(campaigns, list)
        or not isinstance(execution, dict)
        or not isinstance(execution.get("tasks"), list)
        or not isinstance(counts, dict)
        or not isinstance(evidence, dict)
    ):
        raise TypeError("LLM adversarial plan accounting fields are invalid")
    context_ids = [item.get("id") for item in context]
    campaign_ids = [item.get("id") for item in campaigns]
    tasks = execution["tasks"]
    status_counter = Counter(str(item.get("evidence_status")) for item in campaigns)
    expected_counts = {
        status: status_counter.get(status, 0)
        for status in (
            "not-run",
            "inconclusive",
            "exercised-no-confirmed-defect",
            "confirmed-defect",
        )
    }
    references = {
        reference
        for campaign in campaigns
        for reference in campaign.get("context_ids", [])
    }
    task_campaigns = [task.get("campaign_id") for task in tasks]
    if (
        len(context_ids) != len(set(context_ids))
        or len(campaign_ids) != len(set(campaign_ids))
        or not references.issubset(set(context_ids))
        or value.get("campaigns_retained") != len(campaigns)
        or value.get("campaigns_omitted")
        != value.get("campaigns_detected", 0) - len(campaigns)
        or value.get("context_entries_retained") != len(context)
        or value.get("context_bytes")
        != sum(int(item.get("size_bytes", 0)) for item in context)
        or counts != expected_counts
        or execution.get("tasks_detected") != len(tasks)
        or len(task_campaigns) != len(set(task_campaigns))
        or (tasks and set(task_campaigns) != set(campaign_ids))
        or evidence.get("confirmed_defects") != expected_counts["confirmed-defect"]
    ):
        raise ValueError("LLM adversarial plan accounting does not match")


@_typed_validator("runtime-trace-correlation.json")
def _validate_runtime_trace_accounting(value: object) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("traces"), list):
        raise TypeError("runtime trace artifact is invalid")
    traces = value["traces"]
    allow = sum(item.get("authorization_decision") == "allow" for item in traces)
    deny = sum(item.get("authorization_decision") == "deny" for item in traces)
    complete = value.get("complete") is True
    identities = [item.get("trace_id") for item in traces]
    if (
        value.get("trace_count") != len(traces)
        or value.get("allow_count") != allow
        or value.get("deny_count") != deny
        or len(identities) != len(set(identities))
        or any(
            (item.get("authorization_decision") == "allow")
            is not (item.get("sink_observed") is True)
            for item in traces
        )
    ):
        raise ValueError("runtime trace accounting does not match")
    evidence_fields = (
        value.get("evidence_sha256"),
        value.get("deployment_sha256"),
        value.get("boundary_graph_sha256"),
        value.get("authority_receipt"),
        value.get("coverage_policy"),
        value.get("coverage_policy_authority_receipt"),
        value.get("evidence"),
    )
    if complete is not bool(traces and all(evidence_fields)):
        raise ValueError("runtime trace completeness does not match its evidence")
    if complete == bool(value.get("limitations")):
        raise ValueError("runtime trace limitations are inconsistent")
    if complete:
        evidence = value["evidence"]
        if (
            not isinstance(evidence, dict)
            or evidence.get("deployment_sha256") != value.get("deployment_sha256")
            or evidence.get("boundary_graph_sha256")
            != value.get("boundary_graph_sha256")
            or evidence.get("coverage_requirements")
            != value.get("coverage_requirements")
            or not isinstance(value.get("coverage_policy"), dict)
            or value["coverage_policy"].get("requirements")
            != value.get("coverage_requirements")
            or not isinstance(evidence.get("traces"), list)
            or any(not isinstance(item, dict) for item in evidence.get("traces", []))
            or sorted(
                evidence.get("traces") or [], key=lambda item: str(item.get("trace_id"))
            )
            != traces
        ):
            raise ValueError("runtime trace artifact is not bound to signed evidence")
        if (
            value.get("coverage_required")
            != len(value.get("coverage_requirements") or [])
            or value.get("coverage_observed") != value.get("coverage_required")
            or value.get("coverage_percent") != 100.0
        ):
            raise ValueError("runtime trace coverage accounting does not match")
        _reverify_portable(
            evidence,
            value["authority_receipt"],
            "runtime-trace-evidence",
        )
        _reverify_portable(
            value["coverage_policy"],
            value["coverage_policy_authority_receipt"],
            "runtime-coverage-policy",
        )
        observed_at = _portable_verified_at(value["authority_receipt"])
        collector_subject = {
            "schema_version": "1.0",
            "deployment_sha256": evidence["deployment_sha256"],
            "boundary_graph_sha256": evidence["boundary_graph_sha256"],
            "collector_identity_sha256": evidence["collector_identity_sha256"],
            "failure_domain": evidence["collector_failure_domain"],
            "metrics": evidence["collector_metrics"],
            "traces_sha256": hashlib.sha256(
                canonical_bytes(evidence["traces"])
            ).hexdigest(),
        }
        _reverify_operation(
            collector_subject,
            evidence["collector_operation_receipt"],
            "runtime-collector-accounting",
            observed_at,
            str(evidence["collector_authority_key_sha256"]),
        )
        for name in ("collector_config", "instrumentation_manifest", "raw_spans"):
            if (
                evidence.get(f"{name}_sha256")
                != hashlib.sha256(canonical_bytes(evidence.get(name))).hexdigest()
            ):
                raise ValueError(f"runtime {name} replay artifact is detached")
        independent_subject = {
            "schema_version": "1.0",
            "deployment_sha256": evidence["deployment_sha256"],
            "boundary_graph_sha256": evidence["boundary_graph_sha256"],
            "observer_identity_sha256": evidence[
                "independent_observer_identity_sha256"
            ],
            "instrumented_build_sha256": evidence["instrumented_build_sha256"],
            "observations_sha256": hashlib.sha256(
                canonical_bytes(evidence["independent_observations"])
            ).hexdigest(),
            "raw_spans_sha256": evidence["independent_raw_spans_sha256"],
            "observer_config_sha256": evidence["independent_observer_config_sha256"],
            "failure_domain": evidence["independent_failure_domain"],
        }
        _reverify_operation(
            independent_subject,
            evidence["independent_operation_receipt"],
            "runtime-independent-observation",
            observed_at,
            str(evidence["independent_authority_key_sha256"]),
        )
        from .runtime_trace import (
            _runtime_source_artifact_valid,
            _verify_independent_observer_config,
            _verify_raw_spans,
        )
        from .failure_domain import require_independent_failure_domains

        require_independent_failure_domains(
            evidence["collector_failure_domain"],
            evidence["independent_failure_domain"],
            labels=("runtime collector", "runtime observer"),
        )

        _verify_raw_spans(evidence["raw_spans"], evidence["traces"])
        _verify_raw_spans(evidence["independent_raw_spans"], evidence["traces"])
        if (
            evidence["independent_raw_spans_sha256"]
            != hashlib.sha256(
                canonical_bytes(evidence["independent_raw_spans"])
            ).hexdigest()
        ):
            raise ValueError("independent runtime span replay artifact is detached")
        if (
            evidence["independent_observer_config_sha256"]
            != hashlib.sha256(
                canonical_bytes(evidence["independent_observer_config"])
            ).hexdigest()
        ):
            raise ValueError("independent runtime observer config is detached")
        _verify_independent_observer_config(
            evidence["independent_observer_config"],
            evidence["independent_raw_spans"],
            evidence["collector_identity_sha256"],
        )
        if {canonical_bytes(item) for item in evidence["independent_raw_spans"]} != {
            canonical_bytes(item) for item in evidence["raw_spans"]
        }:
            raise ValueError("independent runtime telemetry disagrees with collector")

        for inventory in value["coverage_policy"]["source_inventories"]:
            if (
                inventory["artifact_sha256"]
                != hashlib.sha256(
                    canonical_bytes(inventory["source_artifact"])
                ).hexdigest()
            ):
                raise ValueError("runtime source inventory artifact is detached")
            if not _runtime_source_artifact_valid(
                str(inventory["kind"]),
                inventory["source_artifact"],
                inventory["requirements"],
            ):
                raise ValueError("runtime source inventory cannot be reproduced")
            subject = {
                name: item
                for name, item in inventory.items()
                if name != "operation_receipt"
            }
            _reverify_operation(
                subject,
                inventory["operation_receipt"],
                f"runtime-route-inventory:{inventory['kind']}",
                _portable_verified_at(value["coverage_policy_authority_receipt"]),
                str(inventory["authority_key_sha256"]),
            )


@_typed_validator("isolation-probe.json")
def _validate_isolation_receipt(value: object) -> None:
    if not isinstance(value, dict):
        raise TypeError("isolation probe must be an object")
    observations = value.get("policy_observations")
    if not isinstance(observations, dict):
        return
    attestation = observations.get("effective_policy_attestation")
    receipt = observations.get("effective_policy_authority_receipt")
    if bool(attestation) != bool(receipt):
        raise ValueError("effective sandbox portable receipt is incomplete")
    if attestation:
        _reverify_portable(attestation, receipt, "effective-sandbox-policy")


def _reverify_portable(subject: object, receipt: object, purpose: str) -> None:
    if not isinstance(receipt, dict) or not isinstance(receipt.get("statement"), dict):
        raise ValueError("portable authority receipt is absent")
    statement = receipt["statement"]
    try:
        observed = datetime.fromisoformat(
            str(receipt["verified_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("portable authority receipt time is invalid") from exc
    verify_portable_receipt(
        subject,
        receipt,
        purpose=purpose,
        observed_at=observed,
        challenge_sha256=str(statement.get("challenge_sha256") or ""),
    )


def _portable_verified_at(receipt: object) -> datetime:
    if not isinstance(receipt, dict):
        raise ValueError("portable receipt is absent")
    try:
        value = datetime.fromisoformat(
            str(receipt["verified_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("portable receipt verification time is invalid") from exc
    if value.tzinfo is None:
        raise ValueError("portable receipt verification time lacks timezone")
    return value


def _reverify_operation(
    subject: object,
    receipt: object,
    purpose: str,
    observed_at: datetime,
    expected_key_sha256: str,
) -> None:
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    challenge = str((statement or {}).get("challenge_sha256") or "")
    verify_operation_receipt(
        subject,
        receipt,
        purpose=purpose,
        observed_at=observed_at,
        challenge_sha256=challenge,
        expected_key_sha256=expected_key_sha256,
    )


def _validate_operation_receipt_graph(
    artifacts: dict[str, Any],
) -> list[dict[str, Any]]:
    """Reject conflicting, replayed, or forked operation identities report-wide."""
    receipt_fields = {
        "schema_version",
        "statement",
        "signature_base64",
        "public_key_pem_base64",
    }
    statement_fields = {
        "schema_version",
        "purpose",
        "subject_sha256",
        "operation_id",
        "previous_operation_sha256",
        "challenge_sha256",
        "trusted_time_sha256",
        "issued_at",
        "expires_at",
        "signer_key_sha256",
    }
    receipts: list[dict[str, Any]] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            statement = value.get("statement")
            if set(value) == receipt_fields and isinstance(statement, dict):
                if set(statement) == statement_fields:
                    receipts.append(value)
                    return
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(artifacts)
    identities: dict[tuple[str, str], bytes] = {}
    chains: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for receipt in receipts:
        statement = receipt["statement"]
        signer = str(statement["signer_key_sha256"])
        operation_id = str(statement["operation_id"])
        identity = (signer, operation_id)
        encoded = canonical_bytes(receipt)
        previous = identities.get(identity)
        if previous is not None and previous != encoded:
            raise ValueError(
                "operation receipt identity is reused with different evidence"
            )
        identities[identity] = encoded
        chains.setdefault((signer, str(statement["purpose"])), []).append(receipt)
    for chain in chains.values():
        unique = {
            hashlib.sha256(canonical_bytes(item)).hexdigest(): item for item in chain
        }
        if len(unique) < 2:
            continue
        roots: list[str] = []
        children: dict[str, str] = {}
        for digest, receipt in unique.items():
            predecessor = str(receipt["statement"]["previous_operation_sha256"])
            if not predecessor:
                roots.append(digest)
                continue
            if predecessor not in unique:
                raise ValueError("operation receipt predecessor is not retained")
            if predecessor in children:
                raise ValueError("operation receipt predecessor chain forks")
            children[predecessor] = digest
        if len(roots) != 1:
            raise ValueError("operation receipt chain must have exactly one root")
        visited: set[str] = set()
        cursor = roots[0]
        while cursor:
            if cursor in visited:
                raise ValueError("operation receipt predecessor chain contains a cycle")
            visited.add(cursor)
            cursor = children.get(cursor, "")
        if visited != set(unique):
            raise ValueError("operation receipt predecessor chain is discontinuous")
    return receipts


def _contains_operation_receipt(value: object) -> bool:
    """Discover versioned cryptographic envelopes by structure, not one schema.

    Exact v1 operation receipts remain recognized, while portable deployment
    receipts and future signed-statement revisions cannot silently bypass a
    semantic validator merely by adding or renaming non-security metadata.
    """
    receipt_fields = {
        "schema_version",
        "statement",
        "signature_base64",
        "public_key_pem_base64",
    }
    statement_fields = {
        "schema_version",
        "purpose",
        "subject_sha256",
        "operation_id",
        "previous_operation_sha256",
        "challenge_sha256",
        "trusted_time_sha256",
        "issued_at",
        "expires_at",
        "signer_key_sha256",
    }
    if isinstance(value, dict):
        if value.get("x-pysec-crypto-envelope") is True:
            return True
        if _standard_crypto_envelope(value):
            return True
        statement = value.get("statement")
        if (
            set(value) == receipt_fields
            and isinstance(statement, dict)
            and set(statement) == statement_fields
        ):
            return True
        signed_statement = value.get("signed_statement")
        if (
            isinstance(value.get("signature_base64"), str)
            and bool(value["signature_base64"])
            and (
                isinstance(statement, dict)
                or isinstance(signed_statement, dict)
                or isinstance(value.get("receipt_payload_base64"), str)
            )
            and any(
                isinstance(value.get(name), str) and bool(value[name])
                for name in (
                    "public_key_pem_base64",
                    "signer_key_sha256",
                    "service_key_sha256",
                    "observer_identity_sha256",
                )
            )
        ):
            return True
        return any(_contains_operation_receipt(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_operation_receipt(item) for item in value)
    return False


def _standard_crypto_envelope(value: dict[str, Any]) -> bool:
    signatures = value.get("signatures")
    if (
        isinstance(value.get("payloadType"), str)
        and isinstance(value.get("payload"), str)
        and isinstance(signatures, list)
        and bool(signatures)
        and all(
            isinstance(item, dict)
            and isinstance(item.get("keyid"), str)
            and isinstance(item.get("sig"), str)
            and bool(item["sig"])
            for item in signatures
        )
    ):
        return True
    if (
        isinstance(value.get("payload"), str)
        and isinstance(signatures, list)
        and bool(signatures)
        and all(
            isinstance(item, dict)
            and isinstance(item.get("protected"), str)
            and isinstance(item.get("signature"), str)
            and bool(item["signature"])
            for item in signatures
        )
    ):
        return True
    if any(
        isinstance(value.get(name), str) and bool(value[name])
        for name in ("cose_sign1_base64", "cose_signature_base64")
    ):
        return True
    media_type = str(value.get("mediaType") or value.get("media_type") or "")
    if (
        "sigstore" in media_type.casefold()
        and isinstance(value.get("verificationMaterial"), dict)
        and (
            isinstance(value.get("messageSignature"), dict)
            or isinstance(value.get("dsseEnvelope"), dict)
        )
    ):
        return True
    return False


def _consume_operation_receipts(
    receipts: list[dict[str, Any]], artifacts: dict[str, Any]
) -> None:
    raw_path = os.environ.get("PYSEC_OPERATION_RECEIPT_STATE_PATH", "").strip()
    if not raw_path or not receipts:
        return
    minimum_sequence = _state_sequence("PYSEC_OPERATION_RECEIPT_MIN_SEQUENCE")
    expected_checkpoint = os.environ.get(
        "PYSEC_OPERATION_RECEIPT_CHECKPOINT_SHA256", ""
    ).strip()
    if not _digest(expected_checkpoint):
        raise ValueError("operation receipt deployment checkpoint is invalid")
    path = Path(raw_path).expanduser().resolve()
    if path.is_symlink():
        raise ValueError("operation receipt state must not be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    report_sha256 = hashlib.sha256(canonical_bytes(artifacts)).hexdigest()
    connection = sqlite3.connect(path, timeout=30, isolation_level=None)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS operation_receipts "
            "(signer TEXT NOT NULL, operation_id TEXT NOT NULL, "
            "receipt_sha256 TEXT NOT NULL, report_sha256 TEXT NOT NULL, "
            "PRIMARY KEY(signer, operation_id))"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS operation_receipt_checkpoint "
            "(scope TEXT PRIMARY KEY, sequence INTEGER NOT NULL, "
            "checkpoint_sha256 TEXT NOT NULL, external_receipt BLOB NOT NULL DEFAULT '')"
        )
        checkpoint_columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(operation_receipt_checkpoint)"
            )
        }
        if "external_receipt" not in checkpoint_columns:
            connection.execute(
                "ALTER TABLE operation_receipt_checkpoint ADD COLUMN "
                "external_receipt BLOB NOT NULL DEFAULT ''"
            )
        connection.execute("BEGIN IMMEDIATE")
        pending: list[tuple[str, str, str, str]] = []
        for receipt in receipts:
            statement = receipt["statement"]
            identity = (
                str(statement["signer_key_sha256"]),
                str(statement["operation_id"]),
            )
            receipt_sha256 = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
            row = connection.execute(
                "SELECT receipt_sha256, report_sha256 FROM operation_receipts "
                "WHERE signer = ? AND operation_id = ?",
                identity,
            ).fetchone()
            if row is not None and row != (receipt_sha256, report_sha256):
                connection.execute("ROLLBACK")
                raise ValueError("operation receipt replay across reports detected")
            if row is None:
                pending.append((*identity, receipt_sha256, report_sha256))
        checkpoint_row = connection.execute(
            "SELECT sequence, checkpoint_sha256, external_receipt "
            "FROM operation_receipt_checkpoint "
            "WHERE scope = 'global'"
        ).fetchone()
        if checkpoint_row is None:
            if (
                minimum_sequence != 0
                or expected_checkpoint != _OPERATION_STATE_GENESIS_SHA256
            ):
                connection.execute("ROLLBACK")
                raise ValueError(
                    "operation receipt state deletion or rollback detected"
                )
            sequence = 0
            checkpoint = _OPERATION_STATE_GENESIS_SHA256
        else:
            sequence = int(checkpoint_row[0])
            checkpoint = str(checkpoint_row[1])
            if sequence < minimum_sequence or (
                sequence == minimum_sequence and checkpoint != expected_checkpoint
            ):
                connection.execute("ROLLBACK")
                raise ValueError(
                    "operation receipt state deletion or rollback detected"
                )
        if not pending:
            if checkpoint_row is None:
                connection.execute("ROLLBACK")
                raise ValueError(
                    "operation receipt state deletion or rollback detected"
                )
            external_required = (
                os.environ.get(
                    "PYSEC_OPERATION_RECEIPT_REQUIRE_EXTERNAL_CHECKPOINT", ""
                ).strip()
                == "1"
            )
            external_bytes = bytes(checkpoint_row[2])
            if external_required and not external_bytes:
                connection.execute("ROLLBACK")
                raise ValueError("operation receipt external checkpoint is absent")
            if external_bytes:
                try:
                    retained_checkpoint = strict_loads(external_bytes)
                    verify_retained_checkpoint(
                        "PYSEC_OPERATION_RECEIPT_CHECKPOINT",
                        retained_checkpoint,
                        {
                            "schema_version": "1.0",
                            "state_kind": "operation-receipts",
                            "sequence": sequence,
                            "checkpoint_sha256": checkpoint,
                            "report_sha256": report_sha256,
                        },
                    )
                except (TypeError, ValueError):
                    connection.execute("ROLLBACK")
                    raise
            connection.execute("COMMIT")
            return
        for record in pending:
            connection.execute(
                "INSERT INTO operation_receipts VALUES (?, ?, ?, ?)", record
            )
        sequence += 1
        checkpoint = hashlib.sha256(
            canonical_bytes(
                {
                    "schema_version": "1.0",
                    "previous_checkpoint_sha256": checkpoint,
                    "sequence": sequence,
                    "report_sha256": report_sha256,
                    "receipt_sha256": sorted(record[2] for record in pending),
                }
            )
        ).hexdigest()
        external_receipt = publish_checkpoint(
            "PYSEC_OPERATION_RECEIPT_CHECKPOINT",
            {
                "schema_version": "1.0",
                "state_kind": "operation-receipts",
                "sequence": sequence,
                "checkpoint_sha256": checkpoint,
                "report_sha256": report_sha256,
            },
            required=os.environ.get(
                "PYSEC_OPERATION_RECEIPT_REQUIRE_EXTERNAL_CHECKPOINT", ""
            ).strip()
            == "1",
        )
        external_bytes = (
            canonical_bytes(external_receipt) if external_receipt is not None else b""
        )
        connection.execute(
            "INSERT INTO operation_receipt_checkpoint "
            "(scope, sequence, checkpoint_sha256, external_receipt) "
            "VALUES ('global', ?, ?, ?) "
            "ON CONFLICT(scope) DO UPDATE SET sequence=excluded.sequence, "
            "checkpoint_sha256=excluded.checkpoint_sha256, "
            "external_receipt=excluded.external_receipt",
            (sequence, checkpoint, external_bytes),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()


def _state_sequence(name: str) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} deployment sequence is invalid") from exc
    if value < 0 or str(value) != raw:
        raise ValueError(f"{name} deployment sequence is invalid")
    return value


@_typed_validator("boundary-graph.json")
def _validate_boundary_graph_receipts(value: object) -> None:
    if not isinstance(value, dict):
        raise TypeError("boundary graph must be an object")
    evidence = value.get("compiler_semantic_evidence")
    receipt = value.get("compiler_semantic_authority_receipt")
    reexecution = value.get("compiler_semantic_reexecution")
    if bool(evidence) != bool(receipt) or bool(evidence) != bool(reexecution):
        raise ValueError("compiler semantic authority receipt is incomplete")
    subject = {name: item for name, item in value.items() if name != "graph_sha256"}
    if (
        value.get("graph_sha256")
        != hashlib.sha256(canonical_bytes(subject)).hexdigest()
    ):
        raise ValueError("boundary graph digest does not match")
    file_sets = value.get("language_file_sets")
    if not isinstance(file_sets, dict):
        raise ValueError("boundary graph language file sets are invalid")
    for file_set in file_sets.values():
        if (
            not isinstance(file_set, dict)
            or file_set.get("files_sha256")
            != hashlib.sha256(canonical_bytes(file_set.get("files"))).hexdigest()
        ):
            raise ValueError("boundary graph language file ledger is detached")
    if evidence:
        from .boundary_graph import (
            verify_compiler_semantic_evidence,
            verify_compiler_semantic_reexecution,
        )

        verify_compiler_semantic_evidence(evidence, file_sets)
        verify_compiler_semantic_reexecution(reexecution, evidence, file_sets)
        _reverify_portable(evidence, receipt, "compiler-semantic-evidence")


@_typed_validator("source-inventory.json")
def _validate_git_provenance(value: object) -> None:
    if not isinstance(value, dict):
        raise TypeError("source inventory must be an object")
    provenance = value.get("git_provenance")
    if provenance is None:
        return
    if not isinstance(provenance, list) or not provenance:
        raise ValueError("retained Git provenance is empty")
    paths: set[str] = set()
    for item in provenance:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "schema_version",
            "manifest",
            "authority_receipt",
        }:
            raise ValueError("retained Git provenance fields do not match")
        path = str(item["path"])
        if path in paths or (
            path != "." and (path.startswith("/") or ".." in path.split("/"))
        ):
            raise ValueError("retained Git provenance path is invalid")
        paths.add(path)
        manifest = item["manifest"]
        if not isinstance(manifest, dict) or set(manifest) != {
            "schema_version",
            "git_executable_sha256",
            "allowed_signers_file_sha256",
            "allowed_signers_file_base64",
            "signer_policy",
            "signature_ledger",
            "repository_state",
            "git_runtime_manifest",
            "clean_replay",
        }:
            raise ValueError("retained Git manifest fields do not match")
        try:
            allowed_signers = base64.b64decode(
                str(manifest["allowed_signers_file_base64"]), validate=True
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("retained Git allowed-signers file is invalid") from exc
        if hashlib.sha256(allowed_signers).hexdigest() != manifest.get(
            "allowed_signers_file_sha256"
        ):
            raise ValueError("retained Git allowed-signers content is detached")
        from .inventory import allowed_signer_fingerprints

        _validate_git_signature_ledger(
            manifest, allowed_signer_fingerprints(allowed_signers)
        )
        _validate_clean_git_replay(manifest)
        _reverify_portable(manifest, item["authority_receipt"], "git-ref-manifest")
    if "." not in paths:
        raise ValueError("retained Git provenance omits the superproject")


def _validate_git_signature_ledger(
    manifest: dict[str, Any], allowed_fingerprints: set[str]
) -> None:
    policy = manifest.get("signer_policy")
    ledger = manifest.get("signature_ledger")
    if (
        not isinstance(policy, list)
        or not isinstance(ledger, dict)
        or set(ledger)
        != {
            "commits",
            "tags",
        }
    ):
        raise ValueError("retained Git signature policy is invalid")
    identities: dict[str, tuple[str, datetime, datetime]] = {}
    for item in policy:
        if not isinstance(item, dict) or set(item) != {
            "fingerprint",
            "organization",
            "not_before",
            "not_after",
        }:
            raise ValueError("retained Git signer policy is invalid")
        try:
            start = datetime.fromisoformat(
                str(item["not_before"]).replace("Z", "+00:00")
            )
            end = datetime.fromisoformat(str(item["not_after"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("retained Git signer lifecycle is invalid") from exc
        fingerprint = str(item["fingerprint"]).casefold()
        organization = str(item["organization"])
        if (
            len(fingerprint) < 16
            or fingerprint in identities
            or not organization
            or start.tzinfo is None
            or end.tzinfo is None
            or start >= end
        ):
            raise ValueError("retained Git signer policy is invalid")
        identities[fingerprint] = organization, start, end
    if set(identities) - allowed_fingerprints:
        raise ValueError("retained Git signer policy is detached from allowed signers")
    repository_state = manifest.get("repository_state")
    if not isinstance(repository_state, dict) or set(repository_state) != {
        "refs",
        "object_format",
        "head",
        "symbolic_head",
        "replace_refs",
        "security_config_sha256",
        "security_config_base64",
        "alternates_sha256",
        "reachable_objects_sha256",
    }:
        raise ValueError("retained Git repository state is invalid")
    object_format = repository_state["object_format"]
    digest_length = 64 if object_format == "sha256" else 0
    refs = repository_state["refs"]
    runtime_manifest = manifest.get("git_runtime_manifest")
    try:
        security_config = base64.b64decode(
            str(repository_state["security_config_base64"]), validate=True
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("retained Git security configuration is invalid") from exc
    if (
        not digest_length
        or any(
            len(str(manifest[name])) != 64
            or any(
                character not in "0123456789abcdef" for character in str(manifest[name])
            )
            for name in (
                "git_executable_sha256",
                "allowed_signers_file_sha256",
            )
        )
        or hashlib.sha256(security_config).hexdigest()
        != repository_state["security_config_sha256"]
        or not isinstance(runtime_manifest, dict)
        or set(runtime_manifest)
        != {"version", "executable_sha256", "runtime_closure_sha256"}
        or not str(runtime_manifest["version"]).startswith("git version ")
        or runtime_manifest["executable_sha256"] != manifest["git_executable_sha256"]
        or any(
            not _digest(str(runtime_manifest[name]))
            for name in ("executable_sha256", "runtime_closure_sha256")
        )
        or not isinstance(refs, dict)
        or not refs
        or any(
            not str(name).startswith("refs/")
            or len(str(digest)) != digest_length
            or any(character not in "0123456789abcdef" for character in str(digest))
            for name, digest in refs.items()
        )
        or len(str(repository_state["head"])) != digest_length
        or any(
            character not in "0123456789abcdef"
            for character in str(repository_state["head"])
        )
        or (
            repository_state["symbolic_head"]
            and repository_state["symbolic_head"] not in refs
        )
        or repository_state["replace_refs"]
        or repository_state["alternates_sha256"]
        or any(
            len(str(repository_state[name])) != 64
            or any(
                character not in "0123456789abcdef"
                for character in str(repository_state[name])
            )
            for name in ("security_config_sha256", "reachable_objects_sha256")
        )
    ):
        raise ValueError("retained Git repository state is invalid")

    commits = ledger["commits"]
    tags = ledger["tags"]
    if not isinstance(commits, list) or not commits or not isinstance(tags, list):
        raise ValueError("retained Git signature ledger is invalid")
    organizations: set[str] = set()
    for kind, records, identity_name, time_name in (
        ("commit", commits, "commit", "committed_at"),
        ("tag", tags, "tag", "tagged_at"),
    ):
        seen: set[str] = set()
        for record in records:
            expected_record_fields = {
                identity_name,
                "fingerprint",
                time_name,
                "organization",
                "object_base64",
                "object_sha256",
            }
            if kind == "tag":
                expected_record_fields.add("object_id")
            if not isinstance(record, dict) or set(record) != expected_record_fields:
                raise ValueError(f"retained Git {kind} signature is invalid")
            identity = str(record[identity_name])
            signer = identities.get(str(record["fingerprint"]).casefold())
            try:
                observed = datetime.fromisoformat(
                    str(record[time_name]).replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise ValueError(f"retained Git {kind} time is invalid") from exc
            if (
                not identity
                or identity in seen
                or (kind == "commit" and len(identity) != digest_length)
                or signer is None
                or record["organization"] != signer[0]
                or observed.tzinfo is None
                or not signer[1] <= observed <= signer[2]
            ):
                raise ValueError(f"retained Git {kind} signature is invalid")
            try:
                payload = base64.b64decode(record["object_base64"], validate=True)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"retained Git {kind} object is invalid") from exc
            object_id = hashlib.sha256(
                kind.encode() + b" " + str(len(payload)).encode() + b"\0" + payload
            ).hexdigest()
            expected_object_id = (
                identity if kind == "commit" else str(record["object_id"])
            )
            if (
                hashlib.sha256(payload).hexdigest() != record["object_sha256"]
                or object_id != expected_object_id
            ):
                raise ValueError(f"retained Git {kind} object replay failed")
            seen.add(identity)
            organizations.add(signer[0])
    if len(organizations) < 2:
        raise ValueError("retained Git signatures lack organization diversity")
    if repository_state["head"] not in {str(item["commit"]) for item in commits}:
        raise ValueError("retained Git signature ledger omits HEAD")
    tag_names = {str(item["tag"]) for item in tags}
    if {
        name.removeprefix("refs/tags/")
        for name in refs
        if str(name).startswith("refs/tags/")
    } != tag_names:
        raise ValueError("retained Git tag ledger does not match repository refs")
    if any(refs.get(f"refs/tags/{item['tag']}") != item["object_id"] for item in tags):
        raise ValueError("retained Git tag object is detached from its ref")


def _validate_clean_git_replay(manifest: dict[str, Any]) -> None:
    replay = manifest.get("clean_replay")
    ledger = manifest.get("signature_ledger")
    repository = manifest.get("repository_state")
    runtime = manifest.get("git_runtime_manifest")
    if not isinstance(replay, dict) or set(replay) != {
        "schema_version",
        "bundle_sha256",
        "reachable_objects_sha256",
        "signature_ledger_sha256",
        "git_executable_sha256",
        "git_runtime_closure_sha256",
        "verified_commits",
        "verified_tags",
        "primary_failure_domain",
        "bundle_storage",
        "secondary_verification",
    }:
        raise ValueError("retained clean Git replay fields do not match")
    if (
        replay.get("schema_version") != "1.0"
        or not all(
            _digest(str(replay.get(name, "")))
            for name in (
                "bundle_sha256",
                "reachable_objects_sha256",
                "signature_ledger_sha256",
                "git_executable_sha256",
                "git_runtime_closure_sha256",
            )
        )
        or not isinstance(ledger, dict)
        or not isinstance(repository, dict)
        or not isinstance(runtime, dict)
        or replay["reachable_objects_sha256"]
        != repository.get("reachable_objects_sha256")
        or replay["signature_ledger_sha256"]
        != hashlib.sha256(canonical_bytes(ledger)).hexdigest()
        or replay["git_executable_sha256"] != manifest.get("git_executable_sha256")
        or replay["git_runtime_closure_sha256"] != runtime.get("runtime_closure_sha256")
        or replay.get("verified_commits") != len(ledger.get("commits", []))
        or replay.get("verified_tags") != len(ledger.get("tags", []))
    ):
        raise ValueError("retained clean Git replay is detached or invalid")
    _validate_external_git_replay(manifest, replay)


def _validate_external_git_replay(
    manifest: dict[str, Any], replay: dict[str, Any]
) -> None:
    storage = replay["bundle_storage"]
    secondary = replay["secondary_verification"]
    primary = verify_failure_domain(
        replay["primary_failure_domain"], "primary Git verifier"
    )
    storage_fields = {
        "schema_version",
        "object_id",
        "object_version",
        "immutable_uri",
        "retention_until",
        "bundle_sha256",
        "bundle_size_bytes",
        "authority_key_sha256",
        "execution_nonce",
        "failure_domain",
        "operation_receipt",
        "effective_policy_attestation",
        "attested_request",
    }
    secondary_fields = {
        "schema_version",
        "bundle_sha256",
        "bundle_size_bytes",
        "reachable_objects_sha256",
        "signature_ledger_sha256",
        "allowed_signers_sha256",
        "verified_commits",
        "verified_tags",
        "cas_object_id",
        "cas_object_version",
        "cas_bundle_read_sha256",
        "authority_key_sha256",
        "execution_nonce",
        "failure_domain",
        "operation_receipt",
        "effective_policy_attestation",
        "attested_request",
    }
    if (
        not isinstance(storage, dict)
        or set(storage) != storage_fields
        or not isinstance(secondary, dict)
        or set(secondary) != secondary_fields
        or storage.get("schema_version") != "1.0"
        or secondary.get("schema_version") != "1.0"
        or not str(storage.get("object_id") or "")
        or isinstance(storage.get("bundle_size_bytes"), bool)
        or not isinstance(storage.get("bundle_size_bytes"), int)
        or storage["bundle_size_bytes"] < 1
        or secondary.get("bundle_size_bytes") != storage["bundle_size_bytes"]
        or storage.get("object_id") != f"sha256:{replay['bundle_sha256']}"
        or not str(storage.get("object_version") or "").strip()
        or not str(storage.get("immutable_uri") or "").startswith("cas://")
        or secondary.get("cas_object_id") != storage.get("object_id")
        or secondary.get("cas_object_version") != storage.get("object_version")
        or secondary.get("cas_bundle_read_sha256") != replay["bundle_sha256"]
    ):
        raise ValueError("external Git replay evidence is invalid")
    storage_statement = (
        storage["operation_receipt"].get("statement")
        if isinstance(storage.get("operation_receipt"), dict)
        else None
    )
    try:
        retention_until = datetime.fromisoformat(
            str(storage["retention_until"]).replace("Z", "+00:00")
        )
        storage_issued = datetime.fromisoformat(
            str((storage_statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("external Git CAS retention is invalid") from exc
    if (
        retention_until < storage_issued + timedelta(days=30)
        or replay["bundle_sha256"] not in storage["immutable_uri"]
    ):
        raise ValueError("external Git CAS retention is insufficient")
    base = {
        "schema_version": "1.0",
        "bundle_sha256": replay["bundle_sha256"],
        "bundle_size_bytes": storage["bundle_size_bytes"],
        "reachable_objects_sha256": replay["reachable_objects_sha256"],
        "signature_ledger_sha256": replay["signature_ledger_sha256"],
        "allowed_signers_sha256": manifest["allowed_signers_file_sha256"],
        "verified_commits": replay["verified_commits"],
        "verified_tags": replay["verified_tags"],
    }
    for name, expected in base.items():
        if name in storage and storage[name] != expected:
            raise ValueError("external Git bundle storage is detached")
        if name in secondary and secondary[name] != expected:
            raise ValueError("secondary Git verification is detached")
    storage_domain = verify_failure_domain(
        storage["failure_domain"], "Git CAS authority"
    )
    secondary_domain = verify_failure_domain(
        secondary["failure_domain"], "secondary Git verifier"
    )
    from .pinned_command import verify_retained_effective_policy_attestation

    if storage_domain != verify_retained_effective_policy_attestation(
        storage["effective_policy_attestation"]
    ):
        raise ValueError("Git CAS failure domain is not hardware-attested")
    if secondary_domain != verify_retained_effective_policy_attestation(
        secondary["effective_policy_attestation"]
    ):
        raise ValueError("secondary Git failure domain is not hardware-attested")
    for response, label in ((storage, "Git CAS"), (secondary, "secondary Git")):
        attestation_subject = response["effective_policy_attestation"].get("subject")
        attested_request = response["attested_request"]
        if (
            not isinstance(attestation_subject, dict)
            or not isinstance(attested_request, dict)
            or attestation_subject.get("request_sha256")
            != hashlib.sha256(canonical_bytes(attested_request)).hexdigest()
            or attestation_subject.get("command_context_sha256")
            != hashlib.sha256(
                canonical_bytes(attested_request.get("command_context"))
            ).hexdigest()
            or response.get("execution_nonce")
            != attestation_subject.get("execution_nonce")
        ):
            raise ValueError(f"{label} result is detached from its attested request")
    storage_attested = {
        name: value
        for name, value in storage["attested_request"].items()
        if name not in {"bundle_path", "command_context"}
    }
    secondary_attested = {
        name: value
        for name, value in secondary["attested_request"].items()
        if name != "command_context"
    }
    expected_secondary_attested = {
        **base,
        "cas_object_id": storage["object_id"],
        "cas_object_version": storage["object_version"],
        "cas_immutable_uri": storage["immutable_uri"],
        "cas_authority_key_sha256": storage["authority_key_sha256"],
        "cas_operation_receipt_sha256": hashlib.sha256(
            canonical_bytes(storage["operation_receipt"])
        ).hexdigest(),
        "cas_effective_policy_attestation_sha256": hashlib.sha256(
            canonical_bytes(storage["effective_policy_attestation"])
        ).hexdigest(),
    }
    if storage_attested != base or secondary_attested != expected_secondary_attested:
        raise ValueError("external Git result request bindings are detached")
    require_independent_failure_domains(
        primary,
        storage_domain,
        labels=("primary Git verifier", "Git CAS authority"),
    )
    require_independent_failure_domains(
        primary,
        secondary_domain,
        labels=("primary Git verifier", "secondary Git verifier"),
    )
    require_independent_failure_domains(
        storage_domain,
        secondary_domain,
        labels=("Git CAS authority", "secondary Git verifier"),
    )
    _verify_git_authority_receipt(
        {
            **base,
            "object_id": storage["object_id"],
            "object_version": storage["object_version"],
            "immutable_uri": storage["immutable_uri"],
            "retention_until": storage["retention_until"],
            "execution_nonce": storage["execution_nonce"],
            "failure_domain": storage_domain,
        },
        storage,
        "git-bundle-cas-publish",
    )
    _verify_git_authority_receipt(
        {
            **base,
            "cas_object_id": storage["object_id"],
            "cas_object_version": storage["object_version"],
            "cas_immutable_uri": storage["immutable_uri"],
            "cas_authority_key_sha256": storage["authority_key_sha256"],
            "cas_operation_receipt_sha256": hashlib.sha256(
                canonical_bytes(storage["operation_receipt"])
            ).hexdigest(),
            "cas_effective_policy_attestation_sha256": hashlib.sha256(
                canonical_bytes(storage["effective_policy_attestation"])
            ).hexdigest(),
            "cas_bundle_read_sha256": replay["bundle_sha256"],
            "execution_nonce": secondary["execution_nonce"],
            "failure_domain": secondary_domain,
        },
        secondary,
        "git-bundle-secondary-verification",
    )


def _verify_git_authority_receipt(
    subject: dict[str, Any], response: dict[str, Any], purpose: str
) -> None:
    key = str(response.get("authority_key_sha256") or "")
    receipt = response.get("operation_receipt")
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        issued = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("external Git replay receipt time is invalid") from exc
    _reverify_operation(subject, receipt, purpose, issued, key)


def _is_companion_assurance(value: object) -> bool:
    return bool(
        isinstance(value, dict)
        and value.get("schema_version") == "2.0"
        and isinstance(value.get("evidence_binding"), dict)
        and isinstance(value.get("execution"), dict)
        and isinstance(value.get("kind"), str)
    )


def _validate_companion_recovery_receipts(value: object) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("execution"), dict):
        return
    receipts = value["execution"].get("recovery_receipts")
    if not isinstance(receipts, list):
        return
    event_ids: set[str] = set()
    for receipt in receipts:
        if not isinstance(receipt, dict) or not isinstance(
            receipt.get("statement"), dict
        ):
            raise ValueError("portable recovery receipt is invalid")
        statement = receipt["statement"]
        try:
            payload = base64.b64decode(
                str(receipt["receipt_payload_base64"]), validate=True
            )
            original = strict_loads(payload)
            key_bytes = base64.b64decode(
                str(receipt["public_key_pem_base64"]), validate=True
            )
            signature = base64.b64decode(
                str(receipt["signature_base64"]), validate=True
            )
            key = serialization.load_pem_public_key(key_bytes)
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("recovery receipt key is not Ed25519")
            key.verify(signature, canonical_bytes(statement))
        except Exception as exc:
            raise ValueError("portable recovery receipt signature is invalid") from exc
        event_id = str(statement.get("event_id") or "")
        if (
            not event_id
            or event_id in event_ids
            or statement.get("run_id") != value.get("run_id")
            or statement.get("deployment_sha256")
            != value.get("context", {}).get("deployment_sha256")
            or statement.get("orchestrator_identity_sha256")
            != hashlib.sha256(key_bytes).hexdigest()
            or hashlib.sha256(payload).hexdigest() != receipt.get("receipt_sha256")
            or original
            != {**statement, "signature_base64": receipt["signature_base64"]}
        ):
            raise ValueError("portable recovery receipt binding is invalid")
        observer_receipts = receipt.get("observer_receipts")
        if (
            not isinstance(observer_receipts, dict)
            or set(observer_receipts) != {"precondition", "postcondition"}
            or not isinstance(observer_receipts["precondition"], list)
            or not isinstance(observer_receipts["postcondition"], list)
            or len(observer_receipts["precondition"]) < 2
            or len(observer_receipts["precondition"])
            != len(observer_receipts["postcondition"])
        ):
            raise ValueError("portable recovery observer quorum is invalid")
        before = [
            _verify_observer_receipt_offline(item)
            for item in observer_receipts["precondition"]
        ]
        after = [
            _verify_observer_receipt_offline(item)
            for item in observer_receipts["postcondition"]
        ]
        before_ids = {item["observer_identity_sha256"] for item in before}
        after_ids = {item["observer_identity_sha256"] for item in after}
        try:
            receipt_time = datetime.fromisoformat(
                str(statement["issued_at"]).replace("Z", "+00:00")
            )
        except (KeyError, ValueError) as exc:
            raise ValueError("portable recovery receipt time is invalid") from exc
        if (
            before_ids != after_ids
            or len(before_ids) != len(before)
            or len({item["organization"] for item in before}) != len(before)
            or len({item["host_identity_sha256"] for item in before}) != len(before)
            or receipt_time.tzinfo is None
            or any(
                not _observer_time_near(item, receipt_time)
                for item in [*before, *after]
            )
            or any(
                item["run_id"] != statement["run_id"]
                or item["deployment_sha256"] != statement["deployment_sha256"]
                or item["challenge_sha256"] != statement["challenge_sha256"]
                or item["recovery_event_id"]
                or hashlib.sha256(canonical_bytes(item["state"])).hexdigest()
                != statement["before_state_sha256"]
                for item in before
            )
            or any(
                item["run_id"] != statement["run_id"]
                or item["deployment_sha256"] != statement["deployment_sha256"]
                or item["challenge_sha256"] != statement["challenge_sha256"]
                or item["recovery_event_id"] != statement["event_id"]
                or item["recovery_epoch"] != statement["recovery_epoch"]
                or item["fencing_token_sha256"] != statement["fencing_token_sha256"]
                or hashlib.sha256(canonical_bytes(item["state"])).hexdigest()
                != statement["after_state_sha256"]
                for item in after
            )
        ):
            raise ValueError("portable recovery observer binding is invalid")
        event_ids.add(event_id)


def _observer_time_near(value: dict[str, Any], receipt_time: datetime) -> bool:
    try:
        observed = datetime.fromisoformat(
            str(value["observed_at"]).replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(
            str(value["expires_at"]).replace("Z", "+00:00")
        )
    except ValueError:
        return False
    return bool(
        observed.tzinfo is not None
        and expires.tzinfo is not None
        and abs(observed - receipt_time) <= timedelta(minutes=10)
        and observed < expires
        and expires - observed <= timedelta(minutes=5)
    )


def _verify_observer_receipt_offline(value: object) -> dict[str, Any]:
    fields = {
        "schema_version",
        "observer_identity_sha256",
        "organization",
        "host_identity_sha256",
        "request_sha256",
        "observation_id",
        "status",
        "state",
        "recovery_epoch",
        "fencing_token_sha256",
        "context_sha256",
        "run_id",
        "deployment_sha256",
        "challenge_sha256",
        "recovery_event_id",
        "observed_at",
        "expires_at",
        "public_key_pem_base64",
        "signature_base64",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("portable recovery observer fields do not match")
    try:
        key_bytes = base64.b64decode(value["public_key_pem_base64"], validate=True)
        signature = base64.b64decode(value["signature_base64"], validate=True)
        key = serialization.load_pem_public_key(key_bytes)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("observer key is not Ed25519")
        key.verify(
            signature,
            canonical_bytes(
                {name: value[name] for name in fields - {"signature_base64"}}
            ),
        )
    except Exception as exc:
        raise ValueError("portable recovery observer signature is invalid") from exc
    if hashlib.sha256(key_bytes).hexdigest() != value["observer_identity_sha256"]:
        raise ValueError("portable recovery observer identity is invalid")
    return value


@_typed_validator("security-requirements-coverage.json")
def _validate_requirements_crosswalk(value: object) -> None:
    if not isinstance(value, dict):
        raise TypeError("security requirements crosswalk must be an object")
    expected = value.get("crosswalk_sha256")
    subject = {name: item for name, item in value.items() if name != "crosswalk_sha256"}
    if expected != hashlib.sha256(canonical_bytes(subject)).hexdigest():
        raise ValueError("security requirements crosswalk digest does not match")
    records = value.get("requirements")
    if not isinstance(records, list):
        raise TypeError("security requirements must be an array")
    applicable = [
        record
        for record in records
        if isinstance(record, dict) and record.get("applicable") is True
    ]
    gaps = sorted(
        str(record.get("requirement"))
        for record in applicable
        if record.get("status") not in {"evidence-collected", "passed"}
    )
    evidenced = sum(
        record.get("status") in {"evidence-collected", "passed", "failed"}
        for record in applicable
    )
    applicability = value.get("applicability_decision")
    full_catalog = value.get("full_catalog_coverage") is True
    approved = bool(
        isinstance(applicability, dict)
        and applicability.get("organization_approved") is True
    )
    automation_complete = not gaps
    assessment_complete = bool(applicable) and all(
        record.get("status") == "passed" for record in applicable
    )
    if (
        value.get("applicable_requirements") != len(applicable)
        or value.get("evidenced_requirements") != evidenced
        or value.get("gaps") != gaps
        or value.get("automation_complete") is not automation_complete
        or value.get("complete")
        is not (assessment_complete and full_catalog and approved)
    ):
        raise ValueError("security requirements crosswalk accounting does not match")
    evidence_policy = value.get("evidence_policy")
    evidence_authority = value.get("evidence_policy_authority_receipt")
    if bool(evidence_policy) != bool(evidence_authority):
        raise ValueError("requirements evidence policy portable receipt is incomplete")
    if evidence_policy:
        _reverify_portable(
            evidence_policy,
            evidence_authority,
            "requirements-evidence-policy",
        )
        executions = value.get("procedure_executions")
        if not isinstance(executions, dict):
            raise ValueError("requirements procedure executions are not retained")
        controls = {
            (
                str(item["standard"]),
                str(item["version"]),
                str(item["requirement"]),
            ): item
            for item in evidence_policy.get("requirements", [])
            if isinstance(item, dict)
        }
        observed_at = _portable_verified_at(evidence_authority)
        for record in records:
            assessment = record.get("assessment") if isinstance(record, dict) else None
            if not isinstance(assessment, dict):
                continue
            control = controls.get(
                (
                    str(record["standard"]),
                    str(record["version"]),
                    str(record["requirement"]),
                )
            )
            if not isinstance(control, dict):
                raise ValueError("requirements execution policy is detached")
            for assertion in assessment.get("assertions", []):
                execution = executions.get(assertion.get("execution_artifact"))
                if not isinstance(execution, dict) or hashlib.sha256(
                    canonical_bytes(execution)
                ).hexdigest() != assertion.get("execution_sha256"):
                    raise ValueError("requirements execution artifact is detached")
                from .requirements_coverage import _procedure_manifests_valid

                if not _procedure_manifests_valid(execution):
                    raise ValueError("requirements execution manifests are invalid")
                receipt = execution.get("execution_authority_receipt")
                statement = (
                    receipt.get("statement") if isinstance(receipt, dict) else None
                )
                signer = str((statement or {}).get("signer_key_sha256") or "")
                if signer not in control.get(
                    "allowed_execution_authority_key_sha256", []
                ):
                    raise ValueError("requirements execution signer is not approved")
                _reverify_operation(
                    {
                        name: item
                        for name, item in execution.items()
                        if name != "execution_authority_receipt"
                    },
                    receipt,
                    "requirements-procedure-execution",
                    observed_at,
                    signer,
                )


@_typed_validator("checkov-iac.json")
def _validate_checkov_accounting(value: object) -> None:
    if not isinstance(value, dict):
        raise TypeError("Checkov artifact must be an object")
    total = sum(
        int(value.get(name) or 0)
        for name in ("passed_checks", "failed_checks", "skipped_checks")
    )
    if value.get("total_checks") != total:
        raise ValueError("Checkov artifact check accounting does not match")
    _validate_native_normalization(value, total)


@_typed_validator("git-sizer.json")
def _validate_git_sizer_accounting(value: object) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("metrics"), list):
        raise TypeError("git-sizer artifact metrics must be an array")
    metrics = value["metrics"]
    paths = [str(item.get("path")) for item in metrics if isinstance(item, dict)]
    concerning = sum(
        float(item.get("level_of_concern") or 0) >= 1
        for item in metrics
        if isinstance(item, dict)
    )
    if len(paths) != len(metrics) or len(paths) != len(set(paths)):
        raise ValueError("git-sizer metric paths must be unique")
    if value.get("concerning_metrics") != concerning:
        raise ValueError("git-sizer concern accounting does not match")
    _validate_native_normalization(value, len(metrics))


@_typed_validator("pipdeptree-summary.json")
def _validate_pipdeptree_accounting(value: object) -> None:
    if not isinstance(value, dict):
        raise TypeError("pipdeptree artifact must be an object")
    total = int(value.get("total_packages") or 0)
    direct = int(value.get("direct_dependencies") or 0)
    transitive = int(value.get("transitive_dependencies") or 0)
    maximum_depth = int(value.get("max_depth") or 0)
    conflicts = value.get("conflicting_dependencies")
    if direct + transitive != total:
        raise ValueError("pipdeptree package accounting does not match")
    if maximum_depth > total:
        raise ValueError("pipdeptree maximum depth exceeds its package count")
    if not isinstance(conflicts, dict) or int(conflicts.get("packages") or 0) > total:
        raise ValueError("pipdeptree conflict accounting does not match")
    _validate_native_normalization(value, total)


def _validate_native_normalization(value: dict[str, Any], records: int) -> None:
    """Bind normalized accounting to a whole native payload commitment."""
    if value.get("native_report_records") != records:
        raise ValueError("native report record accounting does not match")
    size = value.get("native_report_size_bytes")
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise ValueError("native report byte accounting is invalid")
    native = value.get("native_report_redacted_utf8")
    if not isinstance(native, str):
        raise TypeError("native report redacted replay projection must be UTF-8 text")
    encoded = native.encode("utf-8")
    redacted_size = value.get("native_report_redacted_size_bytes")
    if len(encoded) != redacted_size or hashlib.sha256(
        encoded
    ).hexdigest() != value.get("native_report_redacted_sha256"):
        raise ValueError("native report redacted projection commitment does not match")
    if not isinstance(value.get("native_report_replayable"), bool):
        raise ValueError("native report replay policy is invalid")
    storage = value.get("native_report_storage")
    if not isinstance(storage, dict) or set(storage) != {
        "mode",
        "object_id",
        "ciphertext_sha256",
        "key_sha256",
        "custody_receipt_sha256",
        "custody_level",
        "wrapped_data_key_base64",
        "custody_receipt",
        "custody_authority_receipt",
        "effective_policy_attestation",
        "recovery_drill",
    }:
        raise ValueError("native report storage receipt is invalid")
    replayable = storage["mode"] == "encrypted-cas"
    if value["native_report_replayable"] is not replayable:
        raise ValueError("native report storage and replay policy do not match")
    if replayable and not all(
        isinstance(storage[name], str) and storage[name]
        for name in (
            "object_id",
            "ciphertext_sha256",
            "key_sha256",
            "custody_receipt_sha256",
            "wrapped_data_key_base64",
        )
    ):
        raise ValueError("encrypted native report storage receipt is incomplete")
    if replayable and (
        storage["custody_level"] != "hardware-kms-envelope"
        or not isinstance(storage["custody_receipt"], dict)
        or not isinstance(storage["custody_authority_receipt"], dict)
        or storage["custody_receipt_sha256"]
        != hashlib.sha256(canonical_bytes(storage["custody_receipt"])).hexdigest()
    ):
        raise ValueError("encrypted native evidence lacks hardware KMS custody")
    if replayable:
        custody = storage["custody_receipt"]
        try:
            wrapped_key = base64.b64decode(
                storage["wrapped_data_key_base64"], validate=True
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "encrypted native evidence wrapped key is invalid"
            ) from exc
        if (
            len(wrapped_key) < 32
            or custody.get("wrapped_key_sha256")
            != hashlib.sha256(wrapped_key).hexdigest()
        ):
            raise ValueError("encrypted native evidence wrapped key is unbound")
        _validate_custody_transport(custody)
        _reverify_portable(
            custody,
            storage["custody_authority_receipt"],
            "raw-evidence-custody",
        )
        attestation = storage["effective_policy_attestation"]
        subject = attestation.get("subject") if isinstance(attestation, dict) else None
        if (
            not isinstance(attestation, dict)
            or set(attestation) != {"subject", "operation_receipt"}
            or not isinstance(subject, dict)
            or subject.get("attestor_key_sha256")
            != custody["command_context"]["effective_policy_attestor_key_sha256"]
        ):
            raise ValueError("retained KMS effective-policy attestation is invalid")
        from .pinned_command import verify_effective_policy_subject

        verify_effective_policy_subject(subject)
        statement = attestation["operation_receipt"].get("statement", {})
        try:
            issued = datetime.fromisoformat(
                str(statement["issued_at"]).replace("Z", "+00:00")
            )
        except (KeyError, ValueError) as exc:
            raise ValueError("retained KMS attestation time is invalid") from exc
        _reverify_operation(
            subject,
            attestation["operation_receipt"],
            "pinned-command-effective-policy",
            issued,
            str(subject["attestor_key_sha256"]),
        )
        drill = storage["recovery_drill"]
        if (
            not isinstance(drill, dict)
            or set(drill)
            != {
                "schema_version",
                "mode",
                "request_sha256",
                "recovery_request",
                "object_id",
                "ciphertext_sha256",
                "recovered_plaintext_sha256",
                "replica_identity_sha256",
                "kms_unwrap_operation_id",
                "execution_nonce",
                "recovery_operation_id",
                "recovery_authority_key_sha256",
                "recovery_operation_receipt",
                "provider_audit_authority_key_sha256",
                "provider_audit_event",
                "provider_audit_readback",
                "effective_policy_attestation",
                "verified",
            }
            or drill.get("schema_version") != "1.0"
            or drill.get("mode") != "external-clean-host-kms-restore"
            or drill.get("object_id") != storage["object_id"]
            or drill.get("ciphertext_sha256") != storage["ciphertext_sha256"]
            or drill.get("recovered_plaintext_sha256")
            != value.get("native_report_sha256")
            or not _digest(str(drill.get("request_sha256") or ""))
            or not isinstance(drill.get("recovery_request"), dict)
            or drill["request_sha256"]
            != hashlib.sha256(canonical_bytes(drill["recovery_request"])).hexdigest()
            or drill["recovery_request"].get("object_id") != drill["object_id"]
            or drill["recovery_request"].get("challenge_sha256")
            != os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
            or not _digest(str(drill.get("replica_identity_sha256") or ""))
            or not str(drill.get("kms_unwrap_operation_id") or "")
            or not str(drill.get("execution_nonce") or "")
            or not str(drill.get("recovery_operation_id") or "")
            or not _digest(str(drill.get("recovery_authority_key_sha256") or ""))
            or drill.get("verified") is not True
        ):
            raise ValueError("encrypted native evidence recovery drill is invalid")
        recovery_subject = {
            name: drill[name]
            for name in (
                "schema_version",
                "request_sha256",
                "object_id",
                "ciphertext_sha256",
                "recovered_plaintext_sha256",
                "replica_identity_sha256",
                "kms_unwrap_operation_id",
                "execution_nonce",
            )
        }
        recovery_receipt = drill["recovery_operation_receipt"]
        recovery_statement = (
            recovery_receipt.get("statement")
            if isinstance(recovery_receipt, dict)
            else None
        )
        try:
            recovery_issued = datetime.fromisoformat(
                str((recovery_statement or {})["issued_at"]).replace("Z", "+00:00")
            )
        except (KeyError, ValueError) as exc:
            raise ValueError("retained recovery receipt time is invalid") from exc
        _reverify_operation(
            recovery_subject,
            recovery_receipt,
            "raw-evidence-clean-host-recovery",
            recovery_issued,
            str(drill["recovery_authority_key_sha256"]),
        )
        if (recovery_statement or {}).get("operation_id") != drill.get(
            "recovery_operation_id"
        ):
            raise ValueError("retained recovery operation identity is detached")
        audit = drill["provider_audit_event"]
        audit_fields = {
            "schema_version",
            "provider",
            "audit_event_id",
            "object_id",
            "ciphertext_sha256",
            "recovered_plaintext_sha256",
            "wrapped_key_sha256",
            "kms_unwrap_operation_id",
            "hardware_backed",
            "failure_domain",
            "operation_receipt",
        }
        if (
            not isinstance(audit, dict)
            or set(audit) != audit_fields
            or audit.get("schema_version") != "1.0"
            or not str(audit.get("provider") or "")
            or not str(audit.get("audit_event_id") or "")
            or audit.get("object_id") != drill["object_id"]
            or audit.get("ciphertext_sha256") != drill["ciphertext_sha256"]
            or audit.get("recovered_plaintext_sha256")
            != drill["recovered_plaintext_sha256"]
            or audit.get("wrapped_key_sha256") != custody["wrapped_key_sha256"]
            or audit.get("kms_unwrap_operation_id") != drill["kms_unwrap_operation_id"]
            or audit.get("hardware_backed") is not True
            or not _digest(str(drill["provider_audit_authority_key_sha256"]))
        ):
            raise ValueError("retained KMS provider audit event is invalid")
        audit_subject = {
            name: audit[name] for name in audit_fields if name != "operation_receipt"
        }
        audit_receipt = audit["operation_receipt"]
        audit_statement = (
            audit_receipt.get("statement") if isinstance(audit_receipt, dict) else None
        )
        try:
            audit_issued = datetime.fromisoformat(
                str((audit_statement or {})["issued_at"]).replace("Z", "+00:00")
            )
        except (KeyError, ValueError) as exc:
            raise ValueError("retained KMS provider audit time is invalid") from exc
        _reverify_operation(
            audit_subject,
            audit_receipt,
            "kms-unwrap-provider-audit",
            audit_issued,
            str(drill["provider_audit_authority_key_sha256"]),
        )
        readback = drill["provider_audit_readback"]
        readback_required = (
            os.environ.get(
                "PYSEC_RAW_EVIDENCE_PROVIDER_AUDIT_READBACK_REQUIRED", ""
            ).strip()
            == "1"
        )
        if readback_required and readback is None:
            raise ValueError("retained KMS provider audit readback is absent")
        if readback is not None:
            from .native_evidence import verify_retained_provider_audit_readback

            verify_retained_provider_audit_readback(
                readback,
                audit,
                verify_failure_domain(audit["failure_domain"], "KMS provider audit"),
                os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "")
                .strip()
                .casefold(),
            )
        recovery_attestation = drill["effective_policy_attestation"]
        recovery_attestation_subject = (
            recovery_attestation.get("subject")
            if isinstance(recovery_attestation, dict)
            else None
        )
        if (
            not isinstance(recovery_attestation, dict)
            or set(recovery_attestation) != {"subject", "operation_receipt"}
            or not isinstance(recovery_attestation_subject, dict)
        ):
            raise ValueError("retained recovery attestation is invalid")
        verify_effective_policy_subject(recovery_attestation_subject)
        remote = recovery_attestation_subject["policy_observations"][
            "remote_attestation"
        ]["subject"]
        recovery_domain = {
            name: remote[name]
            for name in (
                "organization",
                "host_identity_sha256",
                "control_plane_sha256",
                "implementation_sha256",
            )
        }
        if drill["execution_nonce"] != recovery_attestation_subject.get(
            "execution_nonce"
        ):
            raise ValueError("retained recovery execution binding is invalid")
        require_independent_failure_domains(
            recovery_domain,
            audit["failure_domain"],
            labels=("recovery executor", "KMS provider audit"),
        )
        recovery_attestation_receipt = (
            recovery_attestation.get("operation_receipt")
            if isinstance(recovery_attestation, dict)
            else None
        )
        recovery_attestation_statement = (
            recovery_attestation_receipt.get("statement")
            if isinstance(recovery_attestation_receipt, dict)
            else None
        )
        try:
            recovery_attestation_issued = datetime.fromisoformat(
                str((recovery_attestation_statement or {})["issued_at"]).replace(
                    "Z", "+00:00"
                )
            )
        except (KeyError, ValueError) as exc:
            raise ValueError("retained recovery attestation time is invalid") from exc
        _reverify_operation(
            recovery_attestation_subject,
            recovery_attestation_receipt,
            "pinned-command-effective-policy",
            recovery_attestation_issued,
            str(recovery_attestation_subject["attestor_key_sha256"]),
        )
    if not replayable and any(
        storage[name] is not None and storage[name] != ""
        for name in (
            "wrapped_data_key_base64",
            "custody_receipt",
            "custody_authority_receipt",
            "effective_policy_attestation",
            "recovery_drill",
        )
    ):
        raise ValueError("inline native evidence cannot claim key custody")
    expected = value.get("normalization_sha256")
    subject = {
        key: item for key, item in value.items() if key != "normalization_sha256"
    }
    if expected != hashlib.sha256(canonical_bytes(subject)).hexdigest():
        raise ValueError("normalized artifact digest does not match")


def _validate_custody_transport(custody: dict[str, Any]) -> None:
    context = custody.get("command_context")
    transcript = custody.get("transport_transcript")
    if not isinstance(context, dict) or set(context) != {
        "schema_version",
        "executable_sha256",
        "allowed_endpoints",
        "mtls_identity_sha256",
        "sandbox_identity_sha256",
        "sandbox_executable_sha256",
        "sandbox_launcher_argv",
        "effective_policy_attestor_key_sha256",
        "remote_attestation_key_sha256",
    }:
        raise ValueError("retained KMS command context is invalid")
    endpoints = context["allowed_endpoints"]
    launcher_argv = context["sandbox_launcher_argv"]
    expected_sandbox = hashlib.sha256(
        canonical_bytes(
            {
                "launcher_sha256": context["sandbox_executable_sha256"],
                "launcher_argv": launcher_argv,
                "allowed_endpoints": endpoints,
                "mtls_identity_sha256": context["mtls_identity_sha256"],
            }
        )
    ).hexdigest()
    if (
        not isinstance(endpoints, list)
        or endpoints != sorted(set(endpoints))
        or not endpoints
        or any(
            not isinstance(item, str) or not item.startswith("https://")
            for item in endpoints
        )
        or not isinstance(launcher_argv, list)
        or any(not isinstance(item, str) or not item for item in launcher_argv)
        or custody.get("sandbox_identity_sha256") != context["sandbox_identity_sha256"]
        or custody.get("allowed_endpoints_sha256")
        != hashlib.sha256(canonical_bytes(endpoints)).hexdigest()
        or custody.get("mtls_peer_identity_sha256") != context["mtls_identity_sha256"]
        or expected_sandbox != context["sandbox_identity_sha256"]
        or not isinstance(transcript, dict)
        or set(transcript)
        != {
            "endpoint",
            "peer_identity_sha256",
            "protocol",
            "cipher",
            "session_id",
        }
        or transcript.get("endpoint") not in endpoints
        or transcript.get("peer_identity_sha256") != context["mtls_identity_sha256"]
        or transcript.get("protocol") != "TLSv1.3"
        or not isinstance(transcript.get("cipher"), str)
        or not transcript["cipher"]
        or not isinstance(transcript.get("session_id"), str)
        or not 16 <= len(transcript["session_id"]) <= 200
        or custody.get("transport_transcript_sha256")
        != hashlib.sha256(canonical_bytes(transcript)).hexdigest()
    ):
        raise ValueError("retained KMS transport transcript is invalid")
