from __future__ import annotations

from importlib.resources import files
import hashlib
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from .strict_json import loads as strict_loads
from .strict_json import canonical_bytes


_ARTIFACT_SCHEMAS = {
    "admission-decisions.json": "admission-decisions.schema.json",
    "advanced-analysis.json": "advanced-analysis.schema.json",
    "artifact-manifest.json": "artifact-manifest.schema.json",
    "artifact-sbom.cdx.json": "cyclonedx-artifact.schema.json",
    "assurance-claims.json": "assurance-claims-1.1.schema.json",
    "boundary-graph.json": "boundary-graph-1.0.schema.json",
    "closure-plan.json": "closure-plan.schema.json",
    "data-exposure.json": "data-exposure-1.5.schema.json",
    "dependency-surface.json": "dependency-surface-1.1.schema.json",
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
    "checkov-iac.json": "checkov-artifact.schema.json",
    "coverage-summary.json": "coverage-artifact.schema.json",
    "junit-summary.json": "test-summary-artifact.schema.json",
    "kics-iac.json": "kics-artifact.schema.json",
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
    "runtime-trace-correlation.json": "runtime-trace-correlation-1.0.schema.json",
    "semantic-language-coverage.json": "semantic-language-coverage-1.0.schema.json",
    "security-requirements-coverage.json": "security-requirements-coverage-1.0.schema.json",
    "source-inventory.json": "source-inventory.schema.json",
    "structural-synthesis.json": "structural-synthesis-1.2.schema.json",
    "trust-policy-attestation.json": "trust-policy-attestation-1.0.schema.json",
    "trust-policy.json": "trust-policy-1.0.schema.json",
}


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
        if name == "security-requirements-coverage.json":
            _validate_requirements_crosswalk(value)
        elif name == "checkov-iac.json":
            _validate_checkov_accounting(value)
        elif name == "git-sizer.json":
            _validate_git_sizer_accounting(value)
        elif name == "pipdeptree-summary.json":
            _validate_pipdeptree_accounting(value)
        validated[name] = schema_name
    return validated


def _is_companion_assurance(value: object) -> bool:
    return bool(
        isinstance(value, dict)
        and value.get("schema_version") == "2.0"
        and isinstance(value.get("evidence_binding"), dict)
        and isinstance(value.get("execution"), dict)
        and isinstance(value.get("kind"), str)
    )


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
        )
    ):
        raise ValueError("encrypted native report storage receipt is incomplete")
    expected = value.get("normalization_sha256")
    subject = {
        key: item for key, item in value.items() if key != "normalization_sha256"
    }
    if expected != hashlib.sha256(canonical_bytes(subject)).hexdigest():
        raise ValueError("normalized artifact digest does not match")
