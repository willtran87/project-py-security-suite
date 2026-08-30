from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import uuid
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import timedelta
from typing import Any

from .version import __version__
from .adapters import ADAPTER_TYPES
from .adapters.base import AdapterResult, ScannerAdapter
from .application_contracts import analyze_application_contracts
from .config import SuiteConfig
from .closure_plan import closure_plan_artifact
from .code_health import analyze_code_health
from .correlation import correlate_findings
from .data_exposure import apply_data_exposure_fusion, build_data_exposure_synthesis
from .dependency_surface import dependency_surface_artifact
from .domain_assurance import analyze_domain_assurance
from .llm_adversarial import build_llm_adversarial_plan
from .finding_delta import apply_finding_delta
from .finding_validation import apply_finding_validation
from .framework_coverage import framework_model_coverage
from .governance import (
    validate_intelligence_approval,
    validate_isolation_evidence,
)
from .graph_analysis import apply_graph_context
from .effectiveness import assurance_claims_artifact, effectiveness_artifact
from .execution import python_runtime_closure_sha256, resolve_executable
from .evidence_fusion import build_evidence_fusion
from .inventory import (
    inventory_target_with_evidence,
    sealed_source_snapshot,
    source_snapshot,
)
from .industry_assurance import build_industry_assurance
from .industry_receipt_trust import load_industry_receipt_trust
from .isolation_probe import probe_isolation_boundary
from .models import (
    Finding,
    ScanManifest,
    ScanResult,
    ToolRun,
    ToolStatus,
    isoformat,
    utc_now,
    json_ready,
)
from .policy import evaluate_policy
from .admission import admission_decisions
from .advanced_analysis import build_advanced_analysis
from .architecture_history import architecture_history
from .boundary_graph import build_boundary_graph
from .capability_manifest import capability_manifest
from .portfolio_health import portfolio_health_artifact
from .path_safety import resolve_regular_directory, resolve_unlinked_path
from .reports import write_reports
from .risk_intelligence import enrich_findings
from .risk_paths import build_risk_paths
from .runtime_reachability import apply_runtime_trace_observations
from .runtime_surface import runtime_surface_binding_artifact
from .source_context import attach_source_context, sanitize_secret_findings
from .semantic_coverage import semantic_language_coverage_artifact
from .requirements_coverage import security_requirements_coverage_artifact
from .structural_synthesis import build_structural_synthesis
from .static_architecture import analyze_static_architecture
from .trust_catalog import apply_trust_catalog
from .trust_policy import activated_trust_environment, snapshot_trust_policy
from .trust_attestation import validate_trust_policy_attestation


_STRUCTURAL_QUALITY_PROFILES = frozenset(
    {"audit", "quality", "repo", "comprehensive", "production", "release"}
)


def scan_project(
    *,
    target: Path,
    output: Path,
    config: SuiteConfig,
    network_isolation_attested: bool,
    diagnostic_without_isolation: bool = False,
    adapter_types: Mapping[str, type[ScannerAdapter]] | None = None,
    replace_existing: bool = False,
) -> ScanResult:
    with activated_trust_environment(config.trust_environment):
        return _scan_project_active(
            target=target,
            output=output,
            config=config,
            network_isolation_attested=network_isolation_attested,
            diagnostic_without_isolation=diagnostic_without_isolation,
            adapter_types=adapter_types,
            replace_existing=replace_existing,
        )


def _scan_project_active(
    *,
    target: Path,
    output: Path,
    config: SuiteConfig,
    network_isolation_attested: bool,
    diagnostic_without_isolation: bool = False,
    adapter_types: Mapping[str, type[ScannerAdapter]] | None = None,
    replace_existing: bool = False,
) -> ScanResult:
    target = resolve_regular_directory(target, "scan target")
    output = resolve_unlinked_path(output, "report output")
    if not target.is_dir():
        raise ValueError(f"scan target is not a directory: {target}")
    if output.exists() and not replace_existing:
        raise ValueError(f"report output already exists: {output}")
    resolve_asset_paths(config, target)
    selected = list(config.selected_tools)
    source_exclusions = (output, *_runtime_evidence_paths(config, selected))
    inventory, source_inventory = inventory_target_with_evidence(
        target, excluded_paths=source_exclusions
    )
    with sealed_source_snapshot(
        target,
        source_inventory,
        vcs_revision=(
            inventory.vcs_revision if inventory.vcs_revision_verified else ""
        ),
        require_signed_git_provenance=config.profile in {"production", "release"},
    ) as scan_target:
        return _scan_sealed_project(
            target=target,
            scan_target=scan_target,
            output=output,
            config=config,
            network_isolation_attested=network_isolation_attested,
            diagnostic_without_isolation=diagnostic_without_isolation,
            adapter_types=adapter_types,
            replace_existing=replace_existing,
            selected=selected,
            source_exclusions=source_exclusions,
            inventory=inventory,
            source_inventory=source_inventory,
        )


def _scan_sealed_project(
    *,
    target: Path,
    scan_target: Path,
    output: Path,
    config: SuiteConfig,
    network_isolation_attested: bool,
    diagnostic_without_isolation: bool,
    adapter_types: Mapping[str, type[ScannerAdapter]] | None,
    replace_existing: bool,
    selected: list[str],
    source_exclusions: tuple[Path, ...],
    inventory: Any,
    source_inventory: dict[str, Any],
) -> ScanResult:
    """Execute every analysis stage against one verified read-only source copy."""
    started_at = utc_now()
    started_clock = time.monotonic()
    diagnostics: dict[str, dict[str, Any]] = {}
    derived_artifacts: dict[str, Any] = {}
    trust_policy = snapshot_trust_policy(config.trust_environment)
    derived_artifacts["trust-policy.json"] = trust_policy
    derived_artifacts["source-inventory.json"] = source_inventory
    derived_artifacts["report-security.json"] = {
        "schema_version": "1.0",
        "classification": config.reports.classification,
        "access_policy": "owner-only",
        "permission_postcondition": "verified-before-atomic-publication",
        "access_control_verification": (
            "exact-current-user-sid" if os.name == "nt" else "mode-0700-0600"
        ),
        "retention_days": config.reports.retention_days,
        "delete_after": isoformat(
            started_at + timedelta(days=config.reports.retention_days)
        ),
        "retention_enforcement": "verified-expiry-atomic-purge",
        "retention_time_authority": "rfc3161-deployment-pinned-timestamp",
        "encryption_support": "X25519-HKDF-SHA256+A256GCM authenticated archive",
        "key_custody": "external-recipient-private-key",
        "key_lifecycle_enforcement": "signed-provider-receipt-and-cryptographic-erasure",
        "plaintext_disposal": "optional-post-encryption-verified-purge",
    }
    derived_artifacts["dependency-surface.json"] = dependency_surface_artifact(
        scan_target
    )
    boundary_graph = build_boundary_graph(
        scan_target,
        require_governed_parsers=config.profile in {"production", "release"},
    )
    derived_artifacts["boundary-graph.json"] = boundary_graph
    from .runtime_trace import runtime_trace_artifact

    runtime_trace = runtime_trace_artifact(boundary_graph)
    derived_artifacts["runtime-trace-correlation.json"] = runtime_trace
    context_errors: list[str] = []
    if config.profile in {"production", "release"} and not runtime_trace["complete"]:
        context_errors.append(
            "signed deployment-bound runtime request-to-sink trace evidence is required"
        )
    if (
        config.profile in {"production", "release"}
        and config.organization_policy_present
        and not config.organization_policy_attestation_validated
    ):
        context_errors.append(
            "organization policy lacks signed anti-rollback quorum metadata"
        )
    trust_attestation = validate_trust_policy_attestation(
        config.trust,
        trust_policy,
        observed_at=started_at,
        trust_environment=config.trust_environment,
    )
    context_errors.extend(trust_attestation.errors)
    derived_artifacts["trust-policy-attestation.json"] = trust_attestation.artifact
    if config.profile in {"production", "release"} and not boundary_graph["complete"]:
        context_errors.append(
            "polyglot boundary analysis was truncated or could not parse every source file"
        )
    intelligence_artifact: dict[str, Any] = {}
    baseline_artifact: dict[str, Any] = {}
    trust = apply_trust_catalog(config)
    context_errors.extend(trust.errors)
    derived_artifacts["scanner-trust.json"] = trust.artifact
    isolation = validate_isolation_evidence(
        config.isolation,
        target_name=target.name,
        source_sha256=inventory.source_sha256,
        observed_at=started_at,
        trust_environment=config.trust_environment,
    )
    if network_isolation_attested:
        context_errors.extend(isolation.errors)
    elif config.isolation.require_evidence and not diagnostic_without_isolation:
        context_errors.append("approved external isolation evidence was not applied")
    derived_artifacts["isolation-attestation.json"] = isolation.artifact
    derived_artifacts["isolation-boundary.json"] = {
        "schema_version": "1.0",
        "mode": config.isolation.enforcement_mode,
        "network_policy": config.isolation.network,
        "sandbox_launcher_configured": bool(config.isolation.sandbox_executable),
        "sandbox_launcher_sha256": (config.isolation.sandbox_executable_sha256 or None),
        "sandbox_launcher_organization_approved": (
            config.isolation.sandbox_organization_approved
        ),
        "external_attestation_validated": bool(isolation.artifact.get("validated")),
    }
    isolation_probe, isolation_probe_errors = probe_isolation_boundary(
        scan_target,
        config.isolation,
        required=(
            config.profile in {"production", "release"}
            and network_isolation_attested
            and not diagnostic_without_isolation
        ),
    )
    derived_artifacts["isolation-probe.json"] = isolation_probe
    context_errors.extend(isolation_probe_errors)

    if (
        config.isolation.require_attestation
        and not network_isolation_attested
        and not diagnostic_without_isolation
    ):
        tool_runs = [
            ToolRun(
                tool=name,
                status=ToolStatus.SKIPPED,
                command=[config.tools[name].executable],
                duration_seconds=0.0,
                error="scan not started because network isolation was not attested",
            )
            for name in selected
        ]
        findings: list[Finding] = []
        diagnostics = {
            run.tool: {
                "tool": run.tool,
                "status": run.status,
                "error": run.error,
                "raw_output_retained": False,
            }
            for run in tool_runs
        }
    else:
        findings, tool_runs, diagnostics, adapter_artifacts = _run_adapters(
            target=scan_target,
            config=config,
            selected=selected,
            adapter_types=adapter_types or ADAPTER_TYPES,
        )
        _annotate_tool_authority(tool_runs, diagnostics, config)
        derived_artifacts.update(adapter_artifacts)
        semantic_coverage = semantic_language_coverage_artifact(
            boundary_graph, derived_artifacts
        )
        derived_artifacts["semantic-language-coverage.json"] = semantic_coverage
        if (
            config.profile in {"production", "release"}
            and not semantic_coverage["complete"]
        ):
            context_errors.append(
                "non-Python boundary extraction requires authenticated, source-bound, complete semantic polyglot evidence"
            )
        dependency_surface = dependency_surface_artifact(
            scan_target, tool_runs, derived_artifacts
        )
        derived_artifacts["dependency-surface.json"] = dependency_surface
        if (
            config.profile in {"production", "release"}
            and not dependency_surface["complete"]
        ):
            uncovered = ", ".join(
                item["ecosystem"]
                for item in dependency_surface["coverage"]
                if not item["covered"]
            )
            context_errors.append(
                "multi-ecosystem dependency analysis is incomplete for: " + uncovered
            )
        runtime_surface = runtime_surface_binding_artifact(tool_runs, derived_artifacts)
        derived_artifacts["runtime-surface-binding.json"] = runtime_surface
        if (
            config.profile in {"production", "release"}
            and not runtime_surface["complete"]
        ):
            context_errors.append(
                "runtime assurance lanes do not share one canonical surface context "
                "with independently corroborated clean claims"
            )
        reachability_feedback = apply_runtime_trace_observations(
            derived_artifacts.get("reachability.json"), runtime_trace, boundary_graph
        )
        if (
            config.profile in {"production", "release"}
            and runtime_trace["complete"]
            and not reachability_feedback["complete"]
        ):
            context_errors.append(
                "authenticated Python runtime traces could not be mapped back to exact reachability nodes"
            )
        framework_findings, framework_coverage = framework_model_coverage(
            scan_target, tool_runs, findings
        )
        qualified_canary_ids = set(framework_coverage["qualified_canary_finding_ids"])
        findings[:] = [
            finding
            for finding in findings
            if finding.finding_id not in qualified_canary_ids
        ]
        findings.extend(framework_findings)
        derived_artifacts["framework-model-coverage.json"] = framework_coverage
        if (
            config.profile in {"production", "release"}
            and not framework_coverage["complete"]
            and (
                framework_coverage["frameworks_detected"]
                or framework_coverage["parse_errors"]
            )
        ):
            context_errors.append(
                "detected Python frameworks lack digest-bound semantic models, positive/negative canaries, or a completed model engine"
            )
        contract_findings, contract_artifact = analyze_application_contracts(
            scan_target, derived_artifacts
        )
        findings.extend(contract_findings)
        derived_artifacts["application-contract-analysis.json"] = contract_artifact
        if (
            config.profile in {"production", "release"}
            and not contract_artifact["complete"]
            and (
                contract_artifact["contract_present"]
                or contract_artifact["openapi"]["current_path"]
            )
        ):
            context_errors.append(
                "application contracts contain API drift, missing authorization test evidence, vulnerable-function calls, or analysis errors"
            )
        if config.profile in _STRUCTURAL_QUALITY_PROFILES:
            code_health_findings, code_health_artifact = analyze_code_health(
                scan_target
            )
            findings.extend(code_health_findings)
            derived_artifacts["code-health.json"] = code_health_artifact
            static_architecture_findings, static_architecture_artifact = (
                analyze_static_architecture(
                    scan_target, derived_artifacts.get("reachability.json")
                )
            )
            findings.extend(static_architecture_findings)
            derived_artifacts["static-architecture.json"] = static_architecture_artifact
            architecture_findings, architecture_artifact = architecture_history(
                scan_target, findings
            )
            findings.extend(architecture_findings)
            derived_artifacts["architecture-history.json"] = architecture_artifact
        domain_findings, domain_artifact = analyze_domain_assurance(
            scan_target, derived_artifacts
        )
        findings.extend(domain_findings)
        derived_artifacts["domain-assurance.json"] = domain_artifact
        sanitize_secret_findings(findings)
        findings = correlate_findings(findings)
        intelligence = enrich_findings(findings, config.intelligence)
        context_errors.extend(intelligence.errors)
        intelligence_artifact = intelligence.artifact
        derived_artifacts["risk-intelligence.json"] = intelligence.artifact
        intelligence_approval = validate_intelligence_approval(
            config.intelligence,
            intelligence.artifact,
            observed_at=started_at,
            trust_environment=config.trust_environment,
        )
        context_errors.extend(intelligence_approval.errors)
        derived_artifacts["intelligence-approval.json"] = intelligence_approval.artifact
        delta = apply_finding_delta(
            findings,
            target=scan_target,
            baseline_path=config.reports.baseline_path,
            baseline_sha256=config.reports.baseline_sha256,
            current_profile=config.profile,
            current_tools=tuple(selected),
            current_source_sha256=inventory.source_sha256,
            current_vcs_revision=inventory.vcs_revision,
        )
        context_errors.extend(delta.errors)
        baseline_artifact = delta.artifact
        derived_artifacts["finding-delta.json"] = delta.artifact
        attach_source_context(scan_target, findings)
        graph_analysis = apply_graph_context(findings, derived_artifacts)
        if graph_analysis is not None:
            derived_artifacts["graph-analysis.json"] = graph_analysis
        structural_synthesis = build_structural_synthesis(findings, derived_artifacts)
        if structural_synthesis is not None:
            derived_artifacts["structural-synthesis.json"] = structural_synthesis
        derived_artifacts["data-exposure.json"] = build_data_exposure_synthesis(
            scan_target, findings, derived_artifacts
        )
        fusion = build_evidence_fusion(findings, derived_artifacts, tool_runs)
        derived_artifacts["evidence-fusion.json"] = fusion
        apply_data_exposure_fusion(
            derived_artifacts["data-exposure.json"], findings, fusion
        )
        derived_artifacts["effectiveness.json"] = effectiveness_artifact(
            findings, tool_runs
        )
        derived_artifacts["risk-paths.json"] = build_risk_paths(
            findings, derived_artifacts
        )
        derived_artifacts["advanced-analysis.json"] = build_advanced_analysis(
            scan_target, findings, derived_artifacts
        )
        derived_artifacts["finding-validation.json"] = apply_finding_validation(
            findings, derived_artifacts
        )
        context_errors.extend(
            (
                "evidence fusion contradiction for "
                f"{contradiction['finding_id']}: {contradiction['message']}"
            )
            for contradiction in fusion["contradictions"]
        )

    resource_assurance = _resource_limit_assurance(
        tool_runs,
        diagnostics,
        isolation.artifact,
        require_external_quota=config.profile in {"production", "release"},
    )
    derived_artifacts["resource-limits.json"] = resource_assurance
    if (
        config.profile in {"production", "release"}
        and not resource_assurance["complete"]
    ):
        context_errors.append(
            "OS resource limits were not proven for every executed scanner"
        )
    runtime_assurance = _runtime_closure_assurance(config, diagnostics)
    derived_artifacts["runtime-closure.json"] = runtime_assurance
    if (
        config.profile in {"production", "release"}
        and not runtime_assurance["complete"]
    ):
        context_errors.append(
            "the complete Python scanner runtime closure was not stable"
        )

    derived_artifacts["capability-manifest.json"] = capability_manifest(
        config.profile, tool_runs
    )

    if "framework-model-coverage.json" not in derived_artifacts:
        framework_findings, framework_coverage = framework_model_coverage(
            scan_target, tool_runs, findings
        )
        qualified_canary_ids = set(framework_coverage["qualified_canary_finding_ids"])
        findings[:] = [
            finding
            for finding in findings
            if finding.finding_id not in qualified_canary_ids
        ]
        findings.extend(framework_findings)
        derived_artifacts["framework-model-coverage.json"] = framework_coverage
    if "application-contract-analysis.json" not in derived_artifacts:
        contract_findings, contract_artifact = analyze_application_contracts(
            scan_target, derived_artifacts
        )
        findings.extend(contract_findings)
        derived_artifacts["application-contract-analysis.json"] = contract_artifact
    if (
        config.profile in _STRUCTURAL_QUALITY_PROFILES
        and "code-health.json" not in derived_artifacts
    ):
        code_health_findings, code_health_artifact = analyze_code_health(scan_target)
        findings.extend(code_health_findings)
        derived_artifacts["code-health.json"] = code_health_artifact
    if (
        config.profile in _STRUCTURAL_QUALITY_PROFILES
        and "static-architecture.json" not in derived_artifacts
    ):
        static_architecture_findings, static_architecture_artifact = (
            analyze_static_architecture(
                scan_target, derived_artifacts.get("reachability.json")
            )
        )
        findings.extend(static_architecture_findings)
        derived_artifacts["static-architecture.json"] = static_architecture_artifact
    if (
        config.profile in _STRUCTURAL_QUALITY_PROFILES
        and "architecture-history.json" not in derived_artifacts
    ):
        architecture_findings, architecture_artifact = architecture_history(
            scan_target, findings
        )
        findings.extend(architecture_findings)
        derived_artifacts["architecture-history.json"] = architecture_artifact
    if "domain-assurance.json" not in derived_artifacts:
        domain_findings, domain_artifact = analyze_domain_assurance(
            scan_target, derived_artifacts
        )
        findings.extend(domain_findings)
        derived_artifacts["domain-assurance.json"] = domain_artifact
    domain_assurance = derived_artifacts["domain-assurance.json"]
    if (
        config.profile in {"production", "release"}
        and isinstance(domain_assurance, dict)
        and domain_assurance.get("policy_present") is True
        and (
            domain_assurance.get("complete") is not True
            or (
                domain_assurance.get("enforce_inferred_domains") is True
                and domain_assurance.get("coverage_complete") is not True
            )
        )
    ):
        context_errors.append(
            "declared cross-domain assurance policy is incomplete or has uncovered applicable domains"
        )
    if "effectiveness.json" not in derived_artifacts:
        _annotate_tool_authority(tool_runs, diagnostics, config)
        derived_artifacts["effectiveness.json"] = effectiveness_artifact(
            findings, tool_runs
        )
    if "finding-validation.json" not in derived_artifacts:
        derived_artifacts["finding-validation.json"] = apply_finding_validation(
            findings, derived_artifacts
        )
    if "runtime-surface-binding.json" not in derived_artifacts:
        derived_artifacts["runtime-surface-binding.json"] = (
            runtime_surface_binding_artifact(tool_runs, derived_artifacts)
        )
    if "semantic-language-coverage.json" not in derived_artifacts:
        derived_artifacts["semantic-language-coverage.json"] = (
            semantic_language_coverage_artifact(boundary_graph, derived_artifacts)
        )
    requirements_coverage = security_requirements_coverage_artifact(
        boundary_graph, tool_runs, derived_artifacts
    )
    derived_artifacts["security-requirements-coverage.json"] = requirements_coverage
    if (
        config.profile in {"production", "release"}
        and not requirements_coverage["automation_complete"]
    ):
        context_errors.append(
            "applicable mapped ASVS, MASVS, or TCASVS controls lack retained evidence"
        )
    llm_adversarial_plan, llm_adversarial_errors = build_llm_adversarial_plan(
        scan_target, findings, derived_artifacts
    )
    derived_artifacts["llm-adversarial-plan.json"] = llm_adversarial_plan
    if (
        config.profile in {"production", "release"}
        and llm_adversarial_plan["policy_present"] is True
        and llm_adversarial_plan["complete"] is not True
    ):
        reasons = llm_adversarial_errors or ["plan is truncated or incomplete"]
        context_errors.extend(f"LLM adversarial planning: {error}" for error in reasons)
    receipt_trust_policy, receipt_trust_errors = load_industry_receipt_trust(
        scan_target
    )
    industry_artifacts, industry_errors = build_industry_assurance(
        scan_target,
        derived_artifacts,
        findings,
        receipt_trust_policy=receipt_trust_policy,
    )
    industry_errors = [*receipt_trust_errors, *industry_errors]
    derived_artifacts.update(industry_artifacts)
    control_assessment = industry_artifacts["control-assessment.json"]
    benchmark_scorecard = industry_artifacts["benchmark-scorecard.json"]
    if config.profile in {"production", "release"} and industry_errors:
        context_errors.extend(
            f"industry assurance: {error}" for error in industry_errors
        )
    if (
        config.profile in {"production", "release"}
        and control_assessment["enforced"] is True
        and control_assessment["complete"] is not True
    ):
        context_errors.append(
            "enforced industry control assessment contains unsatisfied controls"
        )
    if (
        config.profile in {"production", "release"}
        and benchmark_scorecard["benchmarks_enabled"]
        and (
            benchmark_scorecard["complete"] is not True
            or benchmark_scorecard["passed"] is not True
        )
    ):
        context_errors.append(
            "enabled industry benchmarks lack valid passing governed evidence"
        )
    if config.profile in {"production", "release"} and _has_local_monotonic_receipt(
        derived_artifacts
    ):
        context_errors.append(
            "deployment authority generations require an external monotonic CAS backend"
        )
    if config.profile in {"production", "release"}:
        anchored_state = (
            "PYSEC_OPERATION_RECEIPT_STATE_PATH",
            "PYSEC_OPERATION_RECEIPT_MIN_SEQUENCE",
            "PYSEC_OPERATION_RECEIPT_CHECKPOINT_SHA256",
            "PYSEC_TRUSTED_TIME_STATE_PATH",
            "PYSEC_TRUSTED_TIME_MIN_SEQUENCE",
            "PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256",
        )
        missing_state = [name for name in anchored_state if not os.environ.get(name)]
        if missing_state:
            context_errors.append(
                "production replay and trusted-time state lacks deployment anchors: "
                + ", ".join(missing_state)
            )
        external_checkpoints = (
            (
                "PYSEC_OPERATION_RECEIPT_CHECKPOINT",
                "PYSEC_OPERATION_RECEIPT_REQUIRE_EXTERNAL_CHECKPOINT",
            ),
            (
                "PYSEC_TRUSTED_TIME_CHECKPOINT",
                "PYSEC_TRUSTED_TIME_REQUIRE_EXTERNAL_CHECKPOINT",
            ),
        )
        missing_external = [
            prefix
            for prefix, required_name in external_checkpoints
            if os.environ.get(required_name) != "1"
            or not os.environ.get(f"{prefix}_COMMAND_JSON")
            or not os.environ.get(f"{prefix}_AUTHORITY_KEY_SHA256")
            or not os.environ.get(f"{prefix}_FAILURE_DOMAIN_JSON")
        ]
        if missing_external:
            context_errors.append(
                "production monotonic state lacks independently attested external "
                "checkpoint authorities: " + ", ".join(missing_external)
            )
        else:
            try:
                from .failure_domain import require_independent_failure_domains
                from .strict_json import loads as strict_loads

                operation_domain = strict_loads(
                    os.environ["PYSEC_OPERATION_RECEIPT_CHECKPOINT_FAILURE_DOMAIN_JSON"]
                )
                time_domain = strict_loads(
                    os.environ["PYSEC_TRUSTED_TIME_CHECKPOINT_FAILURE_DOMAIN_JSON"]
                )
                require_independent_failure_domains(
                    operation_domain,
                    time_domain,
                    labels=(
                        "operation checkpoint authority",
                        "trusted-time checkpoint authority",
                    ),
                )
            except (KeyError, TypeError, ValueError):
                context_errors.append(
                    "production checkpoint authorities do not span independent "
                    "organization, host, control-plane, and implementation domains"
                )

    (
        inventory.source_sha256_after,
        inventory.hashed_files_after,
        inventory.hashed_bytes_after,
    ) = source_snapshot(target, excluded_paths=source_exclusions)
    snapshot_after = source_snapshot(scan_target)
    snapshot_integrity_verified = snapshot_after == (
        inventory.source_sha256,
        inventory.hashed_files,
        inventory.hashed_bytes,
    )
    if not snapshot_integrity_verified:
        context_errors.append("sealed scan snapshot changed during scanner execution")
    if inventory.skipped_symlinks:
        context_errors.append(
            f"source inventory rejected {inventory.skipped_symlinks} symbolic link(s)"
        )
    inventory.source_integrity_verified = (
        inventory.source_sha256 == inventory.source_sha256_after
        and inventory.hashed_files == inventory.hashed_files_after
        and inventory.hashed_bytes == inventory.hashed_bytes_after
        and snapshot_integrity_verified
        and inventory.skipped_symlinks == 0
    )

    decision = evaluate_policy(
        config=config,
        findings=findings,
        tool_runs=tool_runs,
        network_isolation_attested=network_isolation_attested,
        inventory=inventory,
        context_errors=context_errors,
    )
    derived_artifacts["assurance-claims.json"] = assurance_claims_artifact(
        findings,
        tool_runs,
        source_integrity=inventory.source_integrity_verified,
        context_errors=context_errors,
        network_isolation_attested=network_isolation_attested,
    )
    derived_artifacts["portfolio-health.json"] = portfolio_health_artifact(
        findings,
        tool_runs,
        outcome=decision.outcome,
        policy_reasons=decision.reasons,
    )
    derived_artifacts["admission-decisions.json"] = admission_decisions(
        findings,
        tool_runs,
        network_isolation_attested=network_isolation_attested,
        source_integrity_verified=inventory.source_integrity_verified,
    )
    finished_at = utc_now()
    duration = round(time.monotonic() - started_clock, 3)
    counts = {
        severity: 0
        for severity in (
            "critical",
            "high",
            "medium",
            "low",
            "informational",
            "unknown",
        )
    }
    for finding in findings:
        counts[finding.severity.value] += 1

    manifest = ScanManifest(
        schema_version="1.0",
        suite_version=__version__,
        scan_id=f"scan-{uuid.uuid4()}",
        target=target.name,
        profile=config.profile,
        outcome=decision.outcome,
        started_at=isoformat(started_at),
        finished_at=isoformat(finished_at),
        duration_seconds=duration,
        network_policy=config.isolation.network,
        network_isolation_attested=network_isolation_attested,
        execute_target_code=config.isolation.execute_target_code,
        inventory=inventory,
        tools=tool_runs,
        finding_counts=counts,
        policy_reasons=decision.reasons,
        diagnostic_without_isolation=diagnostic_without_isolation,
        configuration_sha256=_configuration_digest(
            config, trust_policy_sha256=trust_policy["policy_sha256"]
        ),
        risk_acceptance_sha256=config.policy.risk_acceptance_sha256,
        intelligence=intelligence_artifact,
        baseline=baseline_artifact,
    )
    derived_artifacts["closure-plan.json"] = closure_plan_artifact(
        manifest,
        findings,
        derived_artifacts,
    )
    write_reports(
        output=output,
        findings=findings,
        manifest=manifest,
        diagnostics=diagnostics,
        include_evidence=config.reports.include_sanitized_evidence,
        derived_artifacts=derived_artifacts,
        replace_existing=replace_existing,
    )
    return ScanResult(
        outcome=decision.outcome,
        findings=findings,
        tool_runs=tool_runs,
        manifest=manifest,
    )


def _resource_limit_assurance(
    tool_runs: list[ToolRun],
    diagnostics: dict[str, dict[str, Any]],
    isolation: dict[str, Any],
    *,
    require_external_quota: bool,
) -> dict[str, Any]:
    external_capabilities = set(isolation.get("capabilities") or [])
    external = isolation.get("validated") is True and {
        "resource-limits",
        "file-write-quota",
    }.issubset(external_capabilities)
    required = (
        {
            "kill-on-close",
            "process-count",
            "process-memory",
            "job-memory",
            "cpu-time",
            "cpu-rate",
            "pre-execution-assignment",
            "bounded-output-pipes",
            "bounded-private-scratch",
        }
        if os.name == "nt"
        else {
            "resident-memory-watchdog" if sys.platform == "darwin" else "address-space",
            "process-count",
            "open-files",
            "file-size",
            "cpu-time",
            "pre-execution-assignment",
            "bounded-output-pipes",
            "bounded-private-scratch",
        }
    )
    scanners: list[dict[str, Any]] = []
    for run in tool_runs:
        if run.status is not ToolStatus.COMPLETED:
            continue
        diagnostic = diagnostics.get(run.tool, {})
        enforced = set(diagnostic.get("resource_limits_enforced") or [])
        errors = list(diagnostic.get("resource_limit_errors") or [])
        locally_complete = required.issubset(enforced) and not errors
        scanners.append(
            {
                "tool": run.tool,
                "local_limits": sorted(enforced),
                "local_errors": errors,
                "external_containment": external,
                "covered": locally_complete
                and (external or not require_external_quota),
            }
        )
    return {
        "schema_version": "1.0",
        "analysis": "os-enforced-scanner-resource-limits",
        "required_local_limits": sorted(required),
        "external_containment_validated": external,
        "external_file_write_quota_required": require_external_quota,
        "scanners": scanners,
        "complete": all(item["covered"] for item in scanners),
    }


def _runtime_closure_assurance(
    config: SuiteConfig, diagnostics: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    governed = {
        name: str(value.get("runtime_closure_sha256") or "")
        for name, value in diagnostics.items()
        if value.get("runtime_closure_sha256")
        and config.tools[name].runtime_closure_scope == "environment"
    }
    if not governed:
        return {
            "schema_version": "1.0",
            "scope": "complete-python-and-native-environment",
            "applicable": False,
            "complete": True,
            "tools": [],
        }
    first = next(iter(governed))
    executable = resolve_executable(config.tools[first].executable)
    observed_after: str | None = None
    error = ""
    try:
        if executable is None:
            raise ValueError("scanner executable could not be resolved after execution")
        observed_after = python_runtime_closure_sha256(
            executable, include_environment=True, refresh=True
        )
    except (OSError, TypeError, ValueError) as exc:
        error = str(exc)
    stable = bool(observed_after) and all(
        digest == observed_after for digest in governed.values()
    )
    for name in governed:
        diagnostics[name]["runtime_closure_unchanged"] = stable
    return {
        "schema_version": "1.0",
        "scope": "complete-python-and-native-environment",
        "applicable": True,
        "tools": sorted(governed),
        "before_sha256": sorted(set(governed.values())),
        "after_sha256": observed_after,
        "error": error or None,
        "complete": stable,
    }


def _annotate_tool_authority(
    tool_runs: list[ToolRun],
    diagnostics: dict[str, dict[str, Any]],
    config: SuiteConfig,
) -> None:
    """Keep digest matching distinct from organization authorization."""
    for run in tool_runs:
        tool = config.tools[run.tool]
        run.executable_organization_approved = tool.executable_organization_approved
        run.auxiliary_executable_organization_approved = (
            tool.auxiliary_executable_organization_approved
        )
        diagnostic = diagnostics.get(run.tool)
        if diagnostic is not None:
            diagnostic["executable_organization_approved"] = (
                run.executable_organization_approved
            )
            diagnostic["auxiliary_executable_organization_approved"] = (
                run.auxiliary_executable_organization_approved
            )


def resolve_asset_paths(config: SuiteConfig, target: Path) -> None:
    """Resolve repository-relative offline assets against the scan target."""
    configured_bundle = config.paths.bundle_root
    bundle_candidate = (
        configured_bundle
        if configured_bundle.is_absolute()
        else target / configured_bundle
    )
    bundle_root = resolve_unlinked_path(
        bundle_candidate,
        "offline scanner bundle root",
        boundary=target if not configured_bundle.is_absolute() else None,
    )
    config.paths.bundle_root = bundle_root
    for tool_name, tool in config.tools.items():
        for setting in ("executable", "auxiliary_executable"):
            value = getattr(tool, setting)
            if _is_bundle_reference(value):
                setattr(
                    tool,
                    setting,
                    str(
                        _resolve_bundle_reference(
                            value,
                            bundle_root=bundle_root,
                            label=f"{tool_name} {setting}",
                        )
                    ),
                )
        for setting in (
            "rules_path",
            "database_path",
            "public_key_path",
            "artifacts_path",
            "provenance_path",
        ):
            value = getattr(tool, setting)
            if value is not None:
                serialized = str(value)
                if _is_bundle_reference(serialized):
                    resolved = _resolve_bundle_reference(
                        serialized,
                        bundle_root=bundle_root,
                        label=f"{tool_name} {setting}",
                    )
                    setattr(tool, setting, resolved)
                    continue
                setattr(
                    tool,
                    setting,
                    _resolve_configured_path(
                        value,
                        target=target,
                        bundle_root=bundle_root,
                        label=f"{tool_name} {setting}",
                    ),
                )
    acceptance = config.policy.risk_acceptance_path
    if acceptance is not None:
        config.policy.risk_acceptance_path = _resolve_configured_path(
            acceptance,
            target=target,
            bundle_root=bundle_root,
            label="risk-acceptance file",
        )
    baseline = config.reports.baseline_path
    if baseline is not None:
        config.reports.baseline_path = _resolve_configured_path(
            baseline,
            target=target,
            bundle_root=bundle_root,
            label="baseline",
        )
    for setting in ("kev_path", "epss_path", "vex_path"):
        value = getattr(config.intelligence, setting)
        if value is not None:
            setattr(
                config.intelligence,
                setting,
                _resolve_configured_path(
                    value,
                    target=target,
                    bundle_root=bundle_root,
                    label=f"{setting} snapshot",
                ),
            )
    approval = config.intelligence.approval_path
    if approval is not None:
        config.intelligence.approval_path = _resolve_configured_path(
            approval,
            target=target,
            bundle_root=bundle_root,
            label="intelligence approval",
        )
    isolation = config.isolation.evidence_path
    if isolation is not None:
        config.isolation.evidence_path = _resolve_configured_path(
            isolation,
            target=target,
            bundle_root=bundle_root,
            label="isolation evidence",
        )
    trust_catalog = config.trust.catalog_path
    if trust_catalog is not None:
        config.trust.catalog_path = _resolve_configured_path(
            trust_catalog,
            target=target,
            bundle_root=bundle_root,
            label="scanner trust catalog",
        )
    trust_policy = config.trust.policy_path
    if trust_policy is not None:
        config.trust.policy_path = _resolve_configured_path(
            trust_policy,
            target=target,
            bundle_root=bundle_root,
            label="execution trust policy attestation",
        )


def _runtime_evidence_paths(
    config: SuiteConfig, selected: list[str]
) -> tuple[Path, ...]:
    paths: set[Path] = set()
    for name in ("coverage", "junit", "hypothesis", "schemathesis", "diff-cover"):
        if name not in selected or name not in config.tools:
            continue
        path = config.tools[name].artifacts_path
        if path is None:
            continue
        resolved = path.resolve()
        paths.add(resolved)
        paths.add(resolved.with_name(resolved.name + ".pysec-binding.json"))
    reachability = config.tools.get("reachability")
    if "reachability" in selected and reachability is not None:
        path = reachability.coverage_path
        if path is not None:
            paths.add(path.resolve())
    return tuple(sorted(paths, key=str))


def _is_bundle_reference(value: str) -> bool:
    normalized = value.replace("\\", "/")
    return normalized == "@bundle" or normalized.startswith("@bundle/")


def _resolve_bundle_reference(
    value: str,
    *,
    bundle_root: Path,
    label: str,
) -> Path:
    normalized = value.replace("\\", "/")
    relative_text = normalized.removeprefix("@bundle/")
    if normalized == "@bundle" or not relative_text:
        raise ValueError(f"{label} must name a path below @bundle/")
    relative = Path(relative_text)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} cannot traverse outside @bundle/")
    return resolve_unlinked_path(
        bundle_root / relative,
        label,
        boundary=bundle_root,
    )


def _resolve_configured_path(
    value: Path,
    *,
    target: Path,
    bundle_root: Path,
    label: str,
) -> Path:
    serialized = str(value)
    if _is_bundle_reference(serialized):
        return _resolve_bundle_reference(
            serialized,
            bundle_root=bundle_root,
            label=label,
        )
    candidate = value if value.is_absolute() else target / value
    return resolve_unlinked_path(candidate, label, boundary=target)


def _configuration_digest(config: SuiteConfig, *, trust_policy_sha256: str = "") -> str:
    payload = json.dumps(
        {
            "configuration": json_ready(config),
            "trust_policy_sha256": trust_policy_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _run_adapters(
    *,
    target: Path,
    config: SuiteConfig,
    selected: list[str],
    adapter_types: Mapping[str, type[ScannerAdapter]],
) -> tuple[
    list[Finding],
    list[ToolRun],
    dict[str, dict[str, Any]],
    dict[str, Any],
]:
    results: dict[str, AdapterResult] = {}
    skipped: dict[str, AdapterResult] = {}
    runnable: dict[str, ScannerAdapter] = {}
    for name in selected:
        tool_config = config.tools[name]
        if not tool_config.enabled:
            run = ToolRun(
                tool=name,
                status=ToolStatus.SKIPPED,
                command=[tool_config.executable],
                duration_seconds=0.0,
                error="scanner disabled by configuration",
            )
            skipped[name] = AdapterResult(
                findings=[],
                tool_run=run,
                diagnostic={
                    "tool": name,
                    "status": run.status,
                    "error": run.error,
                    "raw_output_retained": False,
                },
            )
            continue
        adapter_type = adapter_types.get(name)
        if adapter_type is None:
            run = ToolRun(
                tool=name,
                status=ToolStatus.UNAVAILABLE,
                command=[tool_config.executable],
                duration_seconds=0.0,
                error="adapter is not implemented",
            )
            skipped[name] = AdapterResult(
                findings=[],
                tool_run=run,
                diagnostic={
                    "tool": name,
                    "status": run.status,
                    "error": run.error,
                    "raw_output_retained": False,
                },
            )
            continue
        runnable[name] = adapter_type(tool_config, config.execution.max_output_bytes)

    with ThreadPoolExecutor(
        max_workers=min(config.execution.max_workers, max(len(runnable), 1)),
        thread_name_prefix="pysec",
    ) as executor:
        futures = {
            executor.submit(adapter.run, target): name
            for name, adapter in runnable.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            # Scanner adapters are an isolation boundary: convert every failure into
            # an explicit tool result so one adapter cannot abort the whole scan.
            except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
                run = ToolRun(
                    tool=name,
                    status=ToolStatus.FAILED,
                    command=[config.tools[name].executable],
                    duration_seconds=0.0,
                    error=f"unhandled adapter failure: {type(exc).__name__}",
                )
                results[name] = AdapterResult(
                    findings=[],
                    tool_run=run,
                    diagnostic={
                        "tool": name,
                        "status": run.status,
                        "error": run.error,
                        "raw_output_retained": False,
                    },
                )

    results.update(skipped)
    ordered = [results[name] for name in selected]
    findings = [finding for result in ordered for finding in result.findings]
    tool_runs = [result.tool_run for result in ordered]
    diagnostics = {result.tool_run.tool: result.diagnostic for result in ordered}
    artifacts = {
        name: value for result in ordered for name, value in result.artifacts.items()
    }
    return findings, tool_runs, diagnostics, artifacts


def _has_local_monotonic_receipt(value: object) -> bool:
    if isinstance(value, dict):
        state = value.get("monotonic_state")
        if isinstance(state, dict) and state.get("mode") == "local-sqlite":
            return True
        return any(_has_local_monotonic_receipt(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_local_monotonic_receipt(item) for item in value)
    return False
