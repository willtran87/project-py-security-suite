from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .cli_parser import build_parser as build_parser
from .cli_scan import progress_sink
from .cli_recovery import recovery_command
from .scan_control import ScanControl, controlled_scan
from .adapter_conformance import (
    assess_adapter_conformance,
    render_adapter_conformance,
)
from .advanced_delta import compare_advanced_analysis, render_advanced_delta_markdown
from .baseline_candidate import build_baseline_candidate
from .bundle_qualification import (
    qualify_bundle,
    render_bundle_qualification,
    render_bundle_qualification_markdown,
)
from .audit_package import create_audit_package, verify_audit_package
from .audience_report import build_audience_report, render_audience_markdown
from .ci_workflow import build_github_workflow, render_workflow_receipt
from .closure_plan import build_closure_plan, render_closure_plan_markdown
from .config import ConfigurationError, PROFILE_TOOLS, load_config
from .config_advisor import (
    advise_configuration,
    render_config_advice,
    render_config_advice_markdown,
)
from .config_provenance import build_config_provenance
from .confidential_archive import decrypt_report, encrypt_report
from .report_retention import purge_verified_report, retention_status
from .doctor import assess_readiness, render_readiness, render_readiness_markdown
from .evidence_draft import build_governance_evidence_draft
from .evidence_pack import create_evidence_pack, verify_evidence_pack
from .finding_register import build_finding_register
from .github_annotations import build_github_annotations, render_github_commands
from .effectiveness_corpus import evaluate_report_corpus
from .benchmark_execution import execute_benchmark_manifest
from .benchmark_runtime import (
    BenchmarkRuntimeError,
    probe_oci_runtime_capabilities,
)
from .benchmark_compiler import compile_benchmark_manifest
from .benchmark_adapters import benchmark_execution_contracts
from .benchmark_signing import (
    ExternalEd25519SigningProvider,
    load_external_signing_provider_profile,
    verify_signing_provider_conformance,
)
from .benchmark_telemetry import (
    DurableJsonlSecurityEventSink,
    verify_durable_security_event_log,
)
from .path_safety import read_regular_file
from .assurance_catalog import (
    build_standards_source_manifest,
    export_assurance_catalog,
)
from .execution import sanitize_terminal_text
from .native_bundle import (
    render_native_bundle_verification,
    render_native_bundle_verification_markdown,
    verify_native_bundle,
)
from .orchestrator import scan_project
from .operational_trend import (
    build_operational_trend,
    render_operational_trend_markdown,
)
from .policy import exit_code
from .policy_simulation import simulate_policy
from .precommit_config import build_precommit_config, render_precommit_receipt
from .project_init import (
    build_init_receipt,
    project_profile,
    render_init_receipt,
    render_project_config,
)
from .provisioning import (
    build_provision_plan,
    render_provision_plan,
    render_provision_plan_markdown,
)
from .portfolio_dashboard import build_portfolio_dashboard
from .promotion import (
    build_promotion_plan,
    render_promotion_html,
    render_promotion_markdown,
)
from .coverage_merge import merge_coverage_scenarios
from .passport import (
    create_attestation,
    sign_release_artifacts,
    verify_attestation,
    verify_report,
)
from .path_safety import resolve_regular_directory, resolve_unlinked_path
from .report_inspection import (
    inspect_report,
    read_bundled_schema,
    report_verification_receipt,
    render_inspection,
    verify_inspection,
)
from .reports import is_complete_report
from .reachability import analyze_project
from .reachability_delta import compare_reachability
from .release_payload import prepare_signing_request, verify_signing_request
from .release_manifest import (
    build_release_evidence_manifest,
    verify_release_evidence_manifest,
)
from .release_readiness import assess_release_readiness
from .reproducibility import (
    compare_builds,
    normalize_sdist,
    render_reproducibility_markdown,
)
from .standards_monitor import (
    monitor_standard_sources,
    verify_standards_monitor_report,
)
from .trusted_observation import governed_now, scan_time_identity


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "list-tools":
        return _list_tools_command(args)
    try:
        return _dispatch_command(args)
    except (ConfigurationError, OSError, TypeError, ValueError) as exc:
        _emit_cli_error(args, exc)
        return 3


def _dispatch_command(args: argparse.Namespace) -> int:
    handlers = {
        "recover-report": recovery_command,
        "schema": _schema_command,
        "adapter-check": _adapter_check_command,
        "qualify-bundle": _qualify_bundle_command,
        "verify-native-bundle": _verify_native_bundle_command,
        "generate-ci": _generate_ci_command,
        "generate-hooks": _generate_hooks_command,
        "config-check": _config_check_command,
        "benchmark": _benchmark_command,
        "benchmark-run": _benchmark_run_command,
        "benchmark-provider-check": _benchmark_provider_check_command,
        "benchmark-runtime-probe": _benchmark_runtime_probe_command,
        "benchmark-security-log-verify": _benchmark_security_log_verify_command,
        "benchmark-prepare": _benchmark_prepare_command,
        "assurance-catalog-export": _assurance_catalog_export_command,
        "standards-manifest-build": _standards_manifest_build_command,
        "standards-monitor": _standards_monitor_command,
        "standards-monitor-verify": _standards_monitor_verify_command,
        "release-check": _release_check_command,
        "evidence-draft": _evidence_draft_command,
        "promotion-plan": _promotion_plan_command,
        "closure-plan": _closure_plan_command,
        "compare-builds": _compare_builds_command,
        "normalize-sdist": _normalize_sdist_command,
        "baseline-candidate": _baseline_candidate_command,
        "trend": _trend_command,
        "release-manifest": _release_manifest_command,
        "verify-release-manifest": _verify_release_manifest_command,
        "policy-simulate": _policy_simulation_command,
        "finding-register": _finding_register_command,
        "github-annotations": _github_annotations_command,
        "audit-package": _audit_package_command,
        "verify-audit-package": _verify_audit_package_command,
        "merge-coverage": _merge_coverage_command,
        "portfolio": _portfolio_command,
        "config-provenance": _config_provenance_command,
        "audience-report": _audience_report_command,
        "evidence-pack": _evidence_pack_command,
        "verify-evidence-pack": _verify_evidence_pack_command,
        "sign-artifacts": _sign_artifacts_command,
        "prepare-signing": _prepare_signing_command,
        "verify-signing-request": _verify_signing_request_command,
        "reachability": _reachability_command,
        "reachability-diff": _reachability_diff_command,
        "advanced-diff": _advanced_diff_command,
        "init": _init_command,
        "doctor": _doctor_command,
        "provision-plan": _provision_plan_command,
        "attest": _attest_command,
        "verify": _verify_attestation_command,
        "verify-report": _verify_report_command,
        "verify-inspection": _verify_inspection_command,
        "inspect": _inspect_command,
        "scan": _scan_command,
        "encrypt-report": _encrypt_report_command,
        "decrypt-report": _decrypt_report_command,
        "retention-status": _retention_status_command,
        "purge-expired-report": _purge_expired_report_command,
    }
    return handlers[args.command](args)


def _encrypt_report_command(args: argparse.Namespace) -> int:
    result = encrypt_report(
        args.report,
        args.output,
        recipient_public_key=args.recipient_public_key,
        recipient_public_key_sha256=args.recipient_public_key_sha256,
        key_lifecycle_receipt=args.key_lifecycle_receipt,
        key_lifecycle_receipt_sha256=args.key_lifecycle_receipt_sha256,
        key_authority_public_key=args.key_authority_public_key,
        key_authority_public_key_sha256=args.key_authority_public_key_sha256,
        key_lifecycle_signature=args.key_lifecycle_signature,
        provider_attestation=args.provider_attestation,
        provider_attestation_sha256=args.provider_attestation_sha256,
        provider_authority_public_key=args.provider_authority_public_key,
        provider_authority_public_key_sha256=(
            args.provider_authority_public_key_sha256
        ),
        provider_attestation_signature=args.provider_attestation_signature,
        trusted_time_context=args.trusted_time_context,
        overwrite=args.overwrite,
    )
    if args.delete_plaintext_after_encryption:
        purge = purge_verified_report(args.report, require_expired=False)
        result["plaintext_purged"] = purge["purged"]
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _decrypt_report_command(args: argparse.Namespace) -> int:
    result = decrypt_report(
        args.encrypted,
        args.output,
        recipient_private_key=args.recipient_private_key,
        recipient_private_key_sha256=args.recipient_private_key_sha256,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _retention_status_command(args: argparse.Namespace) -> int:
    print(  # lgtm[py/clear-text-logging-sensitive-data] verified digests and timestamps only
        json.dumps(retention_status(args.report), indent=2, sort_keys=True)
    )
    return 0


def _purge_expired_report_command(args: argparse.Namespace) -> int:
    print(
        json.dumps(
            purge_verified_report(
                args.report, trusted_time_context=args.trusted_time_context
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _init_command(args: argparse.Namespace) -> int:
    target = resolve_regular_directory(args.target, "project target")
    requested = args.output or (target / "pysec.toml")
    requested = requested if requested.is_absolute() else target / requested
    destination = resolve_unlinked_path(requested, "project configuration")
    if not destination.is_relative_to(target):
        raise ValueError("project configuration output must be inside the target")
    profile = project_profile(args.template, args.profile)
    content = render_project_config(args.template, profile)
    _write_atomic_output(
        output=destination,
        content=content,
        overwrite=args.overwrite,
        label="project configuration",
    )
    receipt = build_init_receipt(
        target=target,
        config_path=destination,
        template=args.template,
        profile=profile,
    )
    print(
        json.dumps(receipt, indent=2, sort_keys=True)
        if args.format == "json"
        else render_init_receipt(receipt)
    )
    return 0


def _sign_artifacts_command(args: argparse.Namespace) -> int:
    material = sign_release_artifacts(
        artifacts=args.artifacts,
        output=args.output,
        signing_key=args.signing_key,
        signing_password_file=args.signing_password_file,
        cosign_executable=args.cosign_executable,
        cosign_sha256=args.cosign_sha256,
        allow_signing_network=args.allow_signing_network,
        signing_config=args.signing_config,
        overwrite=args.overwrite,
    )
    print(json.dumps(material, sort_keys=True))
    return 0


def _prepare_signing_command(args: argparse.Namespace) -> int:
    request = prepare_signing_request(args.report, args.artifacts)
    rendered = json.dumps(request, indent=2, sort_keys=True)
    _write_atomic_output(
        output=args.output,
        content=rendered,
        overwrite=args.overwrite,
        label="signing request output",
        forbidden_root=args.report,
    )
    print(rendered)
    return 0


def _verify_signing_request_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("verify-signing-request --overwrite requires --output")
    result = verify_signing_request(
        args.request,
        args.artifacts,
        request_sha256=args.request_sha256,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="signing request verification output",
        )
    if args.format == "json":
        print(rendered)
    else:
        print(
            "VERIFIED REQUEST: "
            f"{result['artifact_count']} artifact(s); payload {result['payload_id']}"
        )
    return 0


def _reachability_command(args: argparse.Namespace) -> int:
    target = resolve_regular_directory(args.target, "reachability target")
    document = analyze_project(
        target,
        configured_entry_points=tuple(args.entry_point),
        configured_source_roots=tuple(args.source_root),
        minimum_island_loc=args.minimum_island_loc,
        discover_framework_roots=not args.no_framework_roots,
        coverage_path=args.coverage,
    )
    print(
        json.dumps(
            document,
            indent=2 if args.pretty else None,
            sort_keys=True,
            separators=None if args.pretty else (",", ":"),
        )
    )
    return 0


def _reachability_diff_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("reachability-diff --overwrite requires --output")
    result = compare_reachability(
        args.baseline,
        args.current,
        baseline_sha256=args.baseline_sha256,
        current_sha256=args.current_sha256,
    )
    rendered_json = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered_json,
            overwrite=args.overwrite,
            label="reachability delta output",
        )
    if args.format == "json":
        print(  # lgtm[py/clear-text-logging-sensitive-data] aggregate governed metrics only
            rendered_json
        )
    else:
        counts = result["counts"]
        print(
            f"{str(result['verdict']).upper()}: "
            f"{counts['state_regressions']} state regression(s), "
            f"{counts['new_disconnected_nodes']} new disconnected node(s), "
            f"{counts['new_reportable_islands']} new reportable island(s)"
        )
    return 0 if result["verdict"] == "pass" else 1


def _advanced_diff_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("advanced-diff --overwrite requires --output")
    result = compare_advanced_analysis(
        args.baseline,
        args.current,
        baseline_sha256=args.baseline_sha256,
        current_sha256=args.current_sha256,
    )
    rendered_json = json.dumps(result, indent=2, sort_keys=True)
    rendered_markdown = render_advanced_delta_markdown(result)
    rendered = rendered_json if args.format == "json" else rendered_markdown
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="advanced analysis delta output",
        )
    if args.format in {"json", "markdown"}:
        print(rendered)
    else:
        summary = result["summary"]
        print(
            f"{str(result['verdict']).upper()}: "
            f"{summary['regressions']} attack-surface regression(s), "
            f"{summary['control_regressions']} control regression(s), "
            f"{summary['privacy_regressions']} privacy regression(s), "
            f"{summary['new_unmodeled_published_entry_points']} new unmodeled artifact entry point(s)"
        )
    return 0 if result["verdict"] == "pass" else 1


def _doctor_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("doctor --overwrite requires --output")
    config = load_config(
        organization_policy=args.policy,
        repository_config=args.config,
        profile_override=args.profile,
    )
    readiness = assess_readiness(target=args.target, config=config)
    rendered = (
        json.dumps(readiness, indent=2, sort_keys=True)
        if args.format == "json"
        else render_readiness_markdown(readiness).rstrip("\n")
        if args.format == "markdown"
        else render_readiness(readiness, explain=args.explain)
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="doctor output",
        )
    print(rendered)
    return 0 if readiness["ready"] else 2


def _provision_plan_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("provision-plan --overwrite requires --output")
    config = load_config(
        organization_policy=args.policy,
        repository_config=args.config,
        profile_override=args.profile,
    )
    plan = build_provision_plan(target=args.target, config=config)
    rendered = (
        json.dumps(plan, indent=2, sort_keys=True)
        if args.format == "json"
        else render_provision_plan_markdown(plan).rstrip("\n")
        if args.format == "markdown"
        else render_provision_plan(plan)
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="provision plan output",
        )
    print(rendered)
    return 0 if plan["decision"]["disposition"] == "proceed" else 2


def _attest_command(args: argparse.Namespace) -> int:
    material = create_attestation(
        report=args.report,
        output=args.output,
        signing_key=args.signing_key,
        signing_password_file=args.signing_password_file,
        cosign_executable=args.cosign_executable,
        cosign_sha256=args.cosign_sha256,
        allow_signing_network=args.allow_signing_network,
        signing_config=args.signing_config,
        overwrite=args.overwrite,
    )
    print(json.dumps(material, sort_keys=True))
    return 0


def _verify_attestation_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("verify --overwrite requires --output")
    if args.output and args.format != "json":
        raise ValueError("verify --output requires --format json")
    verification = verify_attestation(
        passport=args.passport,
        report=args.report,
        public_key=args.public_key,
        artifact_root=args.artifact_root,
        cosign_executable=args.cosign_executable,
        cosign_sha256=args.cosign_sha256,
        allow_unsigned=args.allow_unsigned,
    )
    rendered = (
        _render_attestation_verification(verification)
        if args.format == "text"
        else json.dumps(verification, indent=2, sort_keys=True)
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="passport verification output",
            forbidden_root=args.report,
        )
    print(rendered)
    return 0 if verification.get("release_decision") == "approved" else 1


def _verify_inspection_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("verify-inspection --overwrite requires --output")
    if args.output and args.format != "json":
        raise ValueError("verify-inspection --output requires --format json")
    verification = verify_inspection(
        args.inspection,
        report=args.report,
        limit=args.limit,
    )
    rendered = (
        json.dumps(verification, indent=2, sort_keys=True)
        if args.format == "json"
        else (
            "VERIFIED: inspection for scan "
            f"{verification['scan_id']}; "
            f"{verification['top_actions_verified']} prioritized actions "
            f"(limit {verification['action_limit']}); report checksum "
            f"{verification['report_checksums_sha256']}"
        )
    )
    if args.output:
        _write_inspection_output(
            report=args.report,
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
        )
    print(rendered)
    return 0


def _inspect_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("inspect --overwrite requires --output")
    inspection = inspect_report(args.report, limit=args.limit)
    rendered = (
        json.dumps(inspection, indent=2, sort_keys=True)
        if args.format == "json"
        else render_inspection(inspection, report_root=args.report)
    )
    if args.output:
        _write_inspection_output(
            report=args.report,
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
        )
    _print_portable(rendered)
    return 0


def _print_portable(value: str) -> None:
    """Render untrusted report text on consoles with limited code pages."""
    encoding = sys.stdout.encoding or "utf-8"
    print(value.encode(encoding, errors="replace").decode(encoding))


def _scan_command(args: argparse.Namespace) -> int:
    if args.network_isolated and args.diagnostic_without_isolation:
        raise ValueError(
            "--network-isolated and --diagnostic-without-isolation cannot be used together"
        )
    target = resolve_regular_directory(args.target, "scan target")
    output = _prepare_output(
        target=target,
        output=args.output,
        overwrite=args.overwrite,
    )
    config = load_config(
        organization_policy=args.policy,
        repository_config=args.config,
        profile_override=args.profile,
    )
    control = ScanControl(
        config.execution.max_scan_seconds,
        progress_sink(args.progress),
        max_memory_bytes=config.execution.max_scan_memory_bytes,
    )
    with controlled_scan(control, handle_interrupt=True):
        result = scan_project(
            target=target,
            output=output,
            config=config,
            network_isolation_attested=args.network_isolated,
            diagnostic_without_isolation=args.diagnostic_without_isolation,
            replace_existing=args.overwrite,
        )
    if args.github_summary:
        _append_github_summary(output / "summary.md")
    print(
        f"{result.outcome.value.upper()}: {len(result.findings)} finding(s); "
        f"report: {output}"
    )
    return exit_code(result.outcome)


def _schema_command(args: argparse.Namespace) -> int:
    """Render or safely publish one version-explicit installed schema."""
    if args.overwrite and not args.output:
        raise ValueError("schema --overwrite requires --output")
    rendered_schema = read_bundled_schema(str(args.name))
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered_schema,
            overwrite=bool(args.overwrite),
            label="schema output",
        )
    print(rendered_schema)
    return 0


def _adapter_check_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("adapter-check --overwrite requires --output")
    document = assess_adapter_conformance()
    rendered = (
        json.dumps(document, indent=2, sort_keys=True)
        if args.format == "json"
        else render_adapter_conformance(document)
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="adapter conformance output",
        )
    print(rendered)
    return 0 if document["status"] == "pass" else 1


def _qualify_bundle_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("qualify-bundle --overwrite requires --output")
    config = load_config(
        organization_policy=args.policy,
        repository_config=args.config,
        profile_override=args.profile,
    )
    document = qualify_bundle(
        target=args.target,
        config=config,
        effectiveness_evaluation=args.effectiveness_evaluation,
        effectiveness_report=args.effectiveness_report,
        effectiveness_sha256=args.effectiveness_sha256,
        minimum_effectiveness_labels=args.minimum_effectiveness_labels,
        minimum_effectiveness_tools=args.minimum_effectiveness_tools,
        required_effectiveness_tools=tuple(args.required_effectiveness_tool),
    )
    rendered = (
        json.dumps(document, indent=2, sort_keys=True)
        if args.format == "json"
        else render_bundle_qualification_markdown(document).rstrip("\n")
        if args.format == "markdown"
        else render_bundle_qualification(document)
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="bundle qualification output",
        )
    print(rendered)
    return 0 if document["decision"]["disposition"] == "qualify" else 2


def _verify_native_bundle_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("verify-native-bundle --overwrite requires --output")
    document = verify_native_bundle(
        args.bundle,
        manifest_sha256=args.manifest_sha256,
        python=args.python,
        require_wheelhouse_closure=args.require_wheelhouse_closure,
    )
    rendered = (
        json.dumps(document, indent=2, sort_keys=True)
        if args.format == "json"
        else render_native_bundle_verification_markdown(document).rstrip("\n")
        if args.format == "markdown"
        else render_native_bundle_verification(document)
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="native bundle verification output",
            forbidden_root=args.bundle,
        )
    print(rendered)
    return 0 if document["verified"] else 1


def _generate_ci_command(args: argparse.Namespace) -> int:
    target = resolve_regular_directory(args.target, "project target")
    requested = args.output or Path(".github/workflows/python-security.yml")
    requested = requested if requested.is_absolute() else target / requested
    destination = resolve_unlinked_path(requested, "GitHub workflow output")
    if not destination.is_relative_to(target):
        raise ValueError("GitHub workflow output must be inside the target")
    workflow, receipt = build_github_workflow(
        target=target,
        output=destination,
        profile=args.profile,
        config_path=args.config,
        checkout_sha=args.checkout_sha,
        upload_artifact_sha=args.upload_artifact_sha,
        upload_sarif_sha=args.upload_sarif_sha,
        policy_variable=args.policy_variable,
        isolation_command=args.isolation_command,
        runner_labels=tuple(args.runner_label),
    )
    _write_atomic_output(
        output=destination,
        content=workflow.rstrip("\n"),
        overwrite=args.overwrite,
        label="GitHub workflow output",
    )
    print(
        json.dumps(receipt, indent=2, sort_keys=True)
        if args.format == "json"
        else render_workflow_receipt(receipt)
    )
    return 0


def _generate_hooks_command(args: argparse.Namespace) -> int:
    target = resolve_regular_directory(args.target, "project target")
    requested = args.output or Path(".pre-commit-config.yaml")
    requested = requested if requested.is_absolute() else target / requested
    destination = resolve_unlinked_path(requested, "pre-commit configuration output")
    if not destination.is_relative_to(target):
        raise ValueError("pre-commit configuration output must be inside the target")
    content, receipt = build_precommit_config(
        target=target,
        output=destination,
        profile=args.profile,
        config_path=args.config,
    )
    _write_atomic_output(
        output=destination,
        content=content.rstrip("\n"),
        overwrite=args.overwrite,
        label="pre-commit configuration output",
    )
    print(
        json.dumps(receipt, indent=2, sort_keys=True)
        if args.format == "json"
        else render_precommit_receipt(receipt)
    )
    return 0


def _config_check_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("config-check --overwrite requires --output")
    document = advise_configuration(
        repository_config=args.config,
        organization_policy=args.policy,
        profile_override=args.profile,
    )
    rendered = (
        json.dumps(document, indent=2, sort_keys=True)
        if args.format == "json"
        else render_config_advice_markdown(document).rstrip("\n")
        if args.format == "markdown"
        else render_config_advice(document)
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="configuration assessment output",
        )
    print(rendered)
    return 0 if document["decision"] != "invalid" else 2


def _benchmark_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("benchmark --overwrite requires --output")
    result = evaluate_report_corpus(
        args.report,
        args.corpus,
        corpus_sha256=args.corpus_sha256,
        trusted_time=args.trusted_time,
        trusted_time_sha256=args.trusted_time_sha256,
        replay_ledger=args.replay_ledger,
        replay_service_url=args.replay_service_url,
        replay_service_token_env=args.replay_service_token_env,
        replay_service_receipt_key=args.replay_service_receipt_key,
        replay_service_receipt_key_sha256=args.replay_service_receipt_key_sha256,
        replay_query_budget=args.replay_query_budget,
    )
    rendered_json = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered_json,
            overwrite=args.overwrite,
            label="effectiveness benchmark output",
            forbidden_root=args.report,
        )
    if args.format == "json":
        print(rendered_json)
    else:
        metrics = result["metrics"]
        matrix = result["confusion_matrix"]
        print(
            f"{str(result['verdict']).upper()}: "
            f"precision {_metric_text(metrics['precision'])}; "
            f"recall {_metric_text(metrics['recall'])}; "
            f"TP {matrix['true_positive']}, FP {matrix['false_positive']}, "
            f"FN {matrix['false_negative']}, TN {matrix['true_negative']}"
        )
    return 0 if result["verdict"] == "pass" else 1


def _benchmark_run_command(args: argparse.Namespace) -> int:
    event_sink = (
        DurableJsonlSecurityEventSink(
            args.security_event_log,
            workspace=args.workspace,
        )
        if args.security_event_log is not None
        else None
    )
    signing_provider = _external_benchmark_signing_provider(args)
    if signing_provider is not None and args.receipt_signing_key is not None:
        raise ValueError(
            "local and external benchmark receipt signing providers are mutually exclusive"
        )
    receipt = execute_benchmark_manifest(
        args.manifest,
        args.workspace,
        authorized=args.authorize_execution,
        benchmark_contracts=benchmark_execution_contracts(),
        authority_trust_policy=args.authority_trust_policy,
        authority_trust_policy_sha256=args.authority_trust_policy_sha256,
        authority_trust_policy_signature=args.authority_trust_policy_signature,
        authority_trust_root=args.authority_trust_root,
        authority_trust_root_sha256=args.authority_trust_root_sha256,
        trusted_time_context=args.trusted_time_context,
        trusted_time_context_sha256=args.trusted_time_context_sha256,
        replay_ledger=args.replay_ledger,
        replay_minimum_sequence=args.replay_minimum_sequence,
        replay_checkpoint_sha256=args.replay_checkpoint_sha256,
        replay_checkpoint_state=args.replay_checkpoint_state,
        initialize_replay_checkpoint=args.initialize_replay_checkpoint,
        receipt_signing_key=args.receipt_signing_key,
        receipt_signing_key_sha256=args.receipt_signing_key_sha256,
        receipt_signing_provider=signing_provider,
        security_event_sink=event_sink,
    )
    rendered = json.dumps(receipt, indent=2, sort_keys=True)
    _write_atomic_output(
        output=args.output,
        content=rendered,
        overwrite=args.overwrite,
        label="benchmark execution receipt",
    )
    terminal_decision = "PASS" if receipt["decision"] == "pass" else "FAIL"
    terminal_output = sanitize_terminal_text(str(args.output), maximum=512)
    print(
        f"{terminal_decision}: benchmark execution receipt written to {terminal_output}"
    )
    return 0 if receipt["decision"] == "pass" else 2


def _benchmark_provider_check_command(args: argparse.Namespace) -> int:
    provider = load_external_signing_provider_profile(args.profile, args.profile_sha256)
    configured_time = any(
        os.environ.get(name, "").strip()
        for name in (
            "PYSEC_SCAN_TIME_CONTEXT_PATH",
            "PYSEC_SCAN_TIME_CONTEXT_SHA256",
            "PYSEC_SCAN_TIME_CHALLENGE_SHA256",
        )
    )
    result = verify_signing_provider_conformance(
        provider,
        portable=True,
        observed_at=governed_now(),
        profile_sha256=args.profile_sha256.casefold(),
        time_context_sha256=scan_time_identity() if configured_time else "",
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    _write_atomic_output(
        output=args.output,
        content=rendered,
        overwrite=args.overwrite,
        label="benchmark signing provider conformance receipt",
    )
    print(rendered)
    return 0


def _external_benchmark_signing_provider(
    args: argparse.Namespace,
) -> ExternalEd25519SigningProvider | None:
    profile = args.receipt_signing_provider_profile
    profile_sha256 = args.receipt_signing_provider_profile_sha256
    executable = args.receipt_signing_provider_executable
    values = (
        args.receipt_signing_provider_executable_sha256,
        args.receipt_signing_provider_public_key,
        args.receipt_signing_provider_public_key_sha256,
        args.receipt_signing_provider_id,
        args.receipt_signing_provider_key_version,
    )
    if profile is not None or profile_sha256:
        if profile is None or not profile_sha256:
            raise ValueError(
                "external signing provider profile configuration is incomplete"
            )
        if (
            executable is not None
            or any(values)
            or args.receipt_signing_provider_argument
        ):
            raise ValueError(
                "external signing provider profile and individual provider options are mutually exclusive"
            )
        return load_external_signing_provider_profile(profile, profile_sha256)
    if executable is None and not any(values):
        return None
    if executable is None or not all(values):
        raise ValueError(
            "external benchmark receipt signing configuration is incomplete"
        )
    _, public_payload = read_regular_file(
        args.receipt_signing_provider_public_key,
        "external receipt signer public key",
        maximum_bytes=64 * 1024,
    )
    if hashlib.sha256(public_payload).hexdigest() != (
        args.receipt_signing_provider_public_key_sha256
    ):
        raise ValueError("external receipt signer public key digest does not match")
    if len(public_payload) == 32:
        public_bytes = public_payload
    else:
        key = serialization.load_pem_public_key(public_payload)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("external receipt signer public key must use Ed25519")
        public_bytes = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    return ExternalEd25519SigningProvider(
        executable=executable,
        executable_sha256=args.receipt_signing_provider_executable_sha256,
        arguments=tuple(args.receipt_signing_provider_argument),
        public_key=public_bytes,
        provider_id=args.receipt_signing_provider_id,
        key_version=args.receipt_signing_provider_key_version,
    )


def _benchmark_runtime_probe_command(args: argparse.Namespace) -> int:
    if not args.authorize_execution:
        raise BenchmarkRuntimeError(
            "OCI runtime probing requires explicit --authorize-execution"
        )
    result = probe_oci_runtime_capabilities(
        runtime_path=args.runtime,
        runtime_sha256=args.runtime_sha256,
        runtime_name=args.runtime_name,
        runtime_version=args.runtime_version,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    _write_atomic_output(
        output=args.output,
        content=rendered,
        overwrite=args.overwrite,
        label="OCI runtime capability proof",
    )
    print(rendered)
    return 0


def _benchmark_security_log_verify_command(args: argparse.Namespace) -> int:
    result = verify_durable_security_event_log(args.log)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _benchmark_prepare_command(args: argparse.Namespace) -> int:
    result = compile_benchmark_manifest(args.request, args.workspace)
    rendered_manifest = json.dumps(result["manifest"], indent=2, sort_keys=True)
    _write_atomic_output(
        output=args.output,
        content=rendered_manifest,
        overwrite=args.overwrite,
        label="compiled benchmark adapter manifest",
    )
    print(
        json.dumps(
            {key: value for key, value in result.items() if key != "manifest"},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _assurance_catalog_export_command(args: argparse.Namespace) -> int:
    result = export_assurance_catalog()
    rendered = json.dumps(result, indent=2, sort_keys=True)
    _write_atomic_output(
        output=args.output,
        content=rendered,
        overwrite=args.overwrite,
        label="assurance catalog export",
    )
    print(rendered)
    return 0


def _standards_manifest_build_command(args: argparse.Namespace) -> int:
    selected = set(args.standard) if args.standard else None
    result = build_standards_source_manifest(args.inventory, selected_ids=selected)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    _write_atomic_output(
        output=args.output,
        content=rendered,
        overwrite=args.overwrite,
        label="standards source manifest",
    )
    print(rendered)
    return 0


def _standards_monitor_command(args: argparse.Namespace) -> int:
    report = monitor_standard_sources(
        args.manifest,
        args.output,
        network_authorized=args.authorize_network,
        overwrite=args.overwrite,
        signing_key_path=args.signing_key,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["decision"] == "current" else 2


def _standards_monitor_verify_command(args: argparse.Namespace) -> int:
    receipt = verify_standards_monitor_report(
        args.report,
        args.public_key,
        report_sha256=args.report_sha256,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


def _release_check_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("release-check --overwrite requires --output")
    result = assess_release_readiness(
        args.report,
        effectiveness_evaluation=args.effectiveness_evaluation,
        effectiveness_sha256=args.effectiveness_sha256,
        minimum_effectiveness_labels=args.minimum_effectiveness_labels,
        minimum_effectiveness_positive_labels=(
            args.minimum_effectiveness_positive_labels
        ),
        minimum_effectiveness_negative_labels=(
            args.minimum_effectiveness_negative_labels
        ),
        minimum_effectiveness_tools=args.minimum_effectiveness_tools,
        minimum_effectiveness_labels_per_tool=(
            args.minimum_effectiveness_labels_per_tool
        ),
        required_effectiveness_tools=tuple(args.required_effectiveness_tool),
        passport_verification=args.passport_verification,
        passport_verification_sha256=args.passport_verification_sha256,
        require_passport=args.require_passport,
        provider_conformance=tuple(args.provider_conformance),
        provider_conformance_sha256=tuple(args.provider_conformance_sha256),
        required_provider_ids=tuple(args.required_provider_id),
        maximum_provider_conformance_age_hours=(
            args.maximum_provider_conformance_age_hours
        ),
        require_provider_conformance=args.require_provider_conformance,
    )
    rendered_json = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered_json,
            overwrite=args.overwrite,
            label="release readiness output",
            forbidden_root=args.report,
        )
    if args.format == "json":
        print(rendered_json)
    else:
        summary = result["summary"]
        print(
            f"{str(result['decision']).upper()}: "
            f"{summary['passed']}/{summary['controls']} controls passed; "
            f"blockers {', '.join(result['blockers']) or 'none'}"
        )
    return 0 if result["decision"] == "approved" else 1


def _evidence_draft_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("evidence-draft --overwrite requires --output")
    result = build_governance_evidence_draft(args.report)
    rendered_json = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered_json,
            overwrite=args.overwrite,
            label="governance evidence draft output",
            forbidden_root=args.report,
        )
    if args.format == "json":
        print(rendered_json)
    else:
        print(
            "CANDIDATE: "
            f"{len(result['scanner_trust_candidates'])} scanner identity record(s), "
            f"{len(result['intelligence_candidates'])} intelligence snapshot(s), "
            f"{len(result['artifact_signing_candidates'])} artifact(s) require "
            "independent approval"
        )
    return 0


def _promotion_plan_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("promotion-plan --overwrite requires --output")
    result = build_promotion_plan(
        args.report,
        release_readiness=args.release_readiness,
        release_readiness_sha256=args.release_readiness_sha256,
        operational_trend=args.operational_trend,
        operational_trend_sha256=args.operational_trend_sha256,
    )
    rendered_json = json.dumps(result, indent=2, sort_keys=True)
    rendered = (
        render_promotion_markdown(result)
        if args.format == "markdown"
        else render_promotion_html(result)
        if args.format == "html"
        else rendered_json
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="promotion plan output",
            forbidden_root=args.report,
        )
    if args.format in {"json", "markdown", "html"}:
        print(rendered)
    else:
        summary = result["summary"]
        print(
            f"{str(result['status']).upper()}: "
            f"{summary['release_blockers']} release blocker(s); "
            f"{len(result['next_actions'])} next action(s)"
        )
    return 0 if result["status"] == "ready" else 1


def _closure_plan_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("closure-plan --overwrite requires --output")
    result = build_closure_plan(
        args.report,
        coverage_target=args.coverage_target,
        hotspot_limit=args.hotspot_limit,
    )
    rendered_json = json.dumps(result, indent=2, sort_keys=True)
    rendered = (
        render_closure_plan_markdown(result)
        if args.format == "markdown"
        else rendered_json
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="closure plan output",
            forbidden_root=args.report,
        )
    if args.format in {"json", "markdown"}:
        _print_portable(rendered)
    else:
        summary = result["summary"]
        print(
            f"CLOSURE: {summary['open_items']} item(s); "
            f"{summary['authority_items']} require organization or external authority"
        )
    return 0


def _compare_builds_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("compare-builds --overwrite requires --output")
    result = compare_builds(
        args.first,
        args.second,
        first_label=args.first_label,
        second_label=args.second_label,
    )
    rendered_json = json.dumps(result, indent=2, sort_keys=True)
    rendered = (
        render_reproducibility_markdown(result)
        if args.format == "markdown"
        else rendered_json
    )
    if args.output:
        requested = args.output.expanduser().absolute()
        second_root = args.second.expanduser().absolute().resolve()
        if requested == second_root or requested.is_relative_to(second_root):
            raise ValueError(
                "reproducible build output must be outside both compared directories"
            )
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="reproducible build output",
            forbidden_root=args.first,
        )
    if args.format in {"json", "markdown"}:
        print(rendered)
    else:
        print(
            f"REPRODUCIBLE BUILD {str(result['status']).upper()}: {result['summary']}"
        )
    return 0 if result["reproducible"] else 1


def _normalize_sdist_command(args: argparse.Namespace) -> int:
    result = normalize_sdist(
        args.source,
        args.output,
        epoch=args.source_date_epoch,
        overwrite=args.overwrite,
    )
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            f"NORMALIZED SDIST: {result['members']} member(s); "
            f"SHA-256 {result['output_sha256']}"
        )
    return 0


def _baseline_candidate_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("baseline-candidate --overwrite requires --output")
    result = build_baseline_candidate(args.report)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="baseline candidate output",
            forbidden_root=args.report,
        )
    print(
        rendered
        if args.format == "json"
        else f"{result['status'].upper()}: {result['baseline']['sha256']}"
    )
    return 0 if result["status"] == "candidate" else 1


def _trend_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("trend --overwrite requires --output")
    result = build_operational_trend(
        list(args.reports),
        performance_regression_percent=args.performance_regression_percent,
        maximum_total_seconds=args.maximum_total_seconds,
        tool_budgets=dict(_parse_tool_budget(value) for value in args.tool_budget),
    )
    rendered_json = json.dumps(result, indent=2, sort_keys=True)
    rendered = (
        render_operational_trend_markdown(result)
        if args.format == "markdown"
        else rendered_json
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="operational trend output",
            forbidden_root=args.reports[0],
        )
    if args.format in {"json", "markdown"}:
        _print_portable(rendered)
    else:
        summary = result["summary"]
        print(
            f"TREND: {summary['reports']} verified reports; latest outcome {str(summary['latest_outcome']).upper()}"
        )
    return 0


def _release_manifest_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("release-manifest --overwrite requires --output")
    evidence = tuple(_parse_evidence_argument(value) for value in args.evidence)
    result = build_release_evidence_manifest(
        args.report,
        evidence=evidence,
        path_base=args.output.parent if args.output else Path.cwd(),
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="release evidence manifest output",
            forbidden_root=args.report,
        )
    print(
        rendered
        if args.format == "json"
        else f"CANDIDATE: {len(result['evidence'])} exact evidence item(s); manifest {result['manifest_id']}"
    )
    return 0


def _verify_release_manifest_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("verify-release-manifest --overwrite requires --output")
    result = verify_release_evidence_manifest(
        args.manifest,
        manifest_sha256=args.manifest_sha256,
        report=args.report,
        required_evidence=tuple(args.required_evidence),
        evidence_locations=tuple(
            _parse_evidence_location(value) for value in args.evidence_location
        ),
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="release evidence manifest verification output",
            forbidden_root=args.report,
        )
    print(
        rendered
        if args.format == "json"
        else f"VERIFIED: {result['evidence']['verified_count']} evidence item(s); external approval still required"
    )
    return 0


def _policy_simulation_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("policy-simulate --overwrite requires --output")
    result = simulate_policy(
        args.report,
        block_severities=tuple(args.block_severity or ("critical", "high")),
        required_tools=tuple(args.require_tool),
        minimum_confidence=args.minimum_confidence,
        maximum_blocking_findings=args.maximum_blocking_findings,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="policy simulation output",
            forbidden_root=args.report,
        )
    print(
        rendered
        if args.format == "json"
        else f"SIMULATION {result['result']['disposition'].upper()}: {len(result['result']['reasons'])} reason(s)"
    )
    return 0 if result["result"]["disposition"] == "allow" else 1


def _finding_register_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("finding-register --overwrite requires --output")
    result = build_finding_register(
        args.report, previous=args.previous, previous_sha256=args.previous_sha256
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="finding register output",
            forbidden_root=args.report,
        )
    print(
        rendered
        if args.format == "json"
        else f"FINDINGS: {result['summary']['open']} open, {result['summary']['resolved']} resolved, {result['summary']['overdue']} overdue"
    )
    return 0


def _github_annotations_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("github-annotations --overwrite requires --output")
    result = build_github_annotations(
        args.plan, plan_sha256=args.plan_sha256, report=args.report
    )
    rendered = (
        json.dumps(result, indent=2, sort_keys=True)
        if args.format == "json"
        else render_github_commands(result)
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="GitHub annotations output",
            forbidden_root=args.report,
        )
    print(rendered, end="" if rendered.endswith("\n") else "\n")
    return 0


def _audit_package_command(args: argparse.Namespace) -> int:
    result = create_audit_package(
        args.report,
        args.output,
        evidence=tuple(_parse_evidence_argument(value) for value in args.evidence),
        overwrite=args.overwrite,
    )
    print(
        json.dumps(result, indent=2, sort_keys=True)
        if args.format == "json"
        else f"CANDIDATE: {result['package']['files']} files; SHA-256 {result['package']['sha256']}"
    )
    return 0


def _verify_audit_package_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("verify-audit-package --overwrite requires --output")
    result = verify_audit_package(args.package, package_sha256=args.package_sha256)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="audit package verification output",
        )
    print(
        rendered
        if args.format == "json"
        else f"VERIFIED: {result['package']['files_verified']} files; external approval still required"
    )
    return 0


def _merge_coverage_command(args: argparse.Namespace) -> int:
    result = merge_coverage_scenarios(
        tuple(_parse_evidence_argument(value) for value in args.scenario)
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    _write_atomic_output(
        output=args.output,
        content=rendered,
        overwrite=args.overwrite,
        label="merged coverage output",
    )
    print(
        f"MERGED: {result['pysec_merge']['scenario_count']} scenarios, {result['pysec_merge']['executed_lines']} executed lines"
    )
    return 0


def _portfolio_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("portfolio --overwrite requires --output")
    result = build_portfolio_dashboard(list(args.reports))
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="portfolio dashboard output",
            forbidden_root=args.reports[0],
        )
    print(
        rendered
        if args.format == "json"
        else f"PORTFOLIO: {result['summary']['reports']} reports, {result['summary']['blocking_findings']} blocking findings"
    )
    return 0


def _config_provenance_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("config-provenance --overwrite requires --output")
    result = build_config_provenance(
        organization_policy=args.policy,
        repository_config=args.config,
        profile_override=args.profile,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="configuration provenance output",
        )
    print(
        rendered
        if args.format == "json"
        else (
            f"CONFIG: {result['summary']['facts']} origin fact(s), "
            f"{result['summary']['security_sensitive_facts']} security-sensitive"
        )
    )
    return 0


def _audience_report_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("audience-report --overwrite requires --output")
    result = build_audience_report(
        args.plan,
        plan_sha256=args.plan_sha256,
        report=args.report,
        audience=args.audience,
    )
    rendered = (
        render_audience_markdown(result)
        if args.format == "markdown"
        else json.dumps(result, indent=2, sort_keys=True)
    )
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="audience report output",
            forbidden_root=args.report,
        )
    print(
        rendered
        if args.format != "text"
        else f"{args.audience.upper()}: {result['status'].upper()} ({result['report']['scan_id']})"
    )
    return 0


def _evidence_pack_command(args: argparse.Namespace) -> int:
    result = create_evidence_pack(
        args.report,
        args.output,
        previous_register=args.previous_register,
        previous_register_sha256=args.previous_register_sha256,
        previous_report=args.previous_report,
        artifacts=args.artifacts,
        organization_policy=args.policy,
        repository_config=args.config,
        profile_override=args.profile,
        block_severities=tuple(args.block_severity or ("critical", "high")),
        required_tools=tuple(args.require_tool),
        minimum_confidence=args.minimum_confidence,
        maximum_blocking_findings=args.maximum_blocking_findings,
        effectiveness_evaluation=args.effectiveness_evaluation,
        effectiveness_sha256=args.effectiveness_sha256,
        minimum_effectiveness_labels=args.minimum_effectiveness_labels,
        minimum_effectiveness_positive_labels=(
            args.minimum_effectiveness_positive_labels
        ),
        minimum_effectiveness_negative_labels=(
            args.minimum_effectiveness_negative_labels
        ),
        minimum_effectiveness_tools=args.minimum_effectiveness_tools,
        minimum_effectiveness_labels_per_tool=(
            args.minimum_effectiveness_labels_per_tool
        ),
        required_effectiveness_tools=tuple(args.required_effectiveness_tool),
        passport_verification=args.passport_verification,
        passport_verification_sha256=args.passport_verification_sha256,
        require_passport=args.require_passport,
        performance_regression_percent=args.performance_regression_percent,
        maximum_total_seconds=args.maximum_total_seconds,
        tool_budgets=dict(_parse_tool_budget(value) for value in args.tool_budget),
        overwrite=args.overwrite,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _verify_evidence_pack_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("verify-evidence-pack --overwrite requires --output")
    result = verify_evidence_pack(
        args.pack,
        report=args.report,
        pack_sha256=args.pack_sha256,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="evidence pack verification output",
            forbidden_root=args.pack,
        )
    print(rendered)
    return 0


def _parse_evidence_argument(value: str) -> tuple[str, Path, str]:
    try:
        name, remainder = value.split("=", 1)
        path, digest = remainder.rsplit("@", 1)
    except ValueError as exc:
        raise ValueError("evidence must use NAME=PATH@SHA256") from exc
    if (
        not name
        or not path
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("evidence must use NAME=PATH@SHA256 with a lowercase digest")
    return name, Path(path), digest


def _parse_tool_budget(value: str) -> tuple[str, float]:
    try:
        name, seconds_text = value.split("=", 1)
        seconds = float(seconds_text)
    except ValueError as exc:
        raise ValueError("tool budget must use TOOL=SECONDS") from exc
    if not name or seconds <= 0:
        raise ValueError(
            "tool budget must use TOOL=SECONDS with seconds greater than zero"
        )
    return name, seconds


def _parse_evidence_location(value: str) -> tuple[str, Path]:
    try:
        name, path = value.split("=", 1)
    except ValueError as exc:
        raise ValueError("evidence location must use NAME=PATH") from exc
    if not name or not path:
        raise ValueError("evidence location must use NAME=PATH")
    return name, Path(path)


def _metric_text(value: object) -> str:
    return "not measured" if value is None else f"{float(str(value)) * 100:.2f}%"


def _verify_report_command(args: argparse.Namespace) -> int:
    """Verify a sealed report and optionally publish its portable receipt."""
    if args.overwrite and not args.output:
        raise ValueError("verify-report --overwrite requires --output")
    if args.output and args.format != "json":
        raise ValueError("verify-report --output requires --format json")
    verification = report_verification_receipt(verify_report(args.report))
    rendered = json.dumps(verification, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="report verification output",
            forbidden_root=args.report,
        )
    if args.format == "json":
        print(rendered)
    else:
        print(
            "VERIFIED: "
            f"{verification['file_count']} files; "
            f"outcome {str(verification['outcome']).upper()}; "
            f"scan {verification['scan_id']}"
        )
    return 0


def _list_tools_command(args: argparse.Namespace) -> int:
    """Render the configured profile-to-tool inventory."""
    profiles = (
        {args.profile: PROFILE_TOOLS[args.profile]} if args.profile else PROFILE_TOOLS
    )
    if args.format == "json":
        print(json.dumps(profiles, indent=2, sort_keys=True))
    else:
        for profile, tools in profiles.items():
            print(f"{profile}: {', '.join(tools)}")
    return 0


def _emit_cli_error(
    args: argparse.Namespace,
    exc: ConfigurationError | OSError | TypeError | ValueError,
) -> None:
    message = sanitize_terminal_text(str(exc))
    if getattr(exc, "__notes__", None):
        message += "\n" + sanitize_terminal_text("\n".join(exc.__notes__))
    code = (
        "configuration_error"
        if isinstance(exc, ConfigurationError)
        else "io_error"
        if isinstance(exc, OSError)
        else "validation_error"
    )
    if args.command == "attest" or getattr(args, "format", None) == "json":
        print(
            json.dumps(
                {
                    "command": str(args.command),
                    "error": {"code": code, "message": message},
                    "schema_version": "1.0",
                    "status": "error",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return
    print(f"pysec: error [{code}]: {message}", file=sys.stderr)


def _prepare_output(*, target: Path, output: Path, overwrite: bool) -> Path:
    output = resolve_unlinked_path(output, "report output")
    _validate_output_scope(target, output)
    _validate_existing_output(output, overwrite)
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def _validate_output_scope(target: Path, output: Path) -> None:
    anchor = Path(output.anchor)
    if output == anchor or output.parent == anchor:
        raise ValueError(
            "report output must not be a filesystem root or top-level directory"
        )
    if output == target:
        raise ValueError("report output cannot be the scan target")
    if target.is_relative_to(output):
        raise ValueError("report output cannot contain the scan target")


def _validate_existing_output(output: Path, overwrite: bool) -> None:
    if not output.exists():
        return
    if not output.is_dir():
        raise ValueError(f"report output exists and is not a directory: {output}")
    if not overwrite:
        raise ValueError(
            f"report output already exists; choose a new path or use --overwrite: {output}"
        )
    entries = list(output.iterdir())
    marker = output / "scan-manifest.json"
    if entries and not _is_suite_report(marker):
        raise ValueError(
            "refusing to overwrite a non-empty directory that is not a "
            "Python Security Suite report"
        )


def _is_suite_report(marker: Path) -> bool:
    if marker.name != "scan-manifest.json" or not marker.is_file():
        return False
    return is_complete_report(marker.parent)


def _append_github_summary(summary: Path) -> None:
    destination = os.environ.get("GITHUB_STEP_SUMMARY")
    if not destination:
        raise ValueError(
            "--github-summary requires the GITHUB_STEP_SUMMARY environment variable"
        )
    with Path(destination).open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(summary.read_text(encoding="utf-8"))
        handle.write("\n")


def _write_inspection_output(
    *, report: Path, output: Path, content: str, overwrite: bool
) -> Path:
    """Publish a derived inspection without modifying its sealed source report."""
    return _write_atomic_output(
        output=output,
        content=content,
        overwrite=overwrite,
        label="inspection output",
        forbidden_root=report,
    )


def _write_atomic_output(
    *,
    output: Path,
    content: str,
    overwrite: bool,
    label: str,
    forbidden_root: Path | None = None,
) -> Path:
    """Publish text atomically after link and replacement safety checks."""
    requested = output.expanduser().absolute()
    anchor = Path(requested.anchor)
    destination = resolve_unlinked_path(
        requested,
        label,
        boundary=anchor,
    )
    protected_root = (
        forbidden_root.expanduser().absolute().resolve()
        if forbidden_root is not None
        else None
    )
    if protected_root is not None and (
        destination == protected_root or destination.is_relative_to(protected_root)
    ):
        raise ValueError(f"{label} must be outside the sealed report directory")
    if destination.exists():
        if not destination.is_file():
            raise ValueError(f"{label} exists and is not a file: {destination}")
        if not overwrite:
            raise ValueError(
                f"{label} already exists; choose a new path or use "
                f"--overwrite: {destination}"
            )
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)
            temporary.unlink()
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def _render_attestation_verification(verification: dict[str, object]) -> str:
    scope = str(verification.get("verification_scope") or "unknown").replace("-", " ")
    passport_files = int(str(verification.get("passport_files_verified") or 0))
    report = verification.get("report")
    report_detail = "source report not supplied"
    if isinstance(report, dict):
        report_detail = f"{int(report.get('file_count') or 0)} report files"
    artifact_count = int(str(verification.get("release_artifacts_verified_count") or 0))
    artifact_detail = "release artifacts not declared"
    if verification.get("release_artifacts_required") is True:
        artifact_detail = (
            f"{artifact_count} release artifacts"
            if verification.get("release_artifacts_verified") is True
            else "release artifacts not supplied"
        )
    outcome = str(verification.get("outcome") or "unknown").upper()
    policy = str(
        verification.get("policy_verification_result")
        or verification.get("verification_result")
        or "UNKNOWN"
    )
    decision = str(verification.get("release_decision") or "not_approved").replace(
        "_", " "
    )
    lines = [
        f"VERIFIED ({scope}): {passport_files} passport files; "
        f"{report_detail}; {artifact_detail}",
        f"Policy: {outcome} ({policy}); release decision: {decision.upper()}",
    ]
    blockers = verification.get("release_blockers")
    if isinstance(blockers, list) and blockers:
        lines.append(
            "Blockers: " + "; ".join(str(value).replace("_", " ") for value in blockers)
        )
    return "\n".join(lines)
