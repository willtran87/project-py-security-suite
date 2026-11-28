"""Markdown security summary (summary.md) rendering."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .report_markdown import _markdown_text, _markdown_code
from .admission import admission_decisions
from .models import Finding, FindingStatus, Outcome, ScanManifest, Severity, ToolRun
from .portfolio_health import activation_recipe, portfolio_health_artifact
from .report_common import (
    _advanced_taint_alignment_counts,
    _applicable_scanner_gaps,
    _applicable_tools,
    _area_summary,
    _completed_tools,
    _coverage_action,
    _entrypoint_integrity_counts,
    _executable_integrity_label,
    _markdown_table,
    _markdown_tool_reference,
    _next_action,
    _next_action_for_manifest,
    _not_applicable_scanners,
    _policy_disposition,
    _report_release_status,
    _sdk_dependency_context_summary,
)
from .report_markdown_findings import _render_markdown_findings
from .report_risk_path_summary import _render_risk_path_summary


__all__ = [
    "_render_data_exposure_summary",
    "_render_domain_assurance_summary",
    "_render_fusion_summary",
    "_render_llm_adversarial_summary",
    "_render_structural_summary",
    "render_summary",
]


def render_summary(
    manifest: ScanManifest,
    findings: list[Finding],
    evidence_fusion: dict[str, Any] | None = None,
    structural_synthesis: dict[str, Any] | None = None,
    data_exposure: dict[str, Any] | None = None,
    risk_paths: dict[str, Any] | None = None,
    advanced_analysis: dict[str, Any] | None = None,
    application_contracts: dict[str, Any] | None = None,
    code_health: dict[str, Any] | None = None,
    static_architecture: dict[str, Any] | None = None,
    domain_assurance: dict[str, Any] | None = None,
    llm_adversarial: dict[str, Any] | None = None,
    industry_assurance: dict[str, Any] | None = None,
) -> str:
    active_findings = [
        finding
        for finding in findings
        if finding.status is not FindingStatus.SUPPRESSED
    ]
    coverage_gaps = _applicable_scanner_gaps(manifest.tools)
    not_applicable = _not_applicable_scanners(manifest.tools)
    tool_versions = {run.tool: run.version for run in manifest.tools}
    lines = _render_summary_header(
        manifest,
        active_findings,
        governed_count=len(findings) - len(active_findings),
        coverage_gap_count=len(coverage_gaps),
    )
    closure_backlog = (
        "**Owned closure backlog:** `closure-plan.json` is the stable, "
        + "machine-readable work plan. Render it with "
        + "`pysec closure-plan REPORT --format markdown`."
    )
    lines.extend(["", closure_backlog])
    lines.extend(_render_validation_summary(active_findings))
    lines.extend(
        _render_contextual_analysis_summary(
            application_contracts, code_health, static_architecture
        )
    )
    lines.extend(_render_domain_assurance_summary(domain_assurance))
    lines.extend(_render_llm_adversarial_summary(llm_adversarial))
    lines.extend(_render_industry_assurance_summary(industry_assurance))
    lines.extend(_render_fusion_summary(evidence_fusion))
    lines.extend(_render_structural_summary(structural_synthesis))
    lines.extend(_render_data_exposure_summary(data_exposure))
    lines.extend(_render_advanced_analysis_summary(advanced_analysis))
    lines.extend(_render_risk_path_summary(risk_paths))
    lines.extend(["", "## Decision", ""])
    lines.extend(f"- {reason}" for reason in manifest.policy_reasons)
    lines.extend(_render_admission_decisions(manifest, active_findings))
    lines.extend(_render_finding_lifecycle(manifest, active_findings))
    lines.extend(_render_finding_rollups(active_findings))
    lines.extend(_render_portfolio_health(manifest, active_findings))
    lines.extend(_render_markdown_findings(active_findings, tool_versions))
    lines.extend(_render_tool_coverage(manifest.tools, coverage_gaps, not_applicable))
    lines.extend(_render_coverage_actions(manifest, coverage_gaps, not_applicable))
    lines.extend(_render_derived_evidence(manifest))
    lines.extend(_render_triage_workflow(manifest.outcome))
    return "\n".join(lines)


def _render_validation_summary(findings: list[Finding]) -> list[str]:
    counts = Counter(finding.validation_status.value for finding in findings)
    return [
        "",
        "## Finding validation tiers",
        "",
        "| Strongest retained positive evidence | Findings |",
        "|---|---:|",
        f"| Reproduced | {counts.get('reproduced', 0)} |",
        f"| Runtime observed | {counts.get('runtime-observed', 0)} |",
        f"| Static path confirmed | {counts.get('static-path-confirmed', 0)} |",
        f"| Cross-tool corroborated | {counts.get('corroborated', 0)} |",
        f"| Static candidate | {counts.get('static-candidate', 0)} |",
        "",
        "The tier is independent of severity and lifecycle. Missing runtime evidence never establishes a false positive.",
    ]


def _render_contextual_analysis_summary(
    application: dict[str, Any] | None,
    health: dict[str, Any] | None,
    architecture: dict[str, Any] | None,
) -> list[str]:
    if not any(
        isinstance(value, dict) for value in (application, health, architecture)
    ):
        return []
    application = application or {}
    health = health or {}
    architecture = architecture or {}
    scenarios = application.get("generated_test_scenarios", [])
    execution_plan = application.get("scenario_execution_plan", {})
    policy_violations = architecture.get("policy_violations", [])
    return [
        "",
        "## Contextual security and engineering analysis",
        "",
        "| Signal | Count |",
        "|---|---:|",
        f"| Statically recognized API routes | {len(application.get('routes', []))} |",
        f"| Generated security test scenarios | {len(scenarios) if isinstance(scenarios, list) else 0} |",
        f"| Authorized companion execution tasks | {int(execution_plan.get('tasks_detected', 0)) if isinstance(execution_plan, dict) else 0} |",
        f"| Exact vulnerable-function calls | {len(application.get('vulnerable_call_matches', []))} |",
        f"| Code-health issues | {int(health.get('issues_detected', 0))} |",
        f"| Code-health issue details omitted | {int(health.get('issues_omitted', 0))} |",
        f"| Architecture cycles | {int(architecture.get('cycles_detected', 0))} |",
        f"| Local symbol-call edges | {int(architecture.get('symbol_edges_detected', 0))} |",
        f"| Unified static entry points | {int(architecture.get('entrypoint_symbols_detected', 0))} |",
        f"| Unresolved dynamic imports | {int(architecture.get('unresolved_dynamic_imports', 0))} |",
        f"| Declared architecture-policy violations | {len(policy_violations) if isinstance(policy_violations, list) else 0} |",
        "",
        "Generated scenario manifests and argv-safe companion tasks are machine-actionable plans, not execution evidence. Symbol calls and unified decorator, packaging, module-main, and main-guard entry points are syntactic evidence, while unresolved dynamic imports expose model gaps. Architecture and code-health signals prioritize review; declared native or Tach policy violations remain distinct from heuristic structural smells.",
    ]


def _render_domain_assurance_summary(value: dict[str, Any] | None) -> list[str]:
    if not isinstance(value, dict) or not isinstance(value.get("domains"), list):
        return []
    rows = [
        "",
        "## Cross-domain assurance coverage",
        "",
        f"**Coverage:** {int(value.get('covered_domains', 0))}/{int(value.get('applicable_domains', 0))} applicable domains ({int(value.get('coverage_score', 0))}%).",
        "",
        "| Domain | Applicability | Status | Requirements |",
        "|---|---|---|---:|",
    ]
    for domain in value["domains"]:
        if not isinstance(domain, dict):
            continue
        rows.append(
            f"| {_markdown_table(str(domain.get('name', 'unknown')))} | "
            f"{_markdown_table(str(domain.get('applicability', 'unknown')))} | "
            f"{_markdown_table(str(domain.get('status', 'unknown')))} | "
            f"{int(domain.get('requirements_satisfied', 0))}/"
            f"{int(domain.get('requirements_detected', 0))} |"
        )
    rows.extend(
        [
            "",
            "Surface detection establishes applicability only. A covered requirement has source-bound enforcement points, complete named artifacts, and passing source-bound test identities where behavior must be observed; it does not prove absence of defects.",
        ]
    )
    return rows


def _render_llm_adversarial_summary(value: dict[str, Any] | None) -> list[str]:
    if not isinstance(value, dict):
        return []
    counts = value.get("campaign_status_counts")
    evidence = value.get("evidence")
    if not isinstance(counts, dict) or not isinstance(evidence, dict):
        return []
    return [
        "",
        "## LLM-guided adversarial testing",
        "",
        "| Signal | Count/state |",
        "|---|---:|",
        f"| Prioritized campaigns | {int(value.get('campaigns_retained', 0))} |",
        f"| Context references | {int(value.get('context_entries_retained', 0))} |",
        f"| Authorized companion tasks | {int(value.get('execution_plan', {}).get('tasks_detected', 0))} |",
        f"| Campaigns not run | {int(counts.get('not-run', 0))} |",
        f"| Inconclusive campaigns | {int(counts.get('inconclusive', 0))} |",
        f"| Exercised without a confirmed defect | {int(counts.get('exercised-no-confirmed-defect', 0))} |",
        f"| Objectively confirmed defects | {int(counts.get('confirmed-defect', 0))} |",
        f"| Authenticated evidence source-bound | {'yes' if evidence.get('source_bound') is True else 'no'} |",
        "",
        "The plan treats repository and model text as untrusted data. An LLM proposal is never a finding by itself; confirmation requires authenticated source-bound execution, a deterministic oracle, a negative control, and mutation validation.",
    ]


def _render_industry_assurance_summary(value: dict[str, Any] | None) -> list[str]:
    if not isinstance(value, dict):
        return []
    interoperability = value.get("interoperability")
    supported = (
        sum(
            item.get("status") == "supported"
            for item in interoperability
            if isinstance(item, dict)
        )
        if isinstance(interoperability, list)
        else 0
    )
    total_formats = len(interoperability) if isinstance(interoperability, list) else 0
    return [
        "",
        "## Industry standards and benchmark assurance",
        "",
        "| Signal | Count/state |",
        "|---|---:|",
        f"| Versioned standards catalogs | {int(value.get('standards_registered', 0))} |",
        f"| Assurance packs selected | {int(value.get('assurance_profiles_selected', 0))}/{int(value.get('assurance_profiles_available', 0))} |",
        f"| Registered benchmark families | {int(value.get('benchmarks_registered', 0))} |",
        f"| Policy-declared controls satisfied | {int(value.get('controls_satisfied', 0))}/{int(value.get('controls_assessed', 0))} |",
        f"| Policy-declared procedures satisfied | {int(value.get('procedures_satisfied', 0))}/{int(value.get('procedures_assessed', 0))} |",
        f"| Governed benchmarks executed | {int(value.get('benchmarks_executed', 0))} |",
        f"| Interoperability formats observed/supported | {supported}/{total_formats} |",
        f"| Assessment complete | {'yes' if value.get('complete') is True else 'no'} |",
        "",
        str(value.get("claim_boundary") or ""),
    ]


def _render_fusion_summary(value: dict[str, Any] | None) -> list[str]:
    if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
        return []
    summary = value["summary"]
    lanes = value.get("evidence_lanes", [])
    gaps = (
        sum(
            len(item.get("execution_gaps", []))
            for item in lanes
            if isinstance(item, dict) and isinstance(item.get("execution_gaps"), list)
        )
        if isinstance(lanes, list)
        else 0
    )
    return [
        "",
        "## Cross-referenced evidence",
        "",
        "| Signal | Count |",
        "|---|---:|",
        f"| Findings enriched | {int(summary.get('findings_enriched', 0))} |",
        f"| Independent or cross-stage corroboration | {int(summary.get('independently_corroborated', 0))} |",
        f"| Changed-line findings | {int(summary.get('changed_line_findings', 0))} |",
        f"| Uncovered finding lines | {int(summary.get('uncovered_findings', 0))} |",
        f"| Source/artifact package version drift | {int(summary.get('version_drift_packages', 0))} |",
        f"| Distinct dependency advisories | {int(summary.get('distinct_advisories', 0))} |",
        f"| Retained advisory observations | {int(summary.get('advisory_observations', 0))} |",
        f"| Alias-equivalent observations consolidated for triage | {int(summary.get('alias_collapsed_observations', 0))} |",
        f"| Advisories with exact static import evidence | {int(summary.get('advisories_with_import_evidence', 0))} |",
        f"| Advisories imported by executable code | {int(summary.get('advisories_in_executable_imports', 0))} |",
        f"| Advisories with runtime-observed imports | {int(summary.get('runtime_observed_dependency_advisories', 0))} |",
        f"| Advisories whose package declaration is flagged unused | {int(summary.get('advisories_with_unused_declarations', 0))} |",
        f"| Import-versus-unused evidence conflicts | {int(summary.get('dependency_use_conflicts', 0))} |",
        f"| Known-exploited dependency advisories | {int(summary.get('known_exploited_advisories', 0))} |",
        f"| High-EPSS dependency advisories | {int(summary.get('high_epss_advisories', 0))} |",
        f"| Dependency advisories with scanner-reported fixes | {int(summary.get('advisories_with_fixed_versions', 0))} |",
        f"| P0 dependency advisories | {int(summary.get('p0_advisories', 0))} |",
        f"| Dependency advisories requiring VEX validation | {int(summary.get('advisories_requiring_vex_validation', 0))} |",
        f"| Dependency advisories with graph-selected focused tests | {int(summary.get('advisories_with_focused_tests', 0))} |",
        f"| Dependency advisories with passing focused-test evidence | {int(summary.get('advisories_with_passing_focused_test_evidence', 0))} |",
        f"| Dependency advisories with failing focused-test evidence | {int(summary.get('advisories_with_failing_focused_test_evidence', 0))} |",
        f"| Dependency advisories with selected tests not observed | {int(summary.get('advisories_with_unobserved_focused_tests', 0))} |",
        f"| Dependency advisories with introducing-root paths | {int(summary.get('advisories_with_introducing_dependency_paths', 0))} |",
        f"| Dependency advisories qualified by environment-health gaps | {int(summary.get('advisories_with_dependency_environment_gaps', 0))} |",
        f"| Transitive advisories without an introducing path | {int(summary.get('transitive_advisories_without_dependency_paths', 0))} |",
        f"| Dependency advisories with import-path owners | {int(summary.get('advisories_with_import_path_owners', 0))} |",
        f"| Dependency advisories on import paths below 80% coverage | {int(summary.get('advisories_with_uncovered_import_paths', 0))} |",
        f"| Passing focused tests with dependency import-path coverage gaps | {int(summary.get('advisories_with_test_coverage_mismatch', 0))} |",
        f"| Compound structural hotspots | {int(summary.get('compound_hotspots', 0))} |",
        f"| Evidence-lane execution gaps | {gaps} |",
        f"| Evidence contradictions | {int(summary.get('contradictions', 0))} |",
        "",
        "Detailed lineage, review reasons, limitations, and evidence-lane health are in `evidence-fusion.json`. Fusion guides triage; scanner severity and policy remain authoritative.",
    ]


def _render_structural_summary(value: dict[str, Any] | None) -> list[str]:
    if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
        return []
    summary = value["summary"]
    islands = value.get("island_assessments", [])
    changes = value.get("change_impact_assessments", [])
    orphans = value.get("orphan_symbol_candidates", [])
    boundaries = value.get("island_boundary_assessments", [])
    priority_islands = (
        [
            item
            for item in islands
            if isinstance(item, dict) and item.get("priority") in {"high", "medium"}
        ]
        if isinstance(islands, list)
        else []
    )
    priority_changes = (
        [
            item
            for item in changes
            if isinstance(item, dict) and item.get("priority") in {"high", "medium"}
        ]
        if isinstance(changes, list)
        else []
    )
    actionable_boundaries = (
        [
            item
            for item in boundaries
            if isinstance(item, dict)
            and item.get("boundary_classification")
            in {
                "candidate-missing-entry-point",
                "test-only-or-fixture",
                "closed-boundary",
            }
        ]
        if isinstance(boundaries, list)
        else []
    )
    interpretation = " ".join(
        (
            "Conclusions combine Graphify topology, entry-point reachability, runtime coverage, bounded case-level test execution, Vulture, Radon, Tach, and normalized findings.",
            "They are advisory; absence of runtime observation does not prove code is removable.",
        )
    )
    lines = [
        "",
        "## Structural synthesis",
        "",
        "| Signal | Count |",
        "|---|---:|",
        f"| Dead-code candidates cross-checked | {int(summary.get('dead_code_candidates', 0))} |",
        f"| Likely removable dead-code candidates | {int(summary.get('likely_removable_dead_code_candidates', 0))} |",
        f"| Likely dynamic dead-code candidates | {int(summary.get('likely_dynamic_dead_code_candidates', 0))} |",
        f"| Code islands analyzed | {int(summary.get('islands_analyzed', 0))} |",
        f"| Likely removable islands | {int(summary.get('likely_removable_islands', 0))} |",
        f"| Likely dynamic islands | {int(summary.get('likely_dynamic_islands', 0))} |",
        f"| Latent attack-surface islands | {int(summary.get('latent_attack_surface_islands', 0))} |",
        f"| Import cycles | {int(summary.get('import_cycles', 0))} |",
        f"| Architecture hotspots | {int(summary.get('architecture_hotspots', 0))} |",
        f"| Changed Python files analyzed | {int(summary.get('changed_python_files_analyzed', 0))} |",
        f"| Changed files without mapped tests | {int(summary.get('changed_files_without_mapped_tests', 0))} |",
        f"| Changed files with uncovered lines | {int(summary.get('changed_files_with_uncovered_lines', 0))} |",
        f"| High-priority change hotspots | {int(summary.get('high_priority_change_hotspots', 0))} |",
        f"| Graph-recommended test files | {int(summary.get('recommended_test_files', 0))} |",
        f"| Changed files with passing focused-test evidence | {int(summary.get('changed_files_with_passing_focused_tests', 0))} |",
        f"| Changed files with failing focused-test evidence | {int(summary.get('changed_files_with_failing_focused_tests', 0))} |",
        f"| Changed files with selected tests not observed | {int(summary.get('changed_files_with_unobserved_focused_tests', 0))} |",
        f"| Passing focused tests with uncovered changed lines | {int(summary.get('passing_focused_tests_with_coverage_gaps', 0))} |",
        f"| Changed files aligned across focused tests and changed-line coverage | {int(summary.get('validation_aligned_changed_files', 0))} |",
        f"| Structural orphan symbols | {int(summary.get('orphan_symbol_candidates', 0))} |",
        f"| Candidate missing entry points | {int(summary.get('candidate_missing_entry_points', 0))} |",
        f"| Test-only island candidates | {int(summary.get('test_only_island_candidates', 0))} |",
        "",
        interpretation,
    ]
    if priority_islands:
        lines.extend(
            [
                "",
                "| Priority island | Classification | LOC | Action |",
                "|---|---|---:|---|",
            ]
        )
        lines.extend(
            (
                "| `"
                + _markdown_code(str(item.get("island_id", "unknown")))
                + "` | `"
                + _markdown_code(str(item.get("classification", "review")))
                + "` | "
                + str(int(item.get("lines_of_code", 0)))
                + " | "
                + _markdown_text(str(item.get("recommended_action", "Review.")))
                + " |"
            )
            for item in priority_islands[:5]
        )
    if priority_changes:
        lines.extend(
            [
                "",
                "| Change hotspot | Classification | Risk | Mapped tests | Validation | Validation action | Change action |",
                "|---|---|---:|---:|---|---|---|",
            ]
        )
        lines.extend(
            "| `"
            + _markdown_code(str(item.get("path", "unknown")))
            + "` | `"
            + _markdown_code(str(item.get("classification", "review")))
            + "` | "
            + str(int(item.get("risk_score", 0)))
            + " | "
            + str(
                len(item.get("direct_test_files", []))
                + len(item.get("transitive_test_files", []))
                + len(item.get("associated_test_files", []))
            )
            + " | `"
            + _markdown_code(str(item.get("test_coverage_alignment", "not-available")))
            + "` | "
            + _markdown_text(
                str(
                    item.get("validation_action")
                    or item.get("recommended_action", "Review.")
                )
            )
            + " | "
            + _markdown_text(str(item.get("recommended_action", "Review.")))
            + " |"
            for item in priority_changes[:5]
        )
    if isinstance(orphans, list) and orphans:
        lines.extend(
            [
                "",
                "| Structural orphan | Location | Classification | Confidence | Action |",
                "|---|---|---|---|---|",
            ]
        )
        lines.extend(
            "| `"
            + _markdown_code(str(item.get("label", "unknown")))
            + "` | `"
            + _markdown_code(str(item.get("path", "unknown")))
            + ":"
            + str(int(item.get("line", 1)))
            + "` | `"
            + _markdown_code(str(item.get("classification", "review")))
            + "` | `"
            + _markdown_code(str(item.get("confidence", "low")))
            + "` | "
            + _markdown_text(str(item.get("recommended_action", "Review.")))
            + " |"
            for item in orphans[:5]
            if isinstance(item, dict)
        )
    if actionable_boundaries:
        lines.extend(
            [
                "",
                "| Island boundary review | Classification | Boundary relations | Entry paths | Action |",
                "|---|---|---:|---:|---|",
            ]
        )
        lines.extend(
            "| `"
            + _markdown_code(str(item.get("island_id", "unknown")))
            + "` | `"
            + _markdown_code(str(item.get("boundary_classification", "review")))
            + "` | "
            + str(int(item.get("boundary_relation_count", 0)))
            + " | "
            + str(len(item.get("candidate_entry_paths", [])))
            + " | "
            + _markdown_text(str(item.get("recommended_action", "Review.")))
            + " |"
            for item in actionable_boundaries[:5]
        )
    return lines


def _render_data_exposure_summary(value: dict[str, Any] | None) -> list[str]:
    if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
        return []
    summary = value["summary"]
    assessments = value.get("finding_assessments", [])
    surfaces = value.get("sink_surfaces", [])
    production_surfaces: list[dict[str, Any]] = (
        [
            item
            for item in surfaces
            if isinstance(item, dict) and item.get("scope") == "production"
        ]
        if isinstance(surfaces, list)
        else []
    )
    query_findings = sum(
        isinstance(item, dict) and item.get("sink_family") in {"url", "url-query"}
        for item in assessments
    )
    response_findings = sum(
        isinstance(item, dict)
        and item.get("sink_family") in {"client-response", "exception"}
        for item in assessments
    )
    lines = [
        "",
        "## Sensitive-data exposure",
        "",
        "| Signal | Count |",
        "|---|---:|",
        f"| Confirmed scanner findings correlated | {int(summary.get('exposure_findings', 0))} |",
        f"| Findings joined with finalized evidence fusion | {int(summary.get('fusion_enriched_findings', 0))} |",
        f"| Urgent cross-referenced exposure findings | {int(summary.get('urgent_cross_referenced_findings', 0))} |",
        f"| Findings on changed lines | {int(summary.get('changed_exposure_findings', 0))} |",
        f"| Findings on uncovered lines | {int(summary.get('uncovered_exposure_findings', 0))} |",
        f"| Runtime-observed exposure findings | {int(summary.get('runtime_observed_exposure_findings', 0))} |",
        f"| Broad upstream blast-radius findings | {int(summary.get('broad_blast_radius_findings', 0))} |",
        f"| Exposure findings with an assigned owner | {int(summary.get('owned_exposure_findings', 0))} |",
        f"| Exposure findings with graph-selected tests | {int(summary.get('exposure_findings_with_mapped_tests', 0))} |",
        f"| Exposure findings with passing-test/coverage mismatch | {int(summary.get('exposure_findings_with_validation_mismatch', 0))} |",
        f"| Exposure findings in high-risk changes | {int(summary.get('high_change_risk_exposure_findings', 0))} |",
        f"| Exposure findings with SDK package risk | {int(summary.get('exposure_findings_with_sdk_package_risk', 0))} |",
        f"| Sensitive logging findings | {int(summary.get('logging_findings', 0))} |",
        f"| Telemetry and analytics findings | {int(summary.get('telemetry_findings', 0))} |",
        f"| Sensitive URL-query findings | {query_findings} |",
        f"| Raw exception response findings | {response_findings} |",
        f"| Production sink review surfaces | {int(summary.get('production_sink_surfaces', 0))} |",
        f"| Test sink review surfaces | {int(summary.get('test_sink_surfaces', 0))} |",
        f"| Explicit risky or invalid capture configurations | {int(summary.get('configuration_review_surfaces', 0))} |",
        f"| High-priority production review surfaces | {int(summary.get('high_priority_review_surfaces', 0))} |",
        f"| Surfaces with sensitive-data context | {int(summary.get('sensitive_context_surfaces', 0))} |",
        f"| Surfaces with an explicit protection signal | {int(summary.get('protected_surfaces', 0))} |",
        f"| Sink surfaces joined with structural/test context | {int(summary.get('structurally_enriched_surfaces', 0))} |",
        f"| Changed sink surfaces | {int(summary.get('changed_sink_surfaces', 0))} |",
        f"| Uncovered sink surfaces | {int(summary.get('uncovered_sink_surfaces', 0))} |",
        f"| Runtime-observed sink surfaces | {int(summary.get('runtime_observed_sink_surfaces', 0))} |",
        f"| Disconnected sink surfaces | {int(summary.get('disconnected_sink_surfaces', 0))} |",
        f"| Sink surfaces near normalized findings | {int(summary.get('compound_sink_surfaces', 0))} |",
        f"| Sink surfaces with an assigned owner | {int(summary.get('owned_sink_surfaces', 0))} |",
        f"| Sink surfaces with graph-selected tests | {int(summary.get('sink_surfaces_with_mapped_tests', 0))} |",
        f"| Sink surfaces with passing-test/coverage mismatch | {int(summary.get('sink_surfaces_with_validation_mismatch', 0))} |",
        f"| Sink surfaces in high-risk changes | {int(summary.get('high_change_risk_sink_surfaces', 0))} |",
        f"| Sink surfaces in structural hotspots | {int(summary.get('sink_surfaces_in_structural_hotspots', 0))} |",
        f"| Sink surfaces with SDK package risk | {int(summary.get('sink_surfaces_with_sdk_package_risk', 0))} |",
        f"| SDK packages correlated | {int(summary.get('sdk_packages_correlated', 0))} |",
        f"| SDK packages with normalized findings | {int(summary.get('sdk_packages_with_findings', 0))} |",
        f"| SDK packages with source/artifact version drift | {int(summary.get('sdk_packages_with_version_drift', 0))} |",
        f"| Distinct advisories affecting SDK packages | {int(summary.get('sdk_distinct_advisories', 0))} |",
        f"| Retained SDK advisory observations | {int(summary.get('sdk_advisory_observations', 0))} |",
        f"| SDK advisories with exact import evidence | {int(summary.get('sdk_advisories_with_import_evidence', 0))} |",
        f"| SDK advisories imported by executable code | {int(summary.get('sdk_advisories_in_executable_imports', 0))} |",
        f"| SDK advisories whose packages are flagged unused | {int(summary.get('sdk_advisories_flagged_unused', 0))} |",
        f"| Known-exploited SDK advisories | {int(summary.get('sdk_known_exploited_advisories', 0))} |",
        f"| High-EPSS SDK advisories | {int(summary.get('sdk_high_epss_advisories', 0))} |",
        f"| SDK advisories with scanner-reported fixes | {int(summary.get('sdk_advisories_with_fixed_versions', 0))} |",
        f"| P0 SDK advisories | {int(summary.get('sdk_p0_advisories', 0))} |",
        f"| SDK advisories requiring VEX validation | {int(summary.get('sdk_advisories_requiring_vex_validation', 0))} |",
        f"| SDK advisories with graph-selected focused tests | {int(summary.get('sdk_advisories_with_focused_tests', 0))} |",
        f"| SDK advisories with passing focused-test evidence | {int(summary.get('sdk_advisories_with_passing_focused_test_evidence', 0))} |",
        f"| SDK advisories with failing focused-test evidence | {int(summary.get('sdk_advisories_with_failing_focused_test_evidence', 0))} |",
        f"| SDK advisories with selected tests not observed | {int(summary.get('sdk_advisories_with_unobserved_focused_tests', 0))} |",
        f"| SDK advisories with introducing-root paths | {int(summary.get('sdk_advisories_with_introducing_dependency_paths', 0))} |",
        f"| SDK advisories qualified by environment-health gaps | {int(summary.get('sdk_advisories_with_dependency_environment_gaps', 0))} |",
        f"| Transitive SDK advisories without an introducing path | {int(summary.get('sdk_transitive_advisories_without_dependency_paths', 0))} |",
        f"| SDK advisories with import-path owners | {int(summary.get('sdk_advisories_with_import_path_owners', 0))} |",
        f"| SDK advisories on import paths below 80% coverage | {int(summary.get('sdk_advisories_with_uncovered_import_paths', 0))} |",
        f"| Passing SDK focused tests with import-path coverage gaps | {int(summary.get('sdk_advisories_with_test_coverage_mismatch', 0))} |",
        f"| Logging, telemetry, analytics, and egress SDK families | {int(summary.get('sdk_families_observed', 0))} |",
        "",
        "A sink surface is an inventory item, not proof of leakage. A finding requires source-to-sink scanner evidence and retains CWE/OWASP guidance.",
    ]
    if isinstance(assessments, list) and assessments:
        lines.extend(
            [
                "",
                "| Exposure finding | Location | Triage / data class | Sink / SDK | Relevance | Cross-reference context | Action |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        lines.extend(
            "| `"
            + _markdown_code(str(item.get("finding_id", "unknown")))
            + "` | `"
            + _markdown_code(str(item.get("path", "unknown")))
            + (":" + str(item["line"]) if item.get("line") else "")
            + "` | `"
            + _markdown_code(str(item.get("triage_tier", "standard")))
            + "` / "
            + _markdown_text(
                ", ".join(str(value) for value in item.get("data_classes", []))
                or "unclassified"
            )
            + " | `"
            + _markdown_code(str(item.get("sink_family", "unknown")))
            + (" / " + _markdown_code(str(item["sdk"])) if item.get("sdk") else "")
            + "` | `"
            + _markdown_code(str(item.get("structural_relevance", "unknown")))
            + "` | "
            + _markdown_text(_exposure_summary_context(item))
            + " | "
            + _markdown_text(str(item.get("recommended_action", "Review.")))
            + " |"
            for item in assessments[:5]
            if isinstance(item, dict)
        )
    if production_surfaces:
        lines.extend(
            [
                "",
                "| Top production sink surface | Family | Priority | Data class | Protection | Cross-reference context | Next verification |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        lines.extend(
            "| `"
            + _markdown_code(str(item.get("path", "unknown")))
            + ":"
            + str(int(item.get("line", 1)))
            + "`<br>"
            + _markdown_text(str(item.get("label", item.get("sink", "sink"))))
            + " | `"
            + _markdown_code(str(item.get("sink_family", "unknown")))
            + "` | `"
            + _markdown_code(str(item.get("review_priority", "medium")))
            + "` | "
            + _markdown_text(
                ", ".join(str(value) for value in item.get("data_classes", []))
                or "unclassified"
            )
            + " | `"
            + _markdown_code(str(item.get("protection_status", "not-observed")))
            + "` | "
            + _markdown_text(_surface_summary_context(item))
            + " | "
            + _markdown_text(
                "; ".join(
                    str(step).rstrip(".")
                    for step in (
                        item.get("verification_steps") or ["Review the sink context."]
                    )[:2]
                )
                + "."
            )
            + " |"
            for item in sorted(
                production_surfaces,
                key=lambda surface: (
                    {"high": 0, "medium": 1, "low": 2}.get(
                        str(surface.get("review_priority")), 3
                    ),
                    {"high": 0, "medium": 1, "none": 2}.get(
                        str(surface.get("sdk_dependency_context", {}).get("risk_tier")),
                        3,
                    ),
                    str(surface.get("path")),
                    int(surface.get("line") or 0),
                ),
            )[:5]
        )
    return lines


def _render_advanced_analysis_summary(value: dict[str, Any] | None) -> list[str]:
    if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
        return []
    summary = value["summary"]
    controls = value.get("control_topology")
    controls = controls if isinstance(controls, list) else []
    privacy = value.get("telemetry_privacy_topology")
    privacy = privacy if isinstance(privacy, list) else []
    dependencies = value.get("dependency_trust_routes")
    dependencies = dependencies if isinstance(dependencies, list) else []
    aligned_taint_paths, retained_taint_paths = _advanced_taint_alignment_counts(value)
    lines = [
        "",
        "## Cross-evidence security leverage",
        "",
        (
            "This section connects route topology, scanner-confirmed flows, release "
            "metadata, threats, tests, mutations, telemetry, and dependency evidence. "
            "Structural relationships are review evidence, not proof of exploitability "
            "or control effectiveness."
        ),
        "",
        "| Decision signal | Count |",
        "|---|---:|",
        f"| Typed evidence nodes / relationships | {int(summary.get('relationship_nodes', 0))} / {int(summary.get('relationship_edges', 0))} |",
        f"| Mandatory / bypass-capable candidate controls | {int(summary.get('mandatory_control_points', 0))} / {int(summary.get('bypass_capable_control_points', 0))} |",
        f"| Shared mandatory security-route points | {int(summary.get('shared_mandatory_security_route_points', 0))} |",
        f"| Scanner-confirmed taint paths / retained steps | {int(summary.get('scanner_confirmed_taint_paths', 0))} / {int(summary.get('retained_taint_steps', 0))} |",
        f"| Ordered route-aligned / not-established taint paths | {aligned_taint_paths} / {retained_taint_paths - aligned_taint_paths} |",
        f"| Published / unmodeled artifact entry points | {int(summary.get('published_entry_points', 0))} / {int(summary.get('unmodeled_published_entry_points', 0))} |",
        f"| Wheel RECORD integrity gaps | {int(summary.get('wheel_record_integrity_gaps', 0))} |",
        f"| Threats without control / source-bound passing test evidence | {int(summary.get('threats_without_control_evidence', 0))} / {int(summary.get('threats_without_test_evidence', 0))} |",
        f"| Security-control mutations without source-bound passing tests | {int(summary.get('security_control_mutations_without_test_evidence', 0))} |",
        f"| Telemetry routes without observed protection / with ordering risk | {int(summary.get('telemetry_routes_without_observed_protection', 0))} / {int(summary.get('telemetry_routes_with_redaction_order_risk', 0))} |",
        f"| Elevated dependency trust routes | {int(summary.get('elevated_dependency_trust_routes', 0))} |",
    ]
    lines.extend(_render_advanced_controls(controls))
    lines.extend(_render_advanced_privacy(privacy))
    lines.extend(_render_advanced_dependencies(dependencies))
    lines.extend(
        [
            "",
            "The complete, machine-readable evidence graph and every retained record are in `advanced-analysis.json`.",
        ]
    )
    return lines


def _render_advanced_controls(values: list[Any]) -> list[str]:
    review = [
        item
        for item in values
        if isinstance(item, dict)
        and (
            item.get("topology_status") in {"bypass-capable", "not-established"}
            or item.get("shared_mandatory_security_route_point") is True
        )
    ]
    if not review:
        return []
    lines = [
        "",
        "### Control topology decisions",
        "",
        "| Status | Candidate control | Scope | Owner / action |",
        "|---|---|---:|---|",
    ]
    for item in review[:10]:
        owners = item.get("owners")
        owner_text = (
            ", ".join(str(owner) for owner in owners[:5])
            if isinstance(owners, list)
            else ""
        )
        lines.append(
            "| `"
            + _markdown_code(str(item.get("topology_status") or "unknown"))
            + "`"
            + (
                "<br>shared mandatory security-route point"
                if item.get("shared_mandatory_security_route_point")
                else ""
            )
            + " | `"
            + _markdown_code(str(item.get("path") or "unknown"))
            + "` | "
            + str(len(item.get("entry_point_ids") or []))
            + " entries / "
            + str(len(item.get("target_ids") or []))
            + " targets | "
            + _markdown_text(owner_text or "Unassigned")
            + "<br>"
            + _markdown_text(str(item.get("recommended_action") or "Review."))
            + " |"
        )
    return lines


def _render_advanced_privacy(values: list[Any]) -> list[str]:
    review = [
        item
        for item in values
        if isinstance(item, dict)
        and item.get("review_status") != "protected-static-route"
    ]
    if not review:
        return []
    lines = [
        "",
        "### Telemetry privacy decisions",
        "",
        "| Status | Route / boundary | Protection | Action |",
        "|---|---|---|---|",
    ]
    for item in review[:10]:
        path = str(item.get("path") or "unknown")
        if isinstance(item.get("line"), int):
            path += f":{item['line']}"
        lines.append(
            "| `"
            + _markdown_code(str(item.get("review_status") or "review"))
            + "` | `"
            + _markdown_code(path)
            + "`<br>boundary `"
            + _markdown_code(str(item.get("trust_boundary") or "unknown"))
            + "` | `"
            + _markdown_code(str(item.get("protection_status") or "unknown"))
            + "`<br>redaction `"
            + _markdown_code(str(item.get("redaction_order") or "not-established"))
            + "`<br>native control correlation `"
            + str(
                len(item.get("control_point_ids_observed_on_every_aligned_path") or [])
            )
            + "/"
            + str(len(item.get("mandatory_control_point_ids") or []))
            + " mandatory`"
            + " | "
            + _markdown_text(str(item.get("recommended_action") or "Review."))
            + " |"
        )
    return lines


def _render_advanced_dependencies(values: list[Any]) -> list[str]:
    elevated = [
        item
        for item in values
        if isinstance(item, dict) and item.get("review_tier") in {"critical", "high"}
    ]
    if not elevated:
        return []
    lines = [
        "",
        "### Elevated dependency trust routes",
        "",
        "| Tier | Package / importer | Evidence factors | Action |",
        "|---|---|---|---|",
    ]
    for item in elevated[:10]:
        factors = item.get("risk_factors")
        factor_text = (
            ", ".join(str(value) for value in factors)
            if isinstance(factors, list)
            else ""
        )
        lines.append(
            "| `"
            + _markdown_code(str(item.get("review_tier") or "unknown"))
            + "` score `"
            + _markdown_code(str(item.get("review_score") or 0))
            + "` | `"
            + _markdown_code(str(item.get("package") or "unknown"))
            + "`<br>`"
            + _markdown_code(str(item.get("path") or "unknown"))
            + "` | "
            + _markdown_text(factor_text or "No elevated factors retained")
            + " | "
            + _markdown_text(str(item.get("recommended_action") or "Review."))
            + " |"
        )
    return lines


def _surface_context_summary(value: Any) -> str:
    if not isinstance(value, dict) or not value.get("context_available"):
        return "not available"
    signals: list[str] = []
    if value.get("changed_line") is True:
        signals.append("changed")
    if value.get("line_covered") is False:
        signals.append("uncovered")
    elif value.get("line_covered") is True:
        signals.append("covered")
    states = value.get("reachability_states")
    if isinstance(states, list) and states:
        signals.append("reachability " + "/".join(str(item) for item in states[:2]))
    observations = value.get("runtime_observations")
    if isinstance(observations, list) and "observed" in observations:
        signals.append("runtime observed")
    upstream = value.get("graph_upstream_files")
    if isinstance(upstream, int):
        signals.append(f"{upstream} upstream")
    related = value.get("related_finding_ids")
    if isinstance(related, list) and related:
        identifiers = ", ".join(str(item) for item in related[:2])
        tools = value.get("related_tools")
        attribution = (
            " via " + ", ".join(str(item) for item in tools[:3])
            if isinstance(tools, list) and tools
            else ""
        )
        signals.append(f"nearby {identifiers}{attribution}")
    owners = value.get("owners")
    if isinstance(owners, list) and owners:
        signals.append("owner " + ", ".join(str(item) for item in owners[:2]))
    mapped = value.get("mapped_test_files")
    if isinstance(mapped, list) and mapped:
        signals.append("mapped " + ", ".join(str(item) for item in mapped[:2]))
    alignment = value.get("test_coverage_alignment")
    if isinstance(alignment, str):
        signals.append("validation " + alignment)
    change_priority = value.get("change_risk_priority")
    change_score = value.get("change_risk_score")
    if isinstance(change_priority, str):
        signals.append(
            f"change risk {change_priority}"
            + (f"/{change_score}" if isinstance(change_score, int) else "")
        )
    risks = value.get("structural_risk_kinds")
    if isinstance(risks, list) and risks:
        signals.append("structural " + ", ".join(str(item) for item in risks[:2]))
    return "; ".join(signals) or "context available"


def _exposure_accountability_summary(value: Any) -> str:
    if not isinstance(value, dict):
        return "unassigned; no mapped tests"
    owners = value.get("owners")
    mapped = value.get("mapped_test_files")
    parts = [
        "owners " + ", ".join(str(item) for item in owners[:2])
        if isinstance(owners, list) and owners
        else "unassigned"
    ]
    if isinstance(mapped, list) and mapped:
        parts.append("mapped " + ", ".join(str(item) for item in mapped[:2]))
    else:
        parts.append("no mapped tests")
    alignment = value.get("test_coverage_alignment")
    if isinstance(alignment, str):
        parts.append("validation " + alignment)
    priority = value.get("change_risk_priority")
    score = value.get("change_risk_score")
    if isinstance(priority, str):
        parts.append(
            f"change risk {priority}" + (f"/{score}" if isinstance(score, int) else "")
        )
    risks = value.get("structural_risk_kinds")
    if isinstance(risks, list) and risks:
        parts.append("structural " + ", ".join(str(item) for item in risks[:2]))
    return "; ".join(parts)


def _exposure_summary_context(item: dict[str, Any]) -> str:
    values = [
        _exposure_accountability_summary(item.get("cross_references")),
        _sdk_dependency_context_summary(item.get("sdk_dependency_context")),
    ]
    return "; ".join(value for value in values if value)


def _surface_summary_context(item: dict[str, Any]) -> str:
    values = [
        _surface_context_summary(item.get("structural_context")),
        _sdk_dependency_context_summary(item.get("sdk_dependency_context")),
    ]
    return "; ".join(value for value in values if value)


def _render_admission_decisions(
    manifest: ScanManifest, findings: list[Finding]
) -> list[str]:
    decisions = admission_decisions(
        findings,
        manifest.tools,
        network_isolation_attested=manifest.network_isolation_attested,
        source_integrity_verified=manifest.inventory.source_integrity_verified,
    )
    lines = [
        "",
        "## Admission decisions by evidence axis",
        "",
        "These cards separate evidence domains for triage. The scan-policy decision above remains authoritative.",
        "",
        "| Evidence axis | Decision | Completed / applicable | Findings | Blocking | Gaps | Required action |",
        "|---|:---:|---:|---:|---:|---|---|",
    ]
    for row in decisions["axes"]:
        gaps = [*row["execution_gaps"], *row["integrity_gaps"]]
        lines.append(
            f"| {_markdown_table(row['label'])} | "
            f"**{_markdown_table(row['decision'].upper())}** | "
            f"{row['completed_tools']}/{row['applicable_tools']} | "
            f"{row['active_findings']} | {row['blocking_findings']} | "
            f"{_markdown_table('; '.join(gaps) or '-')} | "
            f"{_markdown_table(row['required_action'])} |"
        )
    return lines


def _render_summary_header(
    manifest: ScanManifest,
    active_findings: list[Finding],
    *,
    governed_count: int,
    coverage_gap_count: int,
) -> list[str]:
    entrypoints, approved_entrypoints, unchanged_entrypoints = (
        _entrypoint_integrity_counts(manifest.tools)
    )
    counts = {
        severity.value: sum(finding.severity is severity for finding in active_findings)
        for severity in Severity
    }
    health = portfolio_health_artifact(
        active_findings,
        manifest.tools,
        outcome=manifest.outcome,
        policy_reasons=manifest.policy_reasons,
    )["overall"]
    release_status = _report_release_status(manifest.outcome)
    return [
        f"# Security result: {manifest.outcome.value.upper()}",
        "",
        f"- **Scan:** `{_markdown_code(manifest.scan_id)}`",
        f"- **Profile:** `{_markdown_code(manifest.profile)}`",
        f"- **Target:** `{_markdown_code(manifest.target)}`",
        f"- **Scan-policy disposition:** {_policy_disposition(manifest.outcome)}",
        f"- **Findings:** {len(active_findings)} active, {governed_count} governed; "
        f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
        f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low",
        f"- **Applicable scanners completed:** "
        f"{_completed_tools(manifest.tools)}/{_applicable_tools(manifest.tools)}",
        f"- **Not applicable:** "
        f"{len(manifest.tools) - _applicable_tools(manifest.tools)} selected tool(s)",
        f"- **Applicable scanner execution gaps:** {coverage_gap_count}",
        f"- **Execution coverage grade:** {health['execution_grade']}; "
        f"{health['completed_control_slots']}/{health['applicable_control_slots']} "
        "applicable control slots completed",
        f"- **Observed-risk grade:** {health['risk_grade']} "
        f"({health['risk_status'].replace('_', ' ')})",
        f"- **Evidence grade:** {health['evidence_grade']} "
        f"({health['evidence_status'].replace('_', ' ')}); "
        f"release decision `{health['release_decision']}`",
        f"- **Release readiness from this report:** `{release_status}`; "
        "run `pysec release-check` for the governed aggregate decision",
        f"- **Network isolation attested:** "
        f"{'yes' if manifest.network_isolation_attested else 'no'}",
        f"- **Unisolated diagnostic execution:** "
        f"{'yes' if manifest.diagnostic_without_isolation else 'no'}",
        f"- **Target content integrity:** "
        f"{'verified unchanged' if manifest.inventory.source_integrity_verified else 'not verified'} "
        f"(`sha256:{_markdown_code(manifest.inventory.source_sha256)}`; "
        f"{manifest.inventory.hashed_files} files, "
        f"{manifest.inventory.hashed_bytes} bytes)",
        f"- **Scanner entry-point trust:** {approved_entrypoints}/{entrypoints} "
        f"approved and unchanged; {unchanged_entrypoints}/{entrypoints} observed "
        "unchanged after execution",
        f"- **Immediate next step:** {_next_action_for_manifest(manifest)}",
    ]


def _render_finding_lifecycle(
    manifest: ScanManifest, active_findings: list[Finding]
) -> list[str]:
    lifecycle = {
        status.value: sum(finding.status is status for finding in active_findings)
        for status in (
            FindingStatus.NEW,
            FindingStatus.EXISTING,
            FindingStatus.REGRESSION,
        )
    }
    resolved = (
        int(manifest.baseline.get("counts", {}).get("resolved", 0))
        if isinstance(manifest.baseline.get("counts"), dict)
        else 0
    )
    return [
        "",
        "## Finding lifecycle",
        "",
        f"- New: {lifecycle['new']}",
        f"- Existing: {lifecycle['existing']}",
        f"- Regressed: {lifecycle['regression']}",
        f"- Resolved since baseline: {resolved}",
    ]


def _render_finding_rollups(active_findings: list[Finding]) -> list[str]:
    lines = ["", "## Findings by domain", ""]
    lines.append("| Domain | Findings | Blocking |")
    lines.append("|---|---:|---:|")
    for domain, domain_findings in _domain_summary(active_findings):
        lines.append(
            f"| {_markdown_table(domain)} | {len(domain_findings)} | "
            f"{sum(1 for finding in domain_findings if finding.blocking)} |"
        )
    if not active_findings:
        lines.append("| No findings | 0 | 0 |")

    lines.extend(["", "## Findings by area", ""])
    lines.append(
        "| Area | Critical | High | Medium | Low | Informational/Unknown | Total |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for area, area_counts in _area_summary(active_findings):
        lines.append(
            f"| {_markdown_table(area)} | {area_counts['critical']} | "
            f"{area_counts['high']} | {area_counts['medium']} | "
            f"{area_counts['low']} | "
            f"{area_counts['informational'] + area_counts['unknown']} | "
            f"{area_counts['total']} |"
        )
    if not active_findings:
        lines.append("| No findings | 0 | 0 | 0 | 0 | 0 | 0 |")
    return lines


def _render_portfolio_health(
    manifest: ScanManifest, findings: list[Finding]
) -> list[str]:
    health = portfolio_health_artifact(
        findings,
        manifest.tools,
        outcome=manifest.outcome,
        policy_reasons=manifest.policy_reasons,
    )
    overall = health["overall"]
    lines = [
        "",
        "## Operational coverage by domain",
        "",
        (
            f"**Execution {overall['execution_grade']} · Risk "
            f"{overall['risk_grade']} · Evidence {overall['evidence_grade']}** — "
            f"{overall['completed_control_slots']}/"
            f"{overall['applicable_control_slots']} applicable control slots completed. "
            "These independent grades prevent completed execution from being mistaken "
            "for low risk, complete evidence, or release approval."
        ),
        "",
        "| Domain | Execution | Risk | Status | Completed / applicable | Findings | Blocking | Gaps |",
        "|---|:---:|:---:|---|---:|---:|---:|---|",
    ]
    for row in health["domains"]:
        gaps = ", ".join(row["execution_gaps"]) or "-"
        lines.append(
            f"| {_markdown_table(row['domain'])} | {row['execution_grade']} | "
            f"{row['risk_grade']} | "
            f"{_markdown_table(row['status'].replace('_', ' '))} | "
            f"{row['completed_tools']}/{row['applicable_tools']} | "
            f"{row['active_findings']} | {row['blocking_findings']} | "
            f"{_markdown_table(gaps)} |"
        )
    return lines


def _render_tool_coverage(
    tools: list[ToolRun],
    coverage_gaps: list[ToolRun],
    not_applicable: list[ToolRun],
) -> list[str]:
    lines = [
        "",
        "## Tool coverage",
        "",
        f"- Applicable scanners: {_applicable_tools(tools)}",
        f"- Completed scanners: {_completed_tools(tools)}",
        f"- Applicable execution gaps: {len(coverage_gaps)}",
        f"- Conditional controls not applicable: {len(not_applicable)}",
        "",
        f"<details><summary>All {len(tools)} selected scanner results</summary>",
        "",
    ]
    lines.append(
        "| Tool | Version | Applicability | Status | Entry-point integrity | "
        "Findings | Duration |"
    )
    lines.append("|---|---|---:|---:|---|---:|---:|")
    lines.extend(
        (
            f"| {_markdown_table(run.tool)} | {_markdown_table(run.version)} | "
            f"{'applicable' if run.applicable else 'not applicable'} | "
            f"{_markdown_table(run.status.value)} | "
            f"{_markdown_table(_executable_integrity_label(run))} | "
            f"{run.finding_count} | {run.duration_seconds:.3f}s |"
        )
        for run in tools
    )
    lines.extend(["", "</details>"])
    return lines


def _render_coverage_actions(
    manifest: ScanManifest,
    coverage_gaps: list[ToolRun],
    not_applicable: list[ToolRun],
) -> list[str]:
    lines = ["", "## Coverage gaps and actions", ""]
    lines.append("| Tool | Status | Reason | Required action | Reference |")
    lines.append("|---|---|---|---|---|")
    lines.extend(
        (
            f"| {_markdown_table(run.tool)} | "
            f"{_markdown_table(run.status.value)} | "
            f"{_markdown_table(run.error or 'No diagnostic supplied')} | "
            f"{_markdown_table(_coverage_action(run, manifest))} | "
            f"{_markdown_tool_reference(run.tool)} |"
        )
        for run in coverage_gaps
    )
    if not coverage_gaps:
        lines.append("| All applicable tools | completed | - | No action | - |")

    if not_applicable:
        lines.extend(
            [
                "",
                f"<details><summary>{len(not_applicable)} not-applicable controls "
                "(informational)</summary>",
                "",
                "| Tool | Category | Owner | Activation trigger | Required evidence | Action | Reference |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        lines.extend(
            (
                f"| {_markdown_table(run.tool)} | "
                f"{_markdown_table(activation_recipe(run)['category'])} | "
                f"{_markdown_table(activation_recipe(run)['owner'])} | "
                f"{_markdown_table(activation_recipe(run)['activation_trigger'])} | "
                f"{_markdown_table(activation_recipe(run)['evidence_required'])} | "
                f"{_markdown_table(activation_recipe(run)['required_action'])} | "
                f"{_markdown_tool_reference(run.tool)} |"
            )
            for run in not_applicable
        )
        lines.extend(["", "</details>"])
    return lines


def _render_derived_evidence(manifest: ScanManifest) -> list[str]:
    derived = [
        value
        for key, value in manifest.artifacts.items()
        if key
        not in {
            "summary",
            "html",
            "sarif",
            "findings",
            "manifest",
            "checksums",
            "evidence",
            "action_plan",
            "assurance_case",
        }
    ]
    if not derived:
        return []
    return [
        "",
        "## Derived assurance evidence",
        "",
        *(
            f"- [`{_markdown_code(value)}`]({_markdown_code(value)})"
            for value in derived
        ),
    ]


def _render_triage_workflow(outcome: Outcome) -> list[str]:
    return [
        "## Triage workflow",
        "",
        _next_action(outcome),
        "",
        "1. Open the cited location and validate whether the scanner's premise "
        + "is true in this execution context.",
        "2. Choose a disposition: fix, accepted risk, false positive, or "
        + "approved suppression.",
        "3. Record the owner and rationale in the repository's normal review system.",
        "4. Rerun the isolated suite and confirm the finding ID is resolved or "
        + "intentionally governed.",
        "",
        "The downloadable artifact contains detailed findings, citations, tool "
        + "health, the scan manifest, sanitized diagnostics, and checksums.",
        "",
    ]


def _domain_summary(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    domains: dict[str, list[Finding]] = {}
    for finding in findings:
        domain = finding.domain.strip() or "unclassified"
        domains.setdefault(domain, []).append(finding)
    return sorted(
        domains.items(),
        key=lambda item: (-len(item[1]), item[0].casefold()),
    )
