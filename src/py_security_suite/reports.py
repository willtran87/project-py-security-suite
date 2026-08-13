from __future__ import annotations

import hashlib
import html
import json
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from .admission import admission_decisions
from .models import (
    Citation,
    Finding,
    FindingStatus,
    Location,
    Outcome,
    ScanManifest,
    Severity,
    Source,
    ToolRun,
    json_ready,
)
from .passport import (
    REQUIRED_REPORT_ARTIFACTS,
    build_security_passport_statement,
    verify_report,
)
from .prioritization import finding_order_key, finding_priority
from .portfolio_health import activation_recipe, portfolio_health_artifact
from .source_context import source_language


REPORT_FILES = tuple(REQUIRED_REPORT_ARTIFACTS.values())
_MAX_REFERENCE_URI = 2048
_UNSAFE_MARKDOWN_URI_CHARACTERS = frozenset("()<>\\")

_TOOL_REFERENCES = {
    "bandit": "https://bandit.readthedocs.io/",
    "semgrep": "https://semgrep.dev/docs/",
    "detect-secrets": "https://github.com/Yelp/detect-secrets",  # pragma: allowlist secret
    "osv-scanner": "https://google.github.io/osv-scanner/",
    "cyclonedx-py": "https://cyclonedx-bom-tool.readthedocs.io/",
    "ruff": "https://docs.astral.sh/ruff/rules/#flake8-bandit-s",
    "ruff-quality": "https://docs.astral.sh/ruff/linter/",
    "ruff-format": "https://docs.astral.sh/ruff/formatter/",
    "pylint": "https://pylint.readthedocs.io/",
    "mypy": "https://mypy.readthedocs.io/",
    "vulture": "https://github.com/jendrikseipp/vulture",
    "radon": "https://radon.readthedocs.io/",
    "tach": "https://docs.gauge.sh/",
    "reachability": (
        "https://github.com/willtran87/project-py-security-suite/"
        "blob/main/docs/reachability.md"
    ),
    "graphify": "https://graphify.com/docs/cli",
    "coverage": "https://coverage.readthedocs.io/",
    "junit": "https://github.com/testmoapp/junitxml",
    "hypothesis": "https://hypothesis.readthedocs.io/",
    "schemathesis": "https://schemathesis.readthedocs.io/",
    "actionlint": "https://github.com/rhysd/actionlint",
    "hadolint": "https://github.com/hadolint/hadolint",
    "devskim": "https://github.com/microsoft/DevSkim",
    "flawfinder": "https://dwheeler.com/flawfinder/",
    "reuse": "https://reuse.software/",
    "zizmor": "https://docs.zizmor.sh/",
    "pysa": "https://pyre-check.org/docs/pysa-basics/",
    "trivy": "https://trivy.dev/docs/latest/",
    "guarddog": "https://github.com/DataDog/guarddog",
    "scancode": "https://scancode-toolkit.readthedocs.io/",
    "gitleaks": "https://github.com/gitleaks/gitleaks",
    "trufflehog": "https://trufflesecurity.com/docs/",
    "codeql": "https://pypi.org/project/run-codeql/",
    "syft": "https://github.com/anchore/syft",
    "grype": "https://github.com/anchore/grype",
    "check-wheel-contents": "https://github.com/jwodder/check-wheel-contents",
    "twine": "https://twine.readthedocs.io/en/stable/#twine-check",
    "pypi-attestations": "https://docs.pypi.org/attestations/",
    "psscriptanalyzer": "https://learn.microsoft.com/powershell/utility-modules/psscriptanalyzer/overview",
    "shellcheck": "https://github.com/koalaman/shellcheck",
    "deptry": "https://deptry.com/",
    "diff-cover": "https://github.com/Bachmann1234/diff-cover",
    "checkov": "https://www.checkov.io/",
    "cosign": "https://docs.sigstore.dev/cosign/",
    "pyright": "https://microsoft.github.io/pyright/",
    "scorecard": "https://scorecard.dev/",
    "conftest": "https://www.conftest.dev/",
    "kics": "https://docs.kics.io/latest/",
    "pipdeptree": "https://pipdeptree.readthedocs.io/",
    "git-sizer": "https://github.com/github/git-sizer",
    "validate-pyproject": "https://validate-pyproject.readthedocs.io/",
    "vale": "https://vale.sh/",
    "kube-linter": "https://docs.kubelinter.io/",
    "crosshair": "https://crosshair.readthedocs.io/",
    "atheris": "https://github.com/google/atheris",
    "mutmut": "https://mutmut.readthedocs.io/",
    "check-manifest": "https://github.com/mgedmin/check-manifest",
    "clamav": "https://docs.clamav.net/",
    "github-attestation": "https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds",
    "zap": "https://www.zaproxy.org/docs/automate/automation-framework/",
    "pytm": "https://owasp.org/www-project-pytm/",
    "in-toto": "https://in-toto.io/docs/getting-started/",
    "oci-image": "https://opencontainers.org/",
    "reproducible-build": "https://reproducible-builds.org/tools/",
    "yara": "https://yara.readthedocs.io/",
}


def write_reports(
    *,
    output: Path,
    findings: list[Finding],
    manifest: ScanManifest,
    diagnostics: dict[str, dict[str, Any]],
    include_evidence: bool,
    derived_artifacts: dict[str, Any] | None = None,
    replace_existing: bool = False,
) -> None:
    output = output.expanduser().absolute()
    if (output.exists() or output.is_symlink()) and not replace_existing:
        raise FileExistsError(f"report output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent)
    )
    try:
        _write_report_contents(
            output=staging,
            findings=findings,
            manifest=manifest,
            diagnostics=diagnostics,
            include_evidence=include_evidence,
            derived_artifacts=derived_artifacts,
        )
        verify_report(staging)
        _publish_report(staging, output, replace_existing=replace_existing)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def is_complete_report(output: Path) -> bool:
    """Return whether an existing directory is a complete verified report."""
    try:
        verify_report(output)
    except (OSError, ValueError):
        return False
    return all((output / name).is_file() for name in REPORT_FILES)


def _publish_report(staging: Path, output: Path, *, replace_existing: bool) -> None:
    lock = output.parent / f".{output.name}.publish-lock"
    try:
        lock.mkdir()
    except FileExistsError as exc:
        raise FileExistsError(
            f"report publication is already active or requires recovery: {lock}"
        ) from exc
    try:
        _publish_report_locked(
            staging,
            output,
            replace_existing=replace_existing,
        )
    finally:
        lock.rmdir()


def _publish_report_locked(
    staging: Path,
    output: Path,
    *,
    replace_existing: bool,
) -> None:
    if not output.exists() and not output.is_symlink():
        staging.rename(output)
        return
    if not replace_existing:
        raise FileExistsError(f"report output appeared during generation: {output}")
    if output.is_symlink() or not output.is_dir():
        raise FileExistsError(f"report output is not a replaceable directory: {output}")
    if any(output.iterdir()) and not is_complete_report(output):
        raise FileExistsError(
            f"report output is not a complete verified suite report: {output}"
        )
    backup = Path(tempfile.mkdtemp(prefix=f".{output.name}.backup-", dir=output.parent))
    backup.rmdir()
    published = False
    output.rename(backup)
    try:
        staging.rename(output)
        published = True
    except BaseException:
        if not output.exists() and not output.is_symlink():
            backup.rename(output)
        raise
    finally:
        if published and backup.exists():
            shutil.rmtree(backup)


def _write_report_contents(
    *,
    output: Path,
    findings: list[Finding],
    manifest: ScanManifest,
    diagnostics: dict[str, dict[str, Any]],
    include_evidence: bool,
    derived_artifacts: dict[str, Any] | None,
) -> None:
    _register_report_artifacts(manifest, derived_artifacts)
    active_findings = [
        finding
        for finding in findings
        if finding.status is not FindingStatus.SUPPRESSED
    ]
    _write_primary_report_files(
        output, manifest, findings, active_findings, derived_artifacts
    )
    _write_evidence(output, manifest, diagnostics, include_evidence)
    _write_derived_artifacts(output, derived_artifacts)
    _write_json(output / "scan-manifest.json", manifest)
    _write_json(
        output / "security-passport.json",
        build_security_passport_statement(output, manifest),
    )
    _write_checksums(output)


def _register_report_artifacts(
    manifest: ScanManifest, derived_artifacts: dict[str, Any] | None
) -> None:
    manifest.artifacts = dict(REQUIRED_REPORT_ARTIFACTS)
    for name in sorted(derived_artifacts or {}):
        if name == "source-inventory.json":
            continue
        if (
            "/" in name
            or "\\" in name
            or name in REPORT_FILES
            or name in REQUIRED_REPORT_ARTIFACTS
        ):
            raise ValueError(f"unsafe or reserved derived artifact name: {name}")
        manifest.artifacts[name] = name
    if "source-inventory.json" not in (derived_artifacts or {}):
        raise ValueError("required source-inventory.json derived artifact is missing")


def _write_primary_report_files(
    output: Path,
    manifest: ScanManifest,
    findings: list[Finding],
    active_findings: list[Finding],
    derived_artifacts: dict[str, Any] | None,
) -> None:
    fusion = (derived_artifacts or {}).get("evidence-fusion.json")
    structural = (derived_artifacts or {}).get("structural-synthesis.json")
    data_exposure = (derived_artifacts or {}).get("data-exposure.json")
    risk_paths = (derived_artifacts or {}).get("risk-paths.json")
    _write_text(
        output / "summary.md",
        render_summary(
            manifest,
            findings,
            evidence_fusion=fusion if isinstance(fusion, dict) else None,
            structural_synthesis=structural if isinstance(structural, dict) else None,
            data_exposure=data_exposure if isinstance(data_exposure, dict) else None,
            risk_paths=risk_paths if isinstance(risk_paths, dict) else None,
        ),
    )
    _write_text(
        output / "action-plan.md", render_action_plan(manifest, active_findings)
    )
    _write_text(
        output / "assurance-case.md",
        render_assurance_case(manifest, active_findings),
    )
    _write_text(output / "index.html", render_html(manifest, findings))
    _write_json(output / "results.sarif", render_sarif(active_findings))
    _write_json(
        output / "sonarqube-external-issues.json",
        render_sonarqube_external_issues(active_findings),
    )
    _write_json(
        output / "findings.json",
        {
            "schema_version": "1.0",
            "scan_id": manifest.scan_id,
            "outcome": manifest.outcome,
            "target": manifest.target,
            "profile": manifest.profile,
            "source_sha256": manifest.inventory.source_sha256,
            "vcs_revision": manifest.inventory.vcs_revision,
            "vcs_revision_verified": manifest.inventory.vcs_revision_verified,
            "selected_tools": sorted(run.tool for run in manifest.tools),
            "findings": findings,
        },
    )


def _write_evidence(
    output: Path,
    manifest: ScanManifest,
    diagnostics: dict[str, dict[str, Any]],
    include_evidence: bool,
) -> None:
    if include_evidence:
        evidence = output / "evidence"
        evidence.mkdir()
        for tool, diagnostic in sorted(diagnostics.items()):
            _write_json(evidence / f"{tool}.json", diagnostic)
        manifest.artifacts["evidence"] = "evidence/"


def _write_derived_artifacts(
    output: Path, derived_artifacts: dict[str, Any] | None
) -> None:
    for name, value in sorted((derived_artifacts or {}).items()):
        _write_json(output / name, value)


def render_summary(
    manifest: ScanManifest,
    findings: list[Finding],
    evidence_fusion: dict[str, Any] | None = None,
    structural_synthesis: dict[str, Any] | None = None,
    data_exposure: dict[str, Any] | None = None,
    risk_paths: dict[str, Any] | None = None,
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
    lines.extend(_render_fusion_summary(evidence_fusion))
    lines.extend(_render_structural_summary(structural_synthesis))
    lines.extend(_render_data_exposure_summary(data_exposure))
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
    production_surfaces = (
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


def _render_risk_path_summary(value: dict[str, Any] | None) -> list[str]:
    if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
        return []
    summary = value["summary"]
    routes = value.get("routes")
    routes = routes if isinstance(routes, list) else []
    unrouted = value.get("unrouted_targets")
    unrouted = unrouted if isinstance(unrouted, list) else []
    hotspots = value.get("convergence_hotspots")
    hotspots = hotspots if isinstance(hotspots, list) else []
    campaigns = value.get("validation_campaigns")
    campaigns = campaigns if isinstance(campaigns, list) else []
    test_hotspots = value.get("validation_test_hotspots")
    test_hotspots = test_hotspots if isinstance(test_hotspots, list) else []
    owner_queues = value.get("owner_work_queues")
    owner_queues = owner_queues if isinstance(owner_queues, list) else []
    lines = [
        "",
        "## Static risk routes",
        "",
        (
            "These bounded Graphify routes connect declared Python entry points to "
            "review targets and their owner/test evidence. A route is triage context, "
            "not proof of attacker control, exploitability, or sensitive-data flow."
        ),
        "",
        "| Signal | Count |",
        "|---|---:|",
        f"| Declared entry points | {int(summary.get('entry_points', 0))} |",
        f"| Finding targets | {int(summary.get('finding_targets', 0))} |",
        f"| Sensitive sink-surface targets | {int(summary.get('sink_surface_targets', 0))} |",
        f"| Targets analyzed within bound | {int(summary.get('targets_analyzed', 0))} |",
        f"| Targets with a bounded route | {int(summary.get('routed_targets', 0))} |",
        f"| Targets without a bounded route | {int(summary.get('unrouted_targets', 0))} |",
        f"| Runtime-observed routes | {int(summary.get('runtime_observed_routes', 0))} |",
        f"| Routes with line-coverage gaps | {int(summary.get('coverage_gap_routes', 0))} |",
        f"| Routes with validation gaps | {int(summary.get('validation_gap_routes', 0))} |",
        f"| Routes with validation evidence | {int(summary.get('validation_assessed_routes', 0))} |",
        f"| Routes not validation-assessed | {int(summary.get('validation_unassessed_routes', 0))} |",
        f"| Routes with an assigned owner | {int(summary.get('owned_routes', 0))} |",
        f"| Shared route convergence hotspots | {int(summary.get('convergence_hotspots', 0))} |",
        f"| Shared transit/control points | {int(summary.get('shared_control_points', 0))} |",
        f"| Routes benefiting from shared remediation | {int(summary.get('routes_in_convergence_hotspots', 0))} |",
        f"| Owner work queues | {int(summary.get('owner_work_queues', 0))} |",
        f"| Shared validation campaigns | {int(summary.get('validation_campaigns', 0))} |",
        f"| Shared validation-test hotspots | {int(summary.get('shared_validation_test_hotspots', 0))} |",
        f"| Campaigns using shared tests | {int(summary.get('campaigns_using_shared_tests', 0))} |",
        f"| Routes using shared tests | {int(summary.get('routes_using_shared_tests', 0))} |",
        f"| Campaigns dependent on one shared test | {int(summary.get('single_test_dependency_campaigns', 0))} |",
        f"| Campaigns with selected tests | {int(summary.get('campaigns_with_selected_tests', 0))} |",
        f"| Campaigns with failing tests | {int(summary.get('campaigns_with_failing_tests', 0))} |",
        f"| Campaigns with coverage gaps | {int(summary.get('campaigns_with_coverage_gaps', 0))} |",
        f"| Campaigns at changed control points | {int(summary.get('campaigns_with_changed_controls', 0))} |",
        f"| Campaigns with uncovered changed lines | {int(summary.get('campaigns_with_uncovered_changed_lines', 0))} |",
        f"| Campaigns with runtime-observation gaps | {int(summary.get('campaigns_with_runtime_observation_gaps', 0))} |",
        f"| Campaigns aligned in current evidence | {int(summary.get('campaigns_aligned_current_evidence', 0))} |",
        f"| Campaigns requiring more evidence | {int(summary.get('campaigns_requiring_evidence', 0))} |",
        f"| Unique campaign test files | {int(summary.get('unique_campaign_test_files', 0))} |",
        f"| Critical / high review campaigns | {int((summary.get('campaigns_by_review_tier') or {}).get('critical', 0))} / {int((summary.get('campaigns_by_review_tier') or {}).get('high', 0))} |",
        f"| Campaign evidence revision-aligned | {int(summary.get('campaigns_revision_aligned', 0))} |",
        f"| Campaign evidence revision-mismatched | {int(summary.get('campaigns_revision_mismatched', 0))} |",
        f"| Campaign evidence revision not established | {int(summary.get('campaigns_revision_unbound', 0))} |",
        f"| Source-bound shared control points | {int(summary.get('campaigns_with_source_bound_control_points', 0))} |",
        f"| Selected-test source bindings | {int(summary.get('selected_test_source_bindings', 0))} |",
        "",
    ]
    if routes:
        lines.extend(
            [
                "| Priority / target | Entry point and bounded route | Runtime / validation | Owner and action |",
                "|---|---|---|---|",
            ]
        )
        for route in routes[:10]:
            if not isinstance(route, dict):
                continue
            target = route.get("target")
            entry = route.get("entry_point")
            validation = route.get("validation")
            runtime = route.get("runtime_context")
            target = target if isinstance(target, dict) else {}
            entry = entry if isinstance(entry, dict) else {}
            validation = validation if isinstance(validation, dict) else {}
            runtime = runtime if isinstance(runtime, dict) else {}
            files = route.get("files")
            file_values = files if isinstance(files, list) else []
            route_text = " → ".join(str(item) for item in file_values[:5])
            if len(file_values) > 5:
                route_text += f" → … (+{len(file_values) - 5})"
            signals = _risk_path_validation_signals(validation, runtime)
            owners = route.get("owners")
            owner_text = (
                ", ".join(str(item) for item in owners[:3])
                if isinstance(owners, list) and owners
                else "Unassigned"
            )
            lines.append(
                "| `"
                + _markdown_code(str(route.get("priority") or "P4"))
                + "` "
                + _markdown_text(
                    str(target.get("label") or target.get("id") or "target")
                )
                + "<br>`"
                + _markdown_code(
                    str(target.get("path") or "unknown")
                    + (f":{target['line']}" if target.get("line") else "")
                )
                + "` | `"
                + _markdown_code(
                    str(entry.get("declared_as") or entry.get("id") or "unknown")
                )
                + "`<br>"
                + _markdown_text(route_text or "same-file entry point")
                + " | "
                + _markdown_text(signals)
                + " | **"
                + _markdown_text(owner_text)
                + "**<br>"
                + _markdown_text(
                    str(route.get("recommended_action") or "Review the route.")
                )
                + " |"
            )
    if test_hotspots:
        lines.extend(
            [
                "",
                "### Shared validation-test hotspots",
                "",
                "These test files are selected by multiple shared-control campaigns. Concentration coordinates regression work but does not prove independent assertions or sufficient coverage.",
                "",
                "| Review / test | Campaigns / controls / routes | Selection / dependency | Execution / source | Owners / action |",
                "|---|---:|---|---|---|",
            ]
        )
        for hotspot in test_hotspots[:10]:
            if not isinstance(hotspot, dict):
                continue
            owners = hotspot.get("owners")
            owner_text = (
                ", ".join(str(owner) for owner in owners[:3])
                if isinstance(owners, list) and owners
                else "Unassigned"
            )
            statuses = hotspot.get("execution_statuses")
            status_text = (
                ", ".join(str(status) for status in statuses[:5])
                if isinstance(statuses, list) and statuses
                else "not observed"
            )
            binding = hotspot.get("source_binding")
            source_text = (
                "bound"
                if isinstance(binding, dict)
                and hotspot.get("source_binding_consistent") is True
                else "inconsistent"
                if hotspot.get("source_binding_consistent") is False
                else "not bound"
            )
            lines.append(
                "| `"
                + _markdown_code(str(hotspot.get("highest_review_tier") or "low"))
                + "` score `"
                + _markdown_code(str(int(hotspot.get("highest_review_score") or 0)))
                + "`<br>`"
                + _markdown_code(str(hotspot.get("test_path") or "unknown"))
                + "`<br>`"
                + _markdown_code(str(hotspot.get("test_hotspot_id") or "unknown"))
                + "` | "
                + str(len(hotspot.get("campaign_ids") or []))
                + " / "
                + str(len(hotspot.get("control_point_paths") or []))
                + " / "
                + str(len(hotspot.get("route_ids") or []))
                + " | direct/transitive/context `"
                + _markdown_code(
                    str(int(hotspot.get("direct_campaigns") or 0))
                    + "/"
                    + str(int(hotspot.get("transitive_campaigns") or 0))
                    + "/"
                    + str(int(hotspot.get("route_mapped_campaigns") or 0))
                )
                + "`<br>sole dependency `"
                + _markdown_code(
                    str(len(hotspot.get("single_test_dependency_campaign_ids") or []))
                )
                + "` | status `"
                + _markdown_code(status_text)
                + "`; cases `"
                + _markdown_code(str(int(hotspot.get("observed_case_count") or 0)))
                + "`<br>source `"
                + _markdown_code(source_text)
                + "` | **"
                + _markdown_text(owner_text)
                + "**<br>"
                + _markdown_text(
                    str(
                        hotspot.get("recommended_action") or "Review shared test scope."
                    )
                )
                + " |"
            )
    if campaigns:
        lines.extend(
            [
                "",
                "### Shared validation campaigns",
                "",
                "Each campaign converts one shared control point into a bounded regression plan. Test selection is static context; even passing tests with complete retained coverage do not prove security or exploitability.",
                "",
                "| Review / campaign | Selected tests | Execution / coverage | Revision coherence | Owners / action |",
                "|---|---|---|---|---|",
            ]
        )
        for campaign in campaigns[:10]:
            if not isinstance(campaign, dict):
                continue
            selected = campaign.get("selected_test_files")
            selected = selected if isinstance(selected, list) else []
            tests = ", ".join(f"`{_markdown_code(str(path))}`" for path in selected[:5])
            if len(selected) > 5:
                tests += f" (+{len(selected) - 5})"
            owners = campaign.get("owners")
            owner_text = (
                ", ".join(str(owner) for owner in owners[:3])
                if isinstance(owners, list) and owners
                else "Unassigned"
            )
            coverage = campaign.get("coverage_percent")
            coverage_text = (
                f"{float(coverage):.1f}%"
                if isinstance(coverage, (int, float))
                else "not available"
            )
            snapshot = campaign.get("source_snapshot")
            snapshot = snapshot if isinstance(snapshot, dict) else {}
            revision = str(
                snapshot.get("evidence_revision_binding") or "not-established"
            )
            context_text = _risk_campaign_control_text(campaign)
            factor_text = _risk_campaign_factor_text(campaign)
            lines.append(
                "| `"
                + _markdown_code(str(campaign.get("review_tier") or "low"))
                + "` score `"
                + _markdown_code(str(int(campaign.get("review_score") or 0)))
                + "`"
                + ("<br>factors " + _markdown_text(factor_text) if factor_text else "")
                + "<br>route priority `"
                + _markdown_code(str(campaign.get("priority") or "P4"))
                + "`<br>`"
                + _markdown_code(str(campaign.get("campaign_id") or "unknown"))
                + "`<br>`"
                + _markdown_code(str(campaign.get("path") or "unknown"))
                + "` | "
                + (tests or "No bounded test candidate")
                + "<br>selection `"
                + _markdown_code(
                    str(campaign.get("test_selection_confidence") or "not-available")
                )
                + "` | execution `"
                + _markdown_code(
                    str(
                        campaign.get("focused_test_validation_status")
                        or "not-available"
                    )
                )
                + "`<br>aggregate coverage `"
                + _markdown_code(
                    str(campaign.get("coverage_status") or "not-available")
                )
                + "` ("
                + coverage_text
                + ")<br>alignment `"
                + _markdown_code(
                    str(campaign.get("test_coverage_alignment") or "not-selected")
                )
                + "`"
                + ("<br>" + _markdown_text(context_text) if context_text else "")
                + " | revision `"
                + _markdown_code(revision)
                + "`<br>control bound `"
                + _markdown_code(
                    "yes" if snapshot.get("control_point_binding") else "no"
                )
                + "`; tests bound `"
                + _markdown_code(
                    str(int(snapshot.get("selected_test_files_bound") or 0))
                )
                + "` | **"
                + _markdown_text(owner_text)
                + "**<br>"
                + _markdown_text(
                    str(campaign.get("recommended_action") or "Run the campaign.")
                )
                + " |"
            )
    if hotspots:
        lines.extend(
            [
                "",
                "### Shared route control points",
                "",
                "These files occur on multiple distinct target routes. Review shared remediation and integration-test scope before creating duplicate work.",
                "",
                "| Priority / control point | Role | Routes / targets | Owners | Validation | Consolidated action |",
                "|---|---|---:|---|---|---|",
            ]
        )
        for hotspot in hotspots[:10]:
            if not isinstance(hotspot, dict):
                continue
            validation = hotspot.get("validation_statuses")
            validation = validation if isinstance(validation, dict) else {}
            owners = hotspot.get("owners")
            owner_text = (
                ", ".join(str(item) for item in owners[:3])
                if isinstance(owners, list) and owners
                else "Unassigned"
            )
            lines.append(
                "| `"
                + _markdown_code(str(hotspot.get("priority") or "P4"))
                + "` `"
                + _markdown_code(str(hotspot.get("path") or "unknown"))
                + "`<br>`"
                + _markdown_code(str(hotspot.get("hotspot_id") or "unknown"))
                + "` | `"
                + _markdown_code(str(hotspot.get("kind") or "unknown"))
                + "` | "
                + str(len(hotspot.get("route_ids") or []))
                + " / "
                + str(len(hotspot.get("target_ids") or []))
                + " | "
                + _markdown_text(owner_text)
                + " | "
                + _markdown_text(_validation_count_summary(validation))
                + " | "
                + _markdown_text(
                    str(hotspot.get("recommended_action") or "Review shared scope.")
                )
                + " |"
            )
    if owner_queues:
        lines.extend(
            [
                "",
                "### Route owner queues",
                "",
                "| Owner | Priority | Routes / targets | Controls / campaigns / shared tests | Validation / campaign review | Next action |",
                "|---|---|---:|---:|---|---|",
            ]
        )
        for queue in owner_queues[:10]:
            if not isinstance(queue, dict):
                continue
            validation = queue.get("validation_statuses")
            validation = validation if isinstance(validation, dict) else {}
            lines.append(
                "| **"
                + _markdown_text(str(queue.get("owner") or "Unassigned"))
                + "**<br>`"
                + _markdown_code(str(queue.get("queue_id") or "unknown"))
                + "` | `"
                + _markdown_code(str(queue.get("priority") or "P4"))
                + "` | "
                + str(int(queue.get("routes") or 0))
                + " / "
                + str(int(queue.get("targets") or 0))
                + " | "
                + str(len(queue.get("convergence_hotspot_ids") or []))
                + " / "
                + str(len(queue.get("validation_campaign_ids") or []))
                + " / "
                + str(int(queue.get("shared_validation_test_files") or 0))
                + " | "
                + _markdown_text(_validation_count_summary(validation))
                + "<br>highest campaign score `"
                + _markdown_code(
                    str(int(queue.get("highest_campaign_review_score") or 0))
                )
                + "`; mismatch/unbound `"
                + _markdown_code(
                    str(int(queue.get("campaigns_revision_mismatched") or 0))
                    + "/"
                    + str(int(queue.get("campaigns_revision_unbound") or 0))
                )
                + "`"
                + "; changed/runtime gaps `"
                + _markdown_code(
                    str(int(queue.get("campaigns_with_uncovered_changed_lines") or 0))
                    + "/"
                    + str(
                        int(queue.get("campaigns_with_runtime_observation_gaps") or 0)
                    )
                )
                + "`"
                + " | "
                + _markdown_text(
                    str(queue.get("recommended_action") or "Review the queue.")
                )
                + " |"
            )
    if unrouted:
        lines.extend(
            [
                "",
                "### Unrouted review targets",
                "",
                "No route is not a clean result: confirm dynamic or externally invoked entry points before disposition.",
                "",
            ]
        )
        for item in unrouted[:5]:
            if not isinstance(item, dict):
                continue
            target = item.get("target")
            target = target if isinstance(target, dict) else {}
            lines.append(
                "- `"
                + _markdown_code(str(item.get("priority") or "P4"))
                + "` `"
                + _markdown_code(str(target.get("path") or "unknown"))
                + "`: "
                + _markdown_text(str(item.get("reason") or "route unavailable"))
            )
    return lines


def _validation_count_summary(value: dict[str, Any]) -> str:
    labels = (
        ("gap", "gap"),
        ("not-assessed", "not assessed"),
        ("partial", "partial"),
        ("aligned", "aligned"),
    )
    parts = [
        f"{int(value.get(key) or 0)} {label}"
        for key, label in labels
        if int(value.get(key) or 0)
    ]
    return ", ".join(parts) or "no retained assessment"


def _risk_path_validation_signals(
    validation: dict[str, Any], runtime: dict[str, Any]
) -> str:
    signals: list[str] = []
    status = validation.get("assessment_status")
    if isinstance(status, str):
        signals.append("assessment " + status)
    assessment_reasons = validation.get("assessment_reasons")
    if isinstance(assessment_reasons, list) and assessment_reasons:
        signals.append(
            "missing "
            + ", ".join(
                str(item).removeprefix("retained ").removesuffix(" is unavailable")
                for item in assessment_reasons[:3]
            )
        )
    states = runtime.get("reachability_states")
    if isinstance(states, list) and states:
        signals.append("reachability " + "/".join(str(item) for item in states[:3]))
    observations = runtime.get("observations")
    if isinstance(observations, list) and observations:
        signals.append("runtime " + "/".join(str(item) for item in observations[:3]))
    if validation.get("changed_line") is True:
        signals.append("changed line")
    if validation.get("line_covered") is False:
        signals.append("uncovered line")
    elif validation.get("line_covered") is True:
        signals.append("covered line")
    alignment = validation.get("coverage_alignment")
    if isinstance(alignment, str):
        signals.append("validation " + alignment)
    mapped = validation.get("mapped_test_files")
    if isinstance(mapped, list) and mapped:
        signals.append("tests " + ", ".join(str(item) for item in mapped[:2]))
    return "; ".join(signals) or "runtime and validation evidence unavailable"


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


def _sdk_dependency_context_summary(value: Any) -> str:
    if not isinstance(value, dict) or not value.get("context_available"):
        return ""
    packages = value.get("packages")
    package_text = (
        ", ".join(str(item) for item in packages[:3])
        if isinstance(packages, list) and packages
        else "unknown"
    )
    signals = [f"SDK packages {package_text}"]
    if value.get("risk_present"):
        signals.append(f"package risk {value.get('risk_tier', 'medium')}")
        clusters = value.get("advisory_clusters")
        tools = value.get("package_finding_tools")
        if isinstance(clusters, list) and clusters:
            distinct = int(value.get("distinct_advisory_count") or len(clusters))
            observations = int(value.get("advisory_observation_count") or 0)
            attribution = (
                " via " + ", ".join(str(item) for item in tools[:3])
                if isinstance(tools, list) and tools
                else ""
            )
            primary = [
                str(item.get("primary_identifier"))
                for item in clusters[:3]
                if isinstance(item, dict) and item.get("primary_identifier")
            ]
            signals.append(
                f"{distinct} distinct advisories / {observations} observations"
                + attribution
            )
            if primary:
                signals.append("advisories " + ", ".join(primary))
            usage_summaries = sorted(
                {
                    summary
                    for item in clusters
                    if isinstance(item, dict)
                    and (
                        summary := _dependency_usage_summary(
                            item.get("dependency_usage")
                        )
                    )
                }
            )
            if usage_summaries:
                signals.append("use " + " / ".join(usage_summaries[:3]))
            remediation_summaries = sorted(
                {
                    summary
                    for item in clusters
                    if isinstance(item, dict)
                    and (
                        summary := _remediation_context_summary(
                            item.get("remediation_context")
                        )
                    )
                }
            )
            if remediation_summaries:
                signals.append("action " + " / ".join(remediation_summaries[:3]))
        else:
            finding_ids = value.get("package_finding_ids")
            if isinstance(finding_ids, list) and finding_ids:
                attribution = (
                    " via " + ", ".join(str(item) for item in tools[:3])
                    if isinstance(tools, list) and tools
                    else ""
                )
                signals.append(
                    "findings "
                    + ", ".join(str(item) for item in finding_ids[:3])
                    + attribution
                )
    else:
        signals.append("no joined package-risk finding")
    lineage = value.get("lineage")
    exceptional = (
        [
            f"{item.get('package')}:{item.get('status')}"
            for item in lineage
            if isinstance(item, dict)
            and item.get("status") in {"version-drift", "artifact-only"}
        ]
        if isinstance(lineage, list)
        else []
    )
    if exceptional:
        signals.append("lineage " + ", ".join(exceptional[:3]))
    return "; ".join(signals)


def _dependency_usage_summary(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    assessment = str(value.get("assessment") or "unknown")
    relationship = str(value.get("source_relationship") or "unknown")
    paths = value.get("import_paths")
    statuses = value.get("deptry_statuses")
    if (
        assessment == "unknown"
        and relationship == "unknown"
        and not paths
        and not statuses
        and value.get("signals_conflict") is not True
    ):
        return ""
    signals = [assessment]
    if relationship != "unknown":
        signals.append(relationship + " dependency")
    dependency_paths = value.get("dependency_paths")
    if isinstance(dependency_paths, list) and dependency_paths:
        first = dependency_paths[0] if isinstance(dependency_paths[0], dict) else {}
        path = first.get("path") if isinstance(first, dict) else []
        if isinstance(path, list) and path:
            signals.append(
                "introduced by "
                + " -> ".join(str(item) for item in path[:5])
                + f" ({value.get('dependency_path_confidence', 'unknown')})"
            )
    elif relationship == "transitive":
        signals.append(
            "no introducing path"
            if value.get("dependency_path_evidence_available") is True
            else "dependency-path evidence unavailable"
        )
    if value.get("dependency_environment_warning") is True:
        signals.append("installed dependency environment has health gaps")
    elif value.get("environment_health_evidence_available") is not True:
        signals.append("installed-environment health unavailable")
    if isinstance(paths, list) and paths:
        signals.append("imports " + ", ".join(str(item) for item in paths[:2]))
    if (
        value.get("import_observed") is True
        and value.get("reachability_complete") is False
    ):
        signals.append("reachability incomplete")
    if isinstance(statuses, list) and statuses:
        signals.append("deptry " + ", ".join(str(item) for item in statuses[:2]))
    if value.get("signals_conflict") is True:
        signals.append("evidence conflict")
    tests = value.get("recommended_test_files")
    if isinstance(tests, list) and tests:
        signals.append(
            "focused tests "
            + ", ".join(str(item) for item in tests[:2])
            + f" ({value.get('test_selection_confidence', 'unknown')})"
        )
        execution_status = str(
            value.get("focused_test_validation_status") or "not-available"
        )
        signals.append("scanned-state focused-test evidence " + execution_status)
        signals.append(
            "test/coverage alignment "
            + str(value.get("test_coverage_alignment") or "not-available")
        )
        unobserved = value.get("unobserved_recommended_test_files")
        if isinstance(unobserved, list) and unobserved:
            signals.append(
                "not observed " + ", ".join(str(item) for item in unobserved[:2])
            )
    elif value.get("import_observed") is True:
        signals.append(
            "no focused test mapping"
            if value.get("test_mapping_evidence_available") is True
            else "test mapping unavailable"
        )
    owners = value.get("import_path_owners")
    if isinstance(owners, list) and owners:
        signals.append("owners " + ", ".join(str(item) for item in owners[:2]))
    elif value.get("import_observed") is True:
        signals.append(
            "no matched import-path owner"
            if value.get("ownership_evidence_available") is True
            else "ownership evidence unavailable"
        )
    uncovered = value.get("uncovered_import_paths")
    if isinstance(uncovered, list) and uncovered:
        signals.append(
            "below 80% coverage " + ", ".join(str(item) for item in uncovered[:2])
        )
    elif (
        value.get("import_observed") is True
        and value.get("coverage_evidence_available") is not True
    ):
        signals.append("coverage evidence unavailable")
    return ", ".join(signals)


def _remediation_context_summary(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    priority = str(value.get("priority") or "P4")
    kind = str(value.get("action_kind") or "review")
    candidates = value.get("fixed_version_candidates")
    parts = [priority, kind]
    if isinstance(candidates, list) and candidates:
        parts.append(
            "fix candidates " + ", ".join(str(item) for item in candidates[:4])
        )
    elif value.get("fix_available") is False:
        parts.append("no scanner-reported fix")
    owners = value.get("owners")
    if isinstance(owners, list) and owners:
        parts.append("owner " + ", ".join(str(item) for item in owners[:2]))
    tests = value.get("recommended_test_files")
    if isinstance(tests, list) and tests:
        parts.append("tests " + ", ".join(str(item) for item in tests[:2]))
        parts.append(
            "scanned-state focused-test evidence "
            + str(value.get("focused_test_validation_status") or "not-available")
        )
        parts.append(
            "test/coverage alignment "
            + str(value.get("test_coverage_alignment") or "not-available")
        )
    roots = value.get("introducing_packages")
    if isinstance(roots, list) and roots:
        parts.append("introduced by " + ", ".join(str(item) for item in roots[:3]))
    return ", ".join(parts)


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


def _render_markdown_findings(
    findings: list[Finding],
    tool_versions: dict[str, str],
) -> list[str]:
    lines = ["", "## Findings requiring review", ""]
    if not findings:
        return [*lines, "- No normalized findings.", ""]
    ordered = sorted(findings, key=_finding_sort_key)
    for index, finding in enumerate(ordered[:20], start=1):
        sources = (
            "; ".join(
                _markdown_source(source, tool_versions) for source in finding.sources
            )
            or "No scanner attribution recorded"
        )
        classifications = (
            "; ".join(
                _markdown_classification(item) for item in finding.classifications
            )
            or "Unclassified"
        )
        references = (
            "; ".join(_markdown_citation(item) for item in finding.citations)
            or "No external reference"
        )
        lines.extend(
            [
                f"### {index}. {finding.severity.value.upper()} - "
                f"{_markdown_text(finding.title)}",
                "",
                f"- **Finding ID:** `{_markdown_code(finding.finding_id)}`",
                f"- **Priority:** `{_finding_priority(finding)}`",
                f"- **Lifecycle:** `{finding.status.value}`",
                f"- **Owners:** {_finding_owners(finding)}",
                f"- **Threat intelligence:** {_threat_intelligence_summary(finding)}",
                f"- **Location:** `{_markdown_code(_location_text(finding))}`",
                f"- **Found by:** {sources}",
                f"- **Domain / area / confidence:** "
                f"`{_markdown_code(finding.domain)}` / "
                f"`{_markdown_code(finding.area)}` / "
                f"`{_markdown_code(finding.confidence.value)}`",
                f"- **Classification:** {classifications}",
                f"- **References:** {references}",
                *_markdown_graph_context(finding),
                *_markdown_risk_path_context(finding),
                *_markdown_structural_context(finding),
                *_markdown_data_exposure_context(finding),
                *_markdown_fusion_context(finding),
                "",
                f"**What was detected:** {_markdown_text(finding.description)}",
                "",
                *_markdown_source_excerpt(finding),
                f"**Why it matters:** {_markdown_text(finding.impact)}",
                "",
                f"**Recommended action:** {_markdown_text(finding.remediation)}",
                "",
            ]
        )
    if len(ordered) > 20:
        lines.extend(
            [
                f"{len(ordered) - 20} additional finding(s) are available in "
                "`index.html`, `findings.json`, and `results.sarif`.",
                "",
            ]
        )
    return lines


def render_action_plan(manifest: ScanManifest, findings: list[Finding]) -> str:
    coverage_gaps = _applicable_scanner_gaps(manifest.tools)
    not_applicable = _not_applicable_scanners(manifest.tools)
    blocking = sum(1 for finding in findings if finding.blocking)
    entrypoints, approved_entrypoints, unchanged_entrypoints = (
        _entrypoint_integrity_counts(manifest.tools)
    )
    trust_gaps, approval_gaps, postcheck_gaps = _entrypoint_integrity_gap_counts(
        manifest.tools
    )
    approval_gap_label = "gap" if approval_gaps == 1 else "gaps"
    postcheck_gap_label = "gap" if postcheck_gaps == 1 else "gaps"
    approval_candidates, unique_candidate_digests = (
        _entrypoint_approval_candidate_counts(manifest.tools)
    )
    candidate_binding_label = "binding" if approval_candidates == 1 else "bindings"
    candidate_digest_label = "digest" if unique_candidate_digests == 1 else "digests"
    assigned_findings = sum(bool(_owner_values(finding)) for finding in findings)
    owner_queues = {owner for finding in findings for owner in _owner_values(finding)}
    unassigned_findings = len(findings) - assigned_findings
    lines = [
        "# Security action plan",
        "",
        f"- **Scan:** `{_markdown_code(manifest.scan_id)}`",
        f"- **Outcome:** `{_markdown_code(manifest.outcome.value)}`",
        f"- **Profile:** `{_markdown_code(manifest.profile)}`",
        f"- **Scan-policy disposition:** {_policy_disposition(manifest.outcome)}",
        f"- **Blocking findings:** {blocking}",
        f"- **Applicable scanner execution gaps:** {len(coverage_gaps)}",
        f"- **Conditional controls not applicable:** {len(not_applicable)}",
        f"- **Scanner entry points approved and unchanged:** "
        f"{approved_entrypoints}/{entrypoints}",
        f"- **Scanner entry points unchanged after execution:** "
        f"{unchanged_entrypoints}/{entrypoints}",
        f"- **Scanner trust actions:** {trust_gaps} affected entry points "
        f"({approval_gaps} approval {approval_gap_label}; "
        f"{postcheck_gaps} post-execution {postcheck_gap_label})",
        f"- **Approval review workload:** {approval_candidates} candidate "
        f"{candidate_binding_label} across {unique_candidate_digests} unique "
        f"executable {candidate_digest_label}",
        f"- **Finding ownership:** {assigned_findings}/{len(findings)} findings "
        f"assigned across {len(owner_queues)} named owner queues; "
        f"{unassigned_findings} unassigned",
        f"- **Immediate next step:** {_next_action_for_manifest(manifest)}",
        "",
        "## Finding actions",
        "",
        "| Risk | Lifecycle | Finding | Domain / area | Location | Evidence | Owner | Action |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for finding in sorted(findings, key=_finding_sort_key):
        sources = (
            ", ".join(f"{source.tool}/{source.rule_id}" for source in finding.sources)
            or "unattributed"
        )
        reference = (
            _markdown_citation(finding.citations[0]) if finding.citations else "-"
        )
        classifications = (
            ", ".join(
                _markdown_classification(value) for value in finding.classifications
            )
            or "-"
        )
        lines.append(
            f"| {_finding_priority(finding)} / "
            f"{_markdown_table(finding.severity.value)} | "
            f"{_markdown_table(finding.status.value)} | "
            f"[`{_markdown_code(finding.finding_id)}` "
            f"{_markdown_table(finding.title)}]"
            f"(index.html#{quote(finding.finding_id, safe='')}) | "
            f"{_markdown_table(finding.domain)} / "
            f"{_markdown_table(finding.area)} | "
            f"`{_markdown_code(_location_text(finding))}` | "
            f"Source: {_markdown_table(sources)}; "
            f"Class: {classifications}; Reference: {reference} | "
            f"{_finding_owners(finding)} | "
            f"{_markdown_table(finding.remediation)} |"
        )
    if not findings:
        lines.append("| - | - | - | No normalized findings | - | - | - | No action |")

    lines.extend(_render_owner_work_queues(findings))
    lines.extend(_render_action_plan_artifact_identities(findings))
    lines.extend(_render_entrypoint_trust_actions(manifest.tools))
    lines.extend(
        [
            "",
            "## Coverage actions",
            "",
            "| Tool | Applicability | Status | Reason | Action | Reference |",
            "|---|---|---|---|---|---|",
        ]
    )
    lines.extend(
        (
            f"| {_markdown_table(run.tool)} | "
            f"{'applicable' if run.applicable else 'not applicable'} | "
            f"{_markdown_table(run.status.value)} | "
            f"{_markdown_table(run.error or 'No diagnostic supplied')} | "
            f"{_markdown_table(_coverage_action(run, manifest))} | "
            f"{_markdown_tool_reference(run.tool)} |"
        )
        for run in coverage_gaps
    )
    if not coverage_gaps:
        lines.append(
            "| All applicable tools | applicable | completed | - | No action | - |"
        )
    if not_applicable:
        lines.extend(
            [
                "",
                f"<details><summary>{len(not_applicable)} not-applicable controls "
                "(informational)</summary>",
                "",
                "| Tool | Reason | Re-enable condition | Reference |",
                "|---|---|---|---|",
            ]
        )
        lines.extend(
            (
                f"| {_markdown_table(run.tool)} | "
                f"{_markdown_table(run.error or 'No diagnostic supplied')} | "
                f"{_markdown_table(_coverage_action(run, manifest))} | "
                f"{_markdown_tool_reference(run.tool)} |"
            )
            for run in not_applicable
        )
        lines.extend(["", "</details>"])
    lines.extend(
        [
            "",
            "## Policy and release-evidence actions",
            "",
            "| Requirement | Required action |",
            "|---|---|",
        ]
    )
    lines.extend(
        (f"| {_markdown_table(reason)} | {_markdown_table(_policy_action(reason))} |")
        for reason in manifest.policy_reasons
    )
    if not manifest.policy_reasons:
        lines.append("| All configured policy requirements | No action |")
    lines.extend(
        [
            "",
            "## Disposition record",
            "",
            "For each finding, record an owner and one disposition: fixed, accepted "
            + "risk, false positive, or approved suppression. Preserve the finding ID "
            + "and cited scanner rule in the review record, then rerun the suite.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_owner_work_queues(findings: list[Finding]) -> list[str]:
    if not findings:
        return []
    queues: dict[str, list[Finding]] = {}
    for finding in findings:
        owners = list(dict.fromkeys(_owner_values(finding))) or ["Unassigned"]
        for owner in owners:
            queues.setdefault(owner, []).append(finding)
    queue_guidance = " ".join(
        (
            "A finding with multiple owners appears in each applicable queue;",
            "totals therefore represent routing workload, not unique finding count.",
        )
    )
    lines = [
        "",
        "### Ownership work queues",
        "",
        queue_guidance,
        "",
        "| Owner | P0 | P1 | P2 | P3 | P4 | Blocking | Total |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for owner, owned_findings in sorted(queues.items()):
        priorities = Counter(_finding_priority(finding) for finding in owned_findings)
        owner_label = (
            "**Unassigned**" if owner == "Unassigned" else f"`{_markdown_code(owner)}`"
        )
        lines.append(
            f"| {owner_label} | {priorities['P0']} | {priorities['P1']} | "
            f"{priorities['P2']} | {priorities['P3']} | {priorities['P4']} | "
            f"{sum(finding.blocking for finding in owned_findings)} | "
            f"{len(owned_findings)} |"
        )
    return lines


def _render_action_plan_artifact_identities(findings: list[Finding]) -> list[str]:
    identities = [
        (finding, identity)
        for finding in sorted(findings, key=_finding_sort_key)
        if (identity := _artifact_identity(finding)) is not None
    ]
    if not identities:
        return []
    identity_guidance = " ".join(
        (
            "Use these immutable identities when locating, signing, quarantining,",
            "or approving an affected distribution.",
        )
    )
    lines = [
        "",
        "### Release artifact bindings",
        "",
        identity_guidance,
        "",
        "| Finding | Artifact | SHA-256 | Size |",
        "|---|---|---|---:|",
    ]
    for finding, (path, digest, size) in identities:
        rendered_size = f"{size} bytes" if size is not None else "not supplied"
        lines.append(
            f"| [`{_markdown_code(finding.finding_id)}`]"
            f"(index.html#{quote(finding.finding_id, safe='')}) | "
            f"`{_markdown_code(path)}` | `sha256:{digest}` | {rendered_size} |"
        )
    return lines


def _render_entrypoint_trust_actions(tools: list[ToolRun]) -> list[str]:
    states = _entrypoint_integrity_states(tools)
    gaps = sorted(
        (state for state in states if state[3] is not True or state[4] is not True),
        key=_entrypoint_trust_sort_key,
    )
    trust_guidance = " ".join(
        (
            "Address changed or unverifiable entry points before approval gaps.",
            "Digest approval candidates below are observations, not provenance decisions.",
        )
    )
    lines = [
        "",
        "## Scanner entry-point trust actions",
        "",
        trust_guidance,
        "",
        "| Priority | Entry point | Digest | Trust state | Required action |",
        "|---|---|---|---|---|",
    ]
    for tool, role, digest, approved, unchanged in gaps:
        priority = (
            "P0" if unchanged is False else "P1" if unchanged is not True else "P2"
        )
        actions: list[str] = []
        if unchanged is False:
            actions.append("Quarantine the changed toolchain and reinstall it.")
        elif unchanged is not True:
            actions.append("Restore post-execution digest verification.")
        if approved is not True:
            actions.append(
                "After integrity is restored, independently verify provenance and "
                "approve the exact digest."
                if unchanged is not True
                else "Independently verify provenance and approve the exact digest."
            )
        postcheck = (
            "unchanged"
            if unchanged is True
            else "changed"
            if unchanged is False
            else "unavailable"
        )
        lines.append(
            f"| {priority} | {_markdown_table(tool)} ({role}) | "
            f"`sha256:{_markdown_code(digest[:12])}...` | "
            f"{'approved' if approved is True else 'not approved'}; "
            f"post-check {postcheck} | {_markdown_table(' '.join(actions))} |"
        )
    if not states:
        lines.append(
            "| P0 | No observed entry points | - | unavailable | Configure scanner "
            "entry points and approved digests, then rerun. |"
        )
    elif not gaps:
        lines.append(
            "| - | All observed entry points | - | approved; post-check unchanged | "
            "No action |"
        )
    versions = {
        (run.tool, role): run.version
        for run in tools
        for role, digest in (
            ("primary", run.executable_sha256),
            ("helper", run.auxiliary_executable_sha256),
        )
        if digest is not None
    }
    lines.extend(_render_entrypoint_approval_candidates(gaps, versions))
    return lines


def _entrypoint_trust_sort_key(
    state: tuple[str, str, str, bool | None, bool | None],
) -> tuple[int, str, str]:
    tool, role, _, _, unchanged = state
    priority = 0 if unchanged is False else 1 if unchanged is not True else 2
    return priority, tool, role


def _render_entrypoint_approval_candidates(
    gaps: list[tuple[str, str, str, bool | None, bool | None]],
    versions: dict[tuple[str, str], str],
) -> list[str]:
    candidates = sorted(
        (state for state in gaps if state[3] is not True and state[4] is True),
        key=lambda state: (state[0], state[1]),
    )
    if not candidates:
        return []
    grouped_by_tool: dict[str, list[tuple[str, str]]] = {}
    grouped_by_digest: dict[str, list[tuple[str, str, str]]] = {}
    for tool, role, digest, _, _ in candidates:
        grouped_by_tool.setdefault(tool, []).append((role, digest))
        grouped_by_digest.setdefault(digest, []).append(
            (tool, role, versions.get((tool, role), "unknown"))
        )
    digest_label = "digest" if len(grouped_by_digest) == 1 else "digests"
    provenance_warning = " ".join(
        (
            "> Do not apply these observed digests as approvals until an independent",
            "provenance review confirms each executable's source, version, and custody.",
        )
    )
    lines = [
        "",
        f"<details><summary>{len(candidates)} copy-ready digest approval "
        "candidates (provenance review required)</summary>",
        "",
        provenance_warning,
        "",
        "### Provenance review batches",
        "",
        f"{len(candidates)} candidate policy bindings map to "
        f"{len(grouped_by_digest)} unique executable {digest_label}. Review provenance "
        "once per digest, then record every affected binding.",
        "",
        "| Exact digest | Observed version | Candidate policy bindings |",
        "|---|---|---|",
    ]
    for digest, bindings in sorted(grouped_by_digest.items()):
        rendered_versions = ", ".join(
            f"`{_markdown_code(version)}`"
            for version in sorted({version for _, _, version in bindings})
        )
        rendered_bindings = ", ".join(
            f"`{_markdown_code(tool)} ({role})`" for tool, role, _ in sorted(bindings)
        )
        lines.append(
            f"| `sha256:{digest}` | {rendered_versions} | {rendered_bindings} |"
        )
    lines.extend(
        [
            "",
            "### Copy-ready policy bindings",
            "",
            "```toml",
        ]
    )
    for tool, entries in grouped_by_tool.items():
        lines.append(f"[tools.{tool}]")
        for role, digest in entries:
            field = (
                "auxiliary_executable_sha256"
                if role == "helper"
                else "executable_sha256"
            )
            lines.append(f'{field} = "{digest}"')
        lines.append("")
    lines.extend(["```", "", "</details>"])
    return lines


def render_assurance_case(
    manifest: ScanManifest, findings: list[Finding] | None = None
) -> str:
    active_findings = [
        finding
        for finding in findings or []
        if finding.status is not FindingStatus.SUPPRESSED
    ]
    entrypoint_count, verified_entrypoint_count, _ = _entrypoint_integrity_counts(
        manifest.tools
    )
    rows = [
        _assurance_row(
            manifest,
            "Python source security",
            ("bandit", "semgrep", "ruff", "devskim", "flawfinder"),
            "Restore every incomplete source-security scanner and rerun before "
            "reviewing the result.",
            "No active source-security findings; retain this evidence and rerun "
            "for material source changes.",
            "https://csrc.nist.gov/pubs/sp/800/218/final",
            active_findings,
        ),
        _assurance_row(
            manifest,
            "Code quality and architecture",
            (
                "ruff-quality",
                "ruff-format",
                "pylint",
                "mypy",
                "pyright",
                "vulture",
                "radon",
                "tach",
                "reachability",
            ),
            "Restore incomplete correctness, formatting, typing, dead-code, "
            "complexity, architecture, and reachability controls, then rerun.",
            "Applicable quality and architecture controls completed without "
            "active findings; retain their evidence with the review.",
            "https://docs.gauge.sh/",
            active_findings,
        ),
        _assurance_row(
            manifest,
            "Automated test evidence",
            ("coverage", "junit", "diff-cover"),
            "Generate branch-enabled coverage JSON and passing JUnit XML in a "
            "disposable test lane, then attach both reports to the scan.",
            "Coverage, changed-line coverage, and JUnit evidence passed; retain "
            "all three reports with the same immutable source revision.",
            "https://coverage.readthedocs.io/en/latest/commands/cmd_reporting.html",
            active_findings,
        ),
        _assurance_row(
            manifest,
            "Deep data-flow analysis",
            ("pysa", "codeql"),
            "Configure and run at least one approved deep data-flow engine; "
            "production policy expects Pysa and the full profile requires CodeQL.",
            "At least one applicable deep data-flow engine completed without an "
            "active finding; retain its normalized result and tool-provenance "
            "evidence.",
            "https://owasp.org/www-project-application-security-verification-standard/",
            active_findings,
        ),
        _assurance_row(
            manifest,
            "Secret exposure",
            ("detect-secrets", "gitleaks", "trufflehog"),
            "Restore incomplete secret scanners, scan the full VCS checkout, and "
            "rerun before evaluating credential exposure.",
            "No active secret findings were reported; retain full-history scan "
            "evidence and rerun after credential-sensitive changes.",
            "https://csrc.nist.gov/pubs/sp/800/218/final",
            active_findings,
        ),
        _assurance_row(
            manifest,
            "Dependency vulnerabilities and SBOM",
            (
                "osv-scanner",
                "cyclonedx-py",
                "guarddog",
                "syft",
                "grype",
                "deptry",
                "pipdeptree",
            ),
            "Restore missing dependency scanners, a reproducible lock, and current "
            "approved offline advisory data, then regenerate the SBOM.",
            "Dependency and SBOM controls completed without active findings; "
            "retain the lock, SBOM, and advisory-snapshot digests.",
            "https://cyclonedx.org/capabilities/sbom/",
            active_findings,
            finding_areas=frozenset(
                {
                    "dependencies",
                    "package-integrity",
                    "artifact-vulnerability",
                    "dependency-health",
                    "dependency-hygiene",
                }
            ),
        ),
        _assurance_row(
            manifest,
            "Deployment, IaC, and CI configuration",
            (
                "trivy",
                "zizmor",
                "actionlint",
                "hadolint",
                "checkov",
                "conftest",
                "kics",
                "kube-linter",
                "psscriptanalyzer",
                "shellcheck",
            ),
            "Stage the final deployment and CI inputs, restore incomplete applicable "
            "controls, and rerun.",
            "Applicable deployment and CI controls completed without active "
            "findings; rerun when final deployment inputs change.",
            "https://csrc.nist.gov/pubs/sp/800/218/final",
            active_findings,
            finding_areas=frozenset(
                {
                    "deployment-configuration",
                    "ci-cd",
                    "ci-cd-correctness",
                    "container-hardening",
                    "infrastructure-as-code",
                    "kubernetes-security",
                    "powershell-safety",
                    "shell-safety",
                }
            ),
        ),
        _assurance_row(
            manifest,
            "License and source inventory",
            ("scancode", "trivy", "reuse"),
            "Restore incomplete license and origin controls, regenerate the component "
            "inventory, and rerun.",
            "No active license or inventory findings were reported; preserve the "
            "component inventory with the release.",
            "https://spdx.dev/use/specifications/",
            active_findings,
            finding_areas=frozenset({"license-governance", "license-compliance"}),
        ),
        _assurance_row(
            manifest,
            "Built artifact integrity and provenance",
            (
                "syft",
                "grype",
                "check-wheel-contents",
                "twine",
                "pypi-attestations",
                "cosign",
            ),
            "Stage immutable artifacts and approved provenance inputs, restore every "
            "incomplete artifact control, and rerun.",
            "Artifact checks completed without active findings; retain digests, "
            "SBOMs, metadata checks, and provenance with the release.",
            "https://slsa.dev/spec/v1.0/levels",
            active_findings,
            finding_areas=frozenset(
                {
                    "artifact-provenance",
                    "artifact-vulnerability",
                    "artifact-integrity",
                    "artifact-source-parity",
                    "artifact-metadata",
                }
            ),
        ),
    ]
    vcs_status = (
        "verified for scan scope"
        if manifest.inventory.vcs_history_available
        else "coverage gap"
    )
    vcs_evidence = (
        "VCS metadata was available to history-aware scanners."
        if manifest.inventory.vcs_history_available
        else "No VCS metadata was present; history and source provenance were not "
        "fully evaluated."
    )
    rows.extend(
        [
            (
                "Target content integrity",
                (
                    "verified unchanged"
                    if manifest.inventory.source_integrity_verified
                    else "coverage gap"
                ),
                (
                    f"Before/after source snapshots covered "
                    f"{manifest.inventory.hashed_files} files and "
                    f"{manifest.inventory.hashed_bytes} bytes; initial digest "
                    f"sha256:{manifest.inventory.source_sha256}."
                ),
                (
                    "Investigate target writes or concurrent edits and rerun from "
                    "an immutable checkout."
                    if not manifest.inventory.source_integrity_verified
                    else "Preserve the scan manifest and checksums with the release."
                ),
                "https://slsa.dev/spec/v1.0/levels",
            ),
            (
                "Scanner entry-point integrity",
                (
                    "verified"
                    if entrypoint_count
                    and verified_entrypoint_count == entrypoint_count
                    else "coverage gap"
                ),
                (
                    f"{verified_entrypoint_count}/{entrypoint_count} resolved "
                    "scanner and helper entry points "
                    "matched an approved SHA-256 digest and remained unchanged "
                    "through execution."
                ),
                (
                    "Pin approved executable_sha256 values (and CodeQL auxiliary "
                    "CLI digest), then rerun."
                    if verified_entrypoint_count != entrypoint_count
                    else "Preserve the approved tool configuration with the release."
                ),
                "https://csrc.nist.gov/pubs/sp/800/218/final",
            ),
            (
                "Source provenance and history",
                vcs_status,
                vcs_evidence,
                (
                    "Preserve the immutable commit identity and VCS-aware evidence "
                    "with the release."
                    if manifest.inventory.vcs_history_available
                    else "Run the production gate against a full, immutable VCS "
                    "checkout."
                ),
                "https://slsa.dev/spec/v1.0/levels",
            ),
            _external_assurance_row(
                manifest,
                "Dynamic, API, and runtime behavior",
                ("hypothesis", "schemathesis", "crosshair", "atheris", "mutmut", "zap"),
                "Run property, fuzz, mutation, and applicable DAST/API security "
                "tests in a separate disposable sandbox, then attach bounded evidence.",
                "Retain the attached companion evidence and rerun every applicable "
                "dynamic lane for material behavior or API changes.",
                "https://owasp.org/www-project-application-security-verification-standard/",
            ),
            (
                "Threat model and security review",
                "external evidence required",
                "Automated scanners do not establish business-logic correctness, "
                "authorization design, abuse-case coverage, or accepted risk.",
                "Complete threat modeling and risk-owner review for material "
                "changes before production approval.",
                "https://csrc.nist.gov/pubs/sp/800/218/final",
            ),
        ]
    )
    lines = [
        "# Production security assurance case",
        "",
        f"- **Scan:** `{_markdown_code(manifest.scan_id)}`",
        f"- **Profile:** `{_markdown_code(manifest.profile)}`",
        f"- **Policy outcome:** `{_markdown_code(manifest.outcome.value)}`",
        "",
        "This document states what the scan demonstrated and what still requires "
        + "separate release evidence. It is not a certification or a guarantee that "
        + "the software is vulnerability-free.",
        "",
        "| Control area | Status | Evidence boundary | Required next action | Reference |",
        "|---|---|---|---|---|",
    ]
    for control, status, evidence, action, reference in rows:
        lines.append(
            f"| {_markdown_table(control)} | {_markdown_table(status)} | "
            f"{_markdown_table(evidence)} | {_markdown_table(action)} | "
            f"[Standard or guidance]({reference}) |"
        )
    lines.extend(
        [
            "",
            "## Production promotion rule",
            "",
            "Promote only when the suite outcome is `PASS`, all required external "
            + "evidence above is attached to the same immutable artifact digest, "
            + "and every accepted risk has an owner, rationale, and expiry date.",
            "",
        ]
    )
    return "\n".join(lines)


def _html_finding_cards(ordered: list[Finding], tool_versions: dict[str, str]) -> str:
    return "".join(
        _render_html_finding(finding, tool_versions) for finding in ordered
    ) or (
        "<section class='empty'><h3>No normalized findings</h3>"
        "<p>The selected scanners completed without reporting a finding.</p></section>"
    )


def _html_finding_rows(ordered: list[Finding]) -> str:
    return "".join(
        "<tr>"
        f"<td><span class='badge {html.escape(finding.severity.value)}'>"
        f"{html.escape(_finding_priority(finding))}</span></td>"
        f"<td>{html.escape(finding.severity.value.upper())}</td>"
        f"<td><a href='#{html.escape(finding.finding_id, quote=True)}'>"
        f"<strong>{html.escape(finding.title)}</strong></a><br>"
        f"<code>{html.escape(finding.finding_id)}</code></td>"
        f"<td><code>{html.escape(_location_text(finding))}</code></td>"
        f"<td>{html.escape(_finding_tools(finding))}</td>"
        f"<td>{html.escape(finding.remediation)}</td>"
        "</tr>"
        for finding in ordered
    ) or ("<tr><td colspan='6'>No normalized findings require review.</td></tr>")


def _html_policy_reasons(manifest: ScanManifest) -> str:
    return (
        "".join(f"<li>{html.escape(reason)}</li>" for reason in manifest.policy_reasons)
        or "<li>No policy reason was recorded.</li>"
    )


def _html_coverage_gap_rows(
    manifest: ScanManifest, coverage_gaps: list[ToolRun]
) -> str:
    return "".join(
        "<tr>"
        f"<td><strong>{html.escape(run.tool)}</strong></td>"
        f"<td>{'applicable' if run.applicable else 'not applicable'}</td>"
        f"<td><span class='status {html.escape(run.status.value)}'>"
        f"{html.escape(run.status.value)}</span></td>"
        f"<td>{html.escape(run.error or 'No diagnostic supplied')}</td>"
        f"<td>{html.escape(_coverage_action(run, manifest))}</td>"
        f"<td>{_html_tool_reference(run.tool)}</td>"
        "</tr>"
        for run in coverage_gaps
    ) or (
        "<tr><td>All applicable tools</td><td>applicable</td>"
        "<td>completed</td><td>-</td><td>No action</td><td>-</td></tr>"
    )


def _html_not_applicable_details(not_applicable: list[ToolRun]) -> str:
    if not not_applicable:
        return ""
    rows = "".join(_html_activation_recipe(run) for run in not_applicable)
    return (
        "<details class='coverage-details'><summary>"
        f"{len(not_applicable)} not-applicable controls (informational)"
        "</summary><table><thead><tr><th>Tool</th><th>Category</th>"
        "<th>Owner</th><th>Activation trigger</th><th>Required evidence</th>"
        "<th>Action</th><th>Reference</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></details>"
    )


def _html_activation_recipe(run: ToolRun) -> str:
    recipe = activation_recipe(run)
    return (
        "<tr>"
        f"<td><strong>{html.escape(run.tool)}</strong></td>"
        f"<td>{html.escape(recipe['category'])}</td>"
        f"<td>{html.escape(recipe['owner'])}</td>"
        f"<td>{html.escape(recipe['activation_trigger'])}</td>"
        f"<td>{html.escape(recipe['evidence_required'])}</td>"
        f"<td>{html.escape(recipe['required_action'])}</td>"
        f"<td>{_html_tool_reference(run.tool)}</td>"
        "</tr>"
    )


def _html_tool_rows(tools: list[ToolRun]) -> str:
    return "".join(
        "<tr>"
        f"<td><strong>{html.escape(run.tool)}</strong></td>"
        f"<td>{html.escape(run.version)}</td>"
        f"<td>{'applicable' if run.applicable else 'not applicable'}</td>"
        f"<td><span class='status {html.escape(run.status.value)}'>"
        f"{html.escape(run.status.value)}</span></td>"
        f"<td>{html.escape(_executable_integrity_label(run))}</td>"
        f"<td>{run.finding_count}</td>"
        f"<td>{run.duration_seconds:.3f}s</td>"
        f"<td>{html.escape(run.error or 'None')}</td>"
        "</tr>"
        for run in tools
    )


def _html_area_rows(active_findings: list[Finding]) -> str:
    return (
        "".join(
            "<tr>"
            f"<td><strong>{html.escape(area)}</strong></td>"
            f"<td>{area_counts['critical']}</td>"
            f"<td>{area_counts['high']}</td>"
            f"<td>{area_counts['medium']}</td>"
            f"<td>{area_counts['low']}</td>"
            f"<td>{area_counts['informational'] + area_counts['unknown']}</td>"
            f"<td>{area_counts['total']}</td>"
            "</tr>"
            for area, area_counts in _area_summary(active_findings)
        )
        or "<tr><td>No findings</td><td colspan='6'>0</td></tr>"
    )


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {
        severity.value: sum(finding.severity is severity for finding in findings)
        for severity in Severity
    }


def _html_admission_cards(manifest: ScanManifest, findings: list[Finding]) -> str:
    decisions = admission_decisions(
        findings,
        manifest.tools,
        network_isolation_attested=manifest.network_isolation_attested,
        source_integrity_verified=manifest.inventory.source_integrity_verified,
    )
    cards: list[str] = []
    for row in decisions["axes"]:
        gaps = [*row["execution_gaps"], *row["integrity_gaps"]]
        gap_text = "; ".join(gaps) or "No axis-specific evidence gaps."
        cards.append(
            f'<article class="axis-card {html.escape(row["decision"])}">'
            f'<div class="axis-heading"><h3>{html.escape(row["label"])}</h3>'
            f'<span class="decision-badge {html.escape(row["decision"])}">'
            f"{html.escape(row['decision'].upper())}</span></div>"
            f"<p>{html.escape(row['purpose'])}</p>"
            f"<p><strong>Coverage:</strong> {row['completed_tools']}/"
            f"{row['applicable_tools']} applicable completed &middot; "
            f"{row['active_findings']} finding(s) &middot; "
            f"{row['blocking_findings']} blocking</p>"
            f"<p><strong>Evidence:</strong> {html.escape(gap_text)}</p>"
            f"<p><strong>Action:</strong> {html.escape(row['required_action'])}</p>"
            "</article>"
        )
    return "".join(cards)


def render_html(manifest: ScanManifest, findings: list[Finding]) -> str:
    tool_versions = {run.tool: run.version for run in manifest.tools}
    active_findings = [
        finding
        for finding in findings
        if finding.status is not FindingStatus.SUPPRESSED
    ]
    accepted = len(findings) - len(active_findings)
    ordered = sorted(active_findings, key=_finding_sort_key)
    coverage_gaps = _applicable_scanner_gaps(manifest.tools)
    not_applicable = _not_applicable_scanners(manifest.tools)
    finding_cards = _html_finding_cards(ordered, tool_versions)
    finding_rows = _html_finding_rows(ordered)
    reasons = _html_policy_reasons(manifest)
    gap_rows = _html_coverage_gap_rows(manifest, coverage_gaps)
    not_applicable_details = _html_not_applicable_details(not_applicable)
    tools = _html_tool_rows(manifest.tools)
    area_rows = _html_area_rows(active_findings)
    counts = _severity_counts(active_findings)
    entrypoints, approved_entrypoints, unchanged_entrypoints = (
        _entrypoint_integrity_counts(manifest.tools)
    )
    outcome = html.escape(manifest.outcome.value)
    decision = _policy_decision_value(manifest.outcome)
    completed = _completed_tools(manifest.tools)
    applicable = _applicable_tools(manifest.tools)
    health = portfolio_health_artifact(
        active_findings,
        manifest.tools,
        outcome=manifest.outcome,
        policy_reasons=manifest.policy_reasons,
    )["overall"]
    release_status = _report_release_status(manifest.outcome)
    admission_cards = _html_admission_cards(manifest, active_findings)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>Python Security Suite report</title>
<style>
:root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui,
  -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: #f5f7fa; color: #172033; }}
.page {{ margin: 0 auto; max-width: 1180px; padding: 2rem; }}
h1, h2, h3 {{ color: #12365d; line-height: 1.25; }}
h2 {{ margin-top: 2.25rem; }}
p, li {{ line-height: 1.55; }}
a {{ color: #125d9c; overflow-wrap: anywhere; }}
code {{ overflow-wrap: anywhere; }}
.banner {{ border-left: .6rem solid #47627f; background: #fff;
  border-radius: .4rem; box-shadow: 0 1px 5px #17203318;
  padding: 1.25rem 1.5rem; }}
.banner.fail, .banner.incomplete {{ border-color: #a61b1b; }}
.banner.warn {{ border-color: #9a6e00; }}
.banner.pass {{ border-color: #247044; }}
.lede {{ color: #506074; margin-bottom: 0; }}
.stats {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: .75rem; margin: 1rem 0 1.5rem; }}
.stat {{ background: #fff; border: 1px solid #d5dde7; border-radius: .4rem;
  padding: .85rem 1rem; }}
.stat strong {{ display: block; font-size: 1.45rem; }}
.stat span {{ color: #59677a; font-size: .9rem; }}
.decision {{ background: #eef3f8; border-radius: .4rem; padding: .75rem 1.1rem; }}
.decision h2 {{ display: flex; align-items: center; gap: .65rem; }}
.decision-badge {{ border-radius: 999px; font-size: .8rem; letter-spacing: .04em;
  padding: .25rem .65rem; }}
.decision-badge.block {{ background: #f8dddd; color: #8c1616; }}
.decision-badge.review {{ background: #fff0c7; color: #6e4e00; }}
.decision-badge.allow {{ background: #dcefe4; color: #185c36; }}
.decision-badge.incomplete, .decision-badge.not_applicable {{
  background: #fff0c7; color: #6e4e00; }}
.axis-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: .8rem; margin: 1rem 0 2rem; }}
.axis-card {{ background: #fff; border: 1px solid #d5dde7; border-left: .4rem solid #247044;
  border-radius: .4rem; padding: 1rem; }}
.axis-card.block {{ border-left-color: #a61b1b; }}
.axis-card.incomplete {{ border-left-color: #9a6e00; }}
.axis-card.not_applicable {{ border-left-color: #718096; }}
.axis-heading {{ display: flex; align-items: center; justify-content: space-between; gap: .75rem; }}
.axis-heading h3 {{ margin: 0; }}
.coverage-details {{ margin: 1rem 0 2rem; }}
.coverage-details summary {{ color: #17395f; cursor: pointer; font-weight: 700;
  padding: .65rem 0; }}
.coverage-details table {{ margin-bottom: 0; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0 2rem;
  background: #fff; }}
th, td {{ text-align: left; vertical-align: top; padding: .65rem;
  border: 1px solid #c7d0db; }}
th {{ background: #e8eef5; color: #17395f; }}
.finding {{ background: #fff; border: 1px solid #d5dde7;
  border-left: .45rem solid #47627f; border-radius: .4rem;
  box-shadow: 0 1px 4px #17203312; margin: 1rem 0; padding: 1.1rem 1.25rem; }}
.finding.critical, .finding.high {{ border-left-color: #a61b1b; }}
.finding.medium {{ border-left-color: #9a6e00; }}
.finding.low, .finding.informational {{ border-left-color: #315b7d; }}
.finding-header {{ display: flex; align-items: flex-start; gap: .75rem; }}
.finding-header h3 {{ margin: 0; flex: 1; }}
.finding-location {{ background: #eef3f8; border-left: .25rem solid #47627f;
  margin: 1rem 0; padding: .65rem .8rem; }}
.finding-location code {{ font-weight: 700; }}
.badge, .status {{ display: inline-block; border-radius: 999px; font-weight: 700;
  font-size: .78rem; letter-spacing: .02em; padding: .2rem .55rem; }}
.badge {{ background: #e8eef5; color: #17395f; white-space: nowrap; }}
.badge.critical, .badge.high {{ background: #f8dddd; color: #8c1616; }}
.badge.medium {{ background: #fff0c7; color: #6e4e00; }}
.badge.low, .badge.informational {{ background: #dfeaf4; color: #234f73; }}
.status.completed {{ background: #dcefe4; color: #185c36; }}
.status.failed, .status.unavailable, .status.timed_out,
.status.parse_error {{ background: #f8dddd; color: #8c1616; }}
.metadata {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: .5rem 1rem; margin: .9rem 0; }}
.metadata div {{ color: #3d4d62; }}
.metadata strong {{ color: #172033; }}
.detail-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem; }}
.detail {{ background: #f7f9fb; border-radius: .35rem; padding: .75rem .9rem; }}
.detail h4 {{ margin: 0 0 .35rem; color: #17395f; }}
.detail p {{ margin: 0; }}
.detail.action {{ background: #e9f5ee; border: 1px solid #b9d8c5; }}
.source-context {{ margin: 1rem 0; }}
.source-context h4 {{ margin: 0 0 .45rem; color: #17395f; }}
.source-context pre {{ background: #111b2b; color: #e7edf5; border-radius: .4rem;
  margin: 0; overflow-x: auto; padding: .65rem 0; }}
.code-line {{ display: grid; grid-template-columns: 4.5rem 1fr;
  min-height: 1.55rem; padding: 0 .8rem; }}
.code-line.highlight {{ background: #5b4616; border-left: .3rem solid #f0c15b;
  padding-left: .5rem; }}
.line-number {{ color: #93a4ba; border-right: 1px solid #405067;
  margin-right: .85rem; padding-right: .65rem; text-align: right;
  user-select: none; }}
.code-text {{ white-space: pre; }}
.redaction-note {{ color: #59677a; font-size: .9rem; margin: .45rem 0 0; }}
.compact {{ margin: .35rem 0 0; padding-left: 1.25rem; }}
.empty {{ background: #fff; padding: 1rem; border-radius: .4rem; }}
.footer-note {{ color: #59677a; font-size: .9rem; }}
@media (max-width: 650px) {{
  .page {{ padding: 1rem; }}
  .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
  .finding-header {{ display: block; }}
  .finding-header .badge {{ margin-bottom: .5rem; }}
  table {{ display: block; overflow-x: auto; white-space: normal; }}
  .metadata {{ grid-template-columns: 1fr; }}
  .code-line {{ grid-template-columns: 3.5rem 1fr; }}
}}
</style>
</head>
<body>
<div class="page">
<header class="banner {outcome}">
<h1>Security result: {outcome.upper()}</h1>
<p class="lede">Scan <code>{html.escape(manifest.scan_id)}</code> &middot;
profile <code>{html.escape(manifest.profile)}</code> &middot;
target <code>{html.escape(manifest.target)}</code></p>
</header>
<section class="stats" aria-label="Scan summary">
<div class="stat"><strong>{
        len(active_findings)
    }</strong><span>Active findings</span></div>
<div class="stat"><strong>{accepted}</strong><span>Governed findings</span></div>
<div class="stat"><strong>{
        counts.get("critical", 0)
    }</strong><span>Critical</span></div>
<div class="stat"><strong>{counts.get("high", 0)}</strong><span>High</span></div>
<div class="stat"><strong>{counts.get("medium", 0)}</strong><span>Medium</span></div>
<div class="stat"><strong>{counts.get("low", 0)}</strong><span>Low</span></div>
<div class="stat"><strong>{completed}/{applicable}</strong>
<span>Applicable completed</span></div>
<div class="stat"><strong>{len(coverage_gaps)}</strong>
<span>Execution gaps</span></div>
<div class="stat"><strong>{len(not_applicable)}</strong>
<span>Not applicable</span></div>
<div class="stat"><strong>{approved_entrypoints}/{entrypoints}</strong>
<span>Entrypoints approved</span></div>
<div class="stat"><strong>{unchanged_entrypoints}/{entrypoints}</strong>
<span>Entrypoints unchanged</span></div>
<div class="stat"><strong>{health["execution_grade"]}</strong>
<span>Execution grade</span></div>
<div class="stat"><strong>{health["risk_grade"]}</strong>
<span>Observed-risk grade</span></div>
<div class="stat"><strong>{health["evidence_grade"]}</strong>
<span>Evidence grade</span></div>
<div class="stat"><strong>{html.escape(release_status)}</strong>
<span>Release readiness</span></div>
<div class="stat"><strong>{
        "yes" if manifest.inventory.source_integrity_verified else "no"
    }</strong><span>Target unchanged</span></div>
</section>
<section class="decision">
<h2>Decision: <span class="decision-badge {decision.lower()}">{decision}</span></h2>
<ul>{reasons}</ul>
<p><strong>Next action:</strong> {html.escape(_next_action_for_manifest(manifest))}</p>
<p><strong>Promotion:</strong> Run <code>pysec release-check</code> with the
required governed sidecars; this report alone does not authorize release.</p>
<p><a href="action-plan.md">Open the prioritized action plan</a></p>
<p><a href="closure-plan.json">Download the owned closure backlog (JSON)</a></p>
<p><a href="assurance-case.md">Open the production assurance case</a></p>
</section>
<section aria-labelledby="admission-heading">
<h2 id="admission-heading">Admission decisions by evidence axis</h2>
<p>Use these cards to route work quickly. The scan-policy decision remains authoritative.</p>
<div class="axis-grid">{admission_cards}</div>
</section>
<main>
<h2>Prioritized findings</h2>
<p>Start here. Each item links the security meaning to a precise source
location, scanner rule, and recommended action.</p>
<table>
<thead><tr><th>Priority</th><th>Severity</th><th>Finding</th>
<th>File and line</th><th>Found by</th><th>Recommended action</th></tr></thead>
<tbody>{finding_rows}</tbody>
</table>
<h2>Findings by area</h2>
<table>
<thead><tr><th>Area</th><th>Critical</th><th>High</th><th>Medium</th>
<th>Low</th><th>Info/Unknown</th><th>Total</th></tr></thead>
<tbody>{area_rows}</tbody>
</table>
<h2>Findings requiring review</h2>
{finding_cards}
<h2>Tool coverage</h2>
<table>
<thead><tr><th>Tool</th><th>Version</th><th>Applicability</th><th>Status</th>
<th>Entry-point integrity</th><th>Findings</th><th>Duration</th>
<th>Diagnostic</th></tr></thead>
<tbody>{tools}</tbody>
</table>
<h2>Coverage gaps and actions</h2>
<table>
<thead><tr><th>Tool</th><th>Applicability</th><th>Status</th>
<th>Reason</th><th>Required action</th><th>Reference</th></tr></thead>
<tbody>{gap_rows}</tbody>
</table>
{not_applicable_details}
<h2>Triage workflow</h2>
<ol>
<li>Open the cited location and validate the scanner premise in context.</li>
<li>Choose a disposition: fix, accepted risk, false positive, or approved suppression.</li>
<li>Record an owner and rationale in the repository's normal review system.</li>
<li>Rerun the isolated suite and confirm the stable finding ID is resolved or governed.</li>
</ol>
<h2>Scan integrity</h2>
<p>Network policy: <code>{html.escape(manifest.network_policy)}</code>;
isolation attested: <strong>{str(manifest.network_isolation_attested).lower()}</strong>;
unisolated diagnostic: <strong>{
        str(manifest.diagnostic_without_isolation).lower()
    }</strong>;
target code execution: <strong>{str(manifest.execute_target_code).lower()}</strong>.</p>
<p>Target source digest:
<code>sha256:{html.escape(manifest.inventory.source_sha256)}</code>;
after scan:
<code>sha256:{html.escape(manifest.inventory.source_sha256_after)}</code>;
unchanged: <strong>{
        str(manifest.inventory.source_integrity_verified).lower()
    }</strong>; scope: {manifest.inventory.hashed_files} files,
{manifest.inventory.hashed_bytes} bytes.</p>
<p class="footer-note">Detected secret values and raw scanner output are not retained.
Use <code>checksums.sha256</code> to verify the downloadable artifact.</p>
</main>
</div>
</body>
</html>
"""


def render_sarif(findings: list[Finding]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        source = finding.sources[0] if finding.sources else None
        rule_id = f"{source.tool}/{source.rule_id}" if source else finding.finding_id
        rule = {
            "id": rule_id,
            "name": _sarif_name(rule_id),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {
                "text": (
                    f"Why it matters: {finding.impact}\n\n"
                    f"Recommended action: {finding.remediation}"
                ),
                "markdown": (
                    f"**Why it matters:** {finding.impact}\n\n"
                    f"**Recommended action:** {finding.remediation}"
                ),
            },
            "properties": {
                "security-severity": str(_sarif_security_score(finding.severity)),
                "tags": list(
                    dict.fromkeys(
                        [finding.domain, finding.area, *finding.classifications]
                    )
                ),
            },
        }
        help_uri = _first_reference_uri(finding)
        if help_uri:
            rule["helpUri"] = help_uri
        rules.setdefault(rule_id, rule)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": finding.title},
            "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
            "properties": {
                "finding_id": finding.finding_id,
                "priority": _finding_priority(finding),
                "domain": finding.domain,
                "area": finding.area,
                "blocking": finding.blocking,
                "confidence": finding.confidence.value,
                "lifecycle": finding.status.value,
                "owners": _owner_values(finding),
                "classifications": finding.classifications,
                "impact": finding.impact,
                "recommended_action": finding.remediation,
                "source_tools": [item.tool for item in finding.sources],
                "source_rules": [
                    {
                        "tool": item.tool,
                        "version": item.version,
                        "rule_id": item.rule_id,
                        "native_severity": item.native_severity,
                    }
                    for item in finding.sources
                ],
                "citations": [
                    {
                        "kind": item.kind,
                        "identifier": item.identifier,
                        "title": item.title,
                        "uri": _reference_uri(item),
                    }
                    for item in finding.citations
                ],
            },
        }
        graph_context = finding.evidence.get("graph_context")
        if isinstance(graph_context, dict):
            result["properties"]["graph_context"] = json_ready(graph_context)
        risk_path = finding.evidence.get("risk_path")
        if isinstance(risk_path, dict):
            result["properties"]["risk_path"] = json_ready(risk_path)
        structural = finding.evidence.get("structural_synthesis")
        if isinstance(structural, dict):
            result["properties"]["structural_synthesis"] = json_ready(structural)
        data_exposure = finding.evidence.get("data_exposure")
        if isinstance(data_exposure, dict):
            result["properties"]["data_exposure"] = json_ready(data_exposure)
        fusion = finding.evidence.get("fusion")
        if isinstance(fusion, dict):
            result["properties"]["evidence_fusion"] = json_ready(fusion)
        if finding.locations:
            location = finding.locations[0]
            physical: dict[str, Any] = {"artifactLocation": {"uri": location.path}}
            if location.start_line:
                region: dict[str, Any] = {
                    "startLine": location.start_line,
                    "endLine": location.end_line or location.start_line,
                }
                if location.snippet and not location.snippet_redacted:
                    highlighted = _highlighted_snippet(location)
                    if highlighted:
                        region["snippet"] = {"text": highlighted}
                    snippet_start = location.snippet_start_line or location.start_line
                    physical["contextRegion"] = {
                        "startLine": snippet_start,
                        "endLine": (
                            snippet_start + len(location.snippet.splitlines()) - 1
                        ),
                        "snippet": {"text": location.snippet},
                    }
                physical["region"] = region
            result["locations"] = [{"physicalLocation": physical}]
        results.append(result)
    return {
        "$schema": ("https://json.schemastore.org/sarif-2.1.0.json"),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Python Security Suite",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def render_sonarqube_external_issues(findings: list[Finding]) -> dict[str, Any]:
    """Render SonarQube's portable generic external-issue format."""

    issues: list[dict[str, Any]] = []
    for finding in findings:
        source = finding.sources[0] if finding.sources else None
        location = (
            finding.locations[0] if finding.locations else Location(path="<repository>")
        )
        issue: dict[str, Any] = {
            "engineId": "py-security-suite",
            "ruleId": f"{source.tool}/{source.rule_id}"
            if source
            else finding.finding_id,
            "severity": {
                Severity.CRITICAL: "BLOCKER",
                Severity.HIGH: "CRITICAL",
                Severity.MEDIUM: "MAJOR",
                Severity.LOW: "MINOR",
                Severity.INFORMATIONAL: "INFO",
                Severity.UNKNOWN: "INFO",
            }[finding.severity],
            "type": "VULNERABILITY"
            if finding.domain in {"security", "supply-chain"}
            else "CODE_SMELL",
            "primaryLocation": {
                "message": f"{finding.title}. Recommended action: {finding.remediation}",
                "filePath": location.path,
            },
        }
        graph_context = finding.evidence.get("graph_context")
        if isinstance(graph_context, dict):
            issue["primaryLocation"]["message"] += (
                f" Graph impact: {int(graph_context.get('two_hop_upstream_count', 0))} "
                "upstream and "
                f"{int(graph_context.get('two_hop_downstream_count', 0))} "
                "downstream files within two hops."
            )
        structural = finding.evidence.get("structural_synthesis")
        if isinstance(structural, dict):
            disposition = structural.get("disposition")
            island = structural.get("island")
            cycle = structural.get("import_cycle")
            change = structural.get("change_impact")
            boundary = structural.get("island_boundary")
            labels = []
            if disposition:
                labels.append(f"dead-code disposition {disposition}")
            if isinstance(island, dict):
                labels.append(
                    f"island classification {island.get('classification', 'review')}"
                )
            if isinstance(cycle, dict):
                labels.append(
                    f"import cycle across {int(cycle.get('file_count', 0))} files"
                )
            if isinstance(change, dict):
                labels.append(
                    "change impact "
                    f"{change.get('classification', 'review')} with risk "
                    f"{int(change.get('risk_score', 0))}"
                )
            if isinstance(boundary, dict):
                labels.append(
                    "island boundary "
                    f"{boundary.get('boundary_classification', 'review')}"
                )
            if labels:
                issue["primaryLocation"]["message"] += (
                    " Structural synthesis: " + "; ".join(labels) + "."
                )
        data_exposure = finding.evidence.get("data_exposure")
        if isinstance(data_exposure, dict):
            issue["primaryLocation"]["message"] += (
                " Sensitive-data path: "
                f"{data_exposure.get('concern', 'review')} to "
                f"{data_exposure.get('sink_family', 'unknown')}"
                + (
                    f" through {data_exposure['sdk']}"
                    if data_exposure.get("sdk")
                    else ""
                )
                + "."
            )
        fusion = finding.evidence.get("fusion")
        if isinstance(fusion, dict):
            issue["primaryLocation"]["message"] += (
                " Evidence fusion: "
                f"{fusion.get('review_tier', 'standard')} review tier, "
                f"{fusion.get('corroboration', 'single-tool')} corroboration."
            )
        if location.start_line:
            issue["primaryLocation"]["textRange"] = {
                "startLine": location.start_line,
                "endLine": location.end_line or location.start_line,
            }
        issues.append(issue)
    return {"issues": issues}


def _area_summary(
    findings: list[Finding],
) -> list[tuple[str, dict[str, int]]]:
    areas: dict[str, dict[str, int]] = {}
    severity_names = [item.value for item in Severity]
    for finding in findings:
        area = finding.area.strip() or "unclassified"
        counts = areas.setdefault(
            area,
            {name: 0 for name in [*severity_names, "total"]},
        )
        counts[finding.severity.value] += 1
        counts["total"] += 1
    return sorted(
        areas.items(),
        key=lambda item: (
            -item[1]["critical"],
            -item[1]["high"],
            -item[1]["medium"],
            -item[1]["low"],
            item[0],
        ),
    )


def _domain_summary(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    domains: dict[str, list[Finding]] = {}
    for finding in findings:
        domain = finding.domain.strip() or "unclassified"
        domains.setdefault(domain, []).append(finding)
    return sorted(
        domains.items(),
        key=lambda item: (-len(item[1]), item[0].casefold()),
    )


def _location_text(finding: Finding) -> str:
    if not finding.locations:
        return "<unknown>"
    location = finding.locations[0]
    value = location.path
    if location.start_line:
        value += f":{location.start_line}"
        if location.end_line and location.end_line != location.start_line:
            value += f"-{location.end_line}"
    if location.package:
        package = location.package
        if location.version:
            package += f" {location.version}"
        if location.ecosystem:
            package = f"{location.ecosystem}:{package}"
        value += f" ({package})"
    return value


def _markdown_source(source: Source, tool_versions: dict[str, str]) -> str:
    version = _source_version(source, tool_versions)
    tool_label = source.tool if version == "unknown" else f"{source.tool} {version}"
    return f"`{_markdown_code(tool_label)}` rule `{_markdown_code(source.rule_id)}`"


def _markdown_classification(value: str) -> str:
    uri = _classification_uri(value)
    label = _markdown_text(value)
    return f"[{label}]({uri})" if uri else f"`{_markdown_code(value)}`"


def _markdown_citation(citation: Citation) -> str:
    label = citation.identifier
    if citation.title and citation.title != citation.identifier:
        label += f" - {citation.title}"
    uri = _reference_uri(citation)
    escaped = _markdown_text(label)
    return f"[{escaped}]({uri})" if uri else f"`{_markdown_code(label)}`"


def _markdown_tool_reference(tool: str) -> str:
    uri = _TOOL_REFERENCES.get(tool)
    return f"[Official documentation]({uri})" if uri else "-"


def _html_tool_reference(tool: str) -> str:
    uri = _TOOL_REFERENCES.get(tool)
    if uri is None:
        return "-"
    return (
        f"<a href='{html.escape(uri, quote=True)}' rel='noreferrer'>"
        "Official documentation</a>"
    )


def _render_html_finding(finding: Finding, tool_versions: dict[str, str]) -> str:
    severity = html.escape(finding.severity.value)
    sources = (
        "".join(
            "<li>"
            f"<strong>{html.escape(source.tool)}</strong> "
            f"{html.escape(_source_version(source, tool_versions))} - "
            f"rule <code>{html.escape(source.rule_id)}</code>"
            "</li>"
            for source in finding.sources
        )
        or "<li>No scanner attribution recorded.</li>"
    )
    classifications = (
        " ".join(_html_classification(value) for value in finding.classifications)
        or "<span class='badge'>Unclassified</span>"
    )
    citations = (
        "".join(
            f"<li>{_html_citation(citation)}</li>" for citation in finding.citations
        )
        or "<li>No external reference.</li>"
    )
    source_context = _html_source_excerpt(finding)
    graph_context = _html_graph_context(finding)
    risk_path_context = _html_risk_path_context(finding)
    structural_context = _html_structural_context(finding)
    data_exposure_context = _html_data_exposure_context(finding)
    fusion_context = _html_fusion_context(finding)
    return (
        f"<article class='finding {severity}' "
        f"id='{html.escape(finding.finding_id, quote=True)}'>"
        "<div class='finding-header'>"
        f"<span class='badge {severity}'>"
        f"{html.escape(finding.severity.value.upper())}</span>"
        f"<h3>{html.escape(finding.title)}</h3>"
        "</div>"
        "<div class='metadata'>"
        f"<div><strong>Finding ID:</strong> "
        f"<code>{html.escape(finding.finding_id)}</code></div>"
        f"<div><strong>Priority:</strong> {_finding_priority(finding)}</div>"
        f"<div><strong>Lifecycle:</strong> {html.escape(finding.status.value)}</div>"
        f"<div><strong>Owners:</strong> {html.escape(', '.join(_owner_values(finding)) or 'Unassigned')}</div>"
        f"<div><strong>Threat intelligence:</strong> {html.escape(_threat_intelligence_summary(finding))}</div>"
        f"<div><strong>Domain:</strong> {html.escape(finding.domain)}</div>"
        f"<div><strong>Area:</strong> {html.escape(finding.area)}</div>"
        f"<div><strong>Confidence:</strong> "
        f"{html.escape(finding.confidence.value)}</div>"
        f"<div><strong>Classification:</strong> {classifications}</div>"
        "</div>"
        "<div class='finding-location'><strong>Review this location:</strong> "
        f"<code>{html.escape(_location_text(finding))}</code></div>"
        f"{source_context}"
        f"{graph_context}"
        f"{risk_path_context}"
        f"{structural_context}"
        f"{data_exposure_context}"
        f"{fusion_context}"
        "<div class='detail-grid'>"
        "<section class='detail'><h4>What was detected</h4>"
        f"<p>{html.escape(finding.description)}</p></section>"
        "<section class='detail'><h4>Found by</h4>"
        f"<ul class='compact'>{sources}</ul></section>"
        "<section class='detail'><h4>References</h4>"
        f"<ul class='compact'>{citations}</ul></section>"
        "<section class='detail'><h4>Why it matters</h4>"
        f"<p>{html.escape(finding.impact)}</p></section>"
        "<section class='detail action'><h4>Recommended action</h4>"
        f"<p>{html.escape(finding.remediation)}</p></section>"
        "</div>"
        "</article>"
    )


def _finding_tools(finding: Finding) -> str:
    return (
        ", ".join(f"{source.tool}/{source.rule_id}" for source in finding.sources)
        or "unattributed"
    )


def _markdown_graph_context(finding: Finding) -> list[str]:
    context = finding.evidence.get("graph_context")
    if not isinstance(context, dict):
        return []
    upstream = int(context.get("two_hop_upstream_count", 0))
    downstream = int(context.get("two_hop_downstream_count", 0))
    degree = int(context.get("degree", 0))
    interpretation = _markdown_text(str(context.get("interpretation", "")))
    related = context.get("related_finding_ids", [])
    related_text = ", ".join(f"`{_markdown_code(str(value))}`" for value in related[:5])
    suffix = f" Related: {related_text}." if related_text else ""
    corroboration = _graph_corroboration_text(context.get("corroborating_evidence", {}))
    if corroboration:
        suffix += f" Corroboration: {corroboration}."
    return [
        "- **Graph impact:** "
        f"degree `{degree}`; two-hop upstream `{upstream}`; "
        f"two-hop downstream `{downstream}` — {interpretation}.{suffix}"
    ]


def _markdown_risk_path_context(finding: Finding) -> list[str]:
    context = finding.evidence.get("risk_path")
    if not isinstance(context, dict):
        return []
    if context.get("status") != "routed":
        return [
            "- **Static risk route:** no bounded declared-entry-point route; "
            + _markdown_text(str(context.get("reason") or "review model coverage"))
            + ". This is an evidence gap, not proof that the code is unreachable."
        ]
    entry = context.get("entry_point")
    entry = entry if isinstance(entry, dict) else {}
    files = context.get("files")
    file_values = files if isinstance(files, list) else []
    route = " → ".join(str(item) for item in file_values[:6])
    if len(file_values) > 6:
        route += f" → … (+{len(file_values) - 6})"
    validation = context.get("validation")
    runtime = context.get("runtime_context")
    validation = validation if isinstance(validation, dict) else {}
    runtime = runtime if isinstance(runtime, dict) else {}
    hotspot_ids = context.get("convergence_hotspot_ids")
    hotspot_text = (
        " **Shared control points:** "
        + ", ".join(f"`{_markdown_code(str(value))}`" for value in hotspot_ids[:5])
        + "."
        if isinstance(hotspot_ids, list) and hotspot_ids
        else ""
    )
    test_hotspot_ids = context.get("validation_test_hotspot_ids")
    test_hotspot_text = (
        " **Shared validation tests:** "
        + ", ".join(f"`{_markdown_code(str(value))}`" for value in test_hotspot_ids[:5])
        + "."
        if isinstance(test_hotspot_ids, list) and test_hotspot_ids
        else ""
    )
    campaigns = context.get("validation_campaigns")
    campaign_values = campaigns if isinstance(campaigns, list) else []
    campaign_text = ""
    if campaign_values:
        campaign = campaign_values[0]
        if isinstance(campaign, dict):
            campaign_ids = ", ".join(
                f"`{_markdown_code(str(value.get('campaign_id') or 'unknown'))}`"
                for value in campaign_values[:5]
                if isinstance(value, dict)
            )
            selected = campaign.get("selected_test_files")
            selected_values = selected if isinstance(selected, list) else []
            snapshot = campaign.get("source_snapshot")
            snapshot = snapshot if isinstance(snapshot, dict) else {}
            control_text = _risk_campaign_control_text(campaign)
            campaign_text = (
                " **Shared validation campaign(s):** "
                + campaign_ids
                + "; first campaign selected tests "
                + (
                    ", ".join(
                        f"`{_markdown_code(str(value))}`"
                        for value in selected_values[:3]
                    )
                    if selected_values
                    else "none mapped"
                )
                + "; execution `"
                + _markdown_code(
                    str(
                        campaign.get("focused_test_validation_status")
                        or "not-available"
                    )
                )
                + "`; aggregate coverage `"
                + _markdown_code(
                    str(campaign.get("coverage_status") or "not-available")
                )
                + "`; alignment `"
                + _markdown_code(
                    str(campaign.get("test_coverage_alignment") or "not-selected")
                )
                + "`; review `"
                + _markdown_code(str(campaign.get("review_tier") or "low"))
                + "`/`"
                + _markdown_code(str(int(campaign.get("review_score") or 0)))
                + "`; revision `"
                + _markdown_code(
                    str(snapshot.get("evidence_revision_binding") or "not-established")
                )
                + "`"
                + ("; " + _markdown_text(control_text) if control_text else "")
                + "."
            )
    return [
        "- **Static risk route:** `"
        + _markdown_code(str(context.get("route_id") or "unknown"))
        + "` from `"
        + _markdown_code(str(entry.get("declared_as") or entry.get("id") or "unknown"))
        + "` in `"
        + _markdown_code(str(int(context.get("hop_count") or 0)))
        + "` file hop(s): "
        + _markdown_text(route or str(entry.get("path") or "same file"))
        + ". **Validation:** "
        + _markdown_text(_risk_path_validation_signals(validation, runtime))
        + "."
        + hotspot_text
        + test_hotspot_text
        + campaign_text
    ]


def _markdown_fusion_context(finding: Finding) -> list[str]:
    fusion = finding.evidence.get("fusion")
    if not isinstance(fusion, dict):
        return []
    reasons = fusion.get("review_reasons", [])
    reason_text = "; ".join(_markdown_text(str(value)) for value in reasons[:5])
    related = fusion.get("related_finding_ids", [])
    related_text = ", ".join(f"`{_markdown_code(str(value))}`" for value in related[:5])
    details = []
    if reason_text:
        details.append(reason_text)
    if related_text:
        details.append(f"related findings {related_text}")
    advisory = fusion.get("advisory_context")
    if isinstance(advisory, dict) and advisory.get("cluster_id"):
        primary = str(advisory.get("primary_identifier") or advisory["cluster_id"])
        usage = _dependency_usage_summary(advisory.get("dependency_usage"))
        remediation = advisory.get("remediation_context")
        remediation_summary = _remediation_context_summary(remediation)
        details.append(
            "advisory `"
            + _markdown_code(primary)
            + "`"
            + ("; dependency use " + _markdown_text(usage) if usage else "")
            + (
                "; remediation " + _markdown_text(remediation_summary)
                if remediation_summary
                else ""
            )
        )
        if isinstance(remediation, dict) and remediation.get("recommended_action"):
            details.append(
                "action " + _markdown_text(str(remediation["recommended_action"]))
            )
    suffix = " — " + "; ".join(details) if details else ""
    return [
        "- **Evidence fusion:** "
        f"review tier `{_markdown_code(str(fusion.get('review_tier', 'standard')))}`; "
        f"corroboration `{_markdown_code(str(fusion.get('corroboration', 'single-tool')))}`"
        f"{suffix}"
    ]


def _markdown_data_exposure_context(finding: Finding) -> list[str]:
    context = finding.evidence.get("data_exposure")
    if not isinstance(context, dict):
        return []
    sdk = str(context.get("sdk") or "none identified")
    exact_sink = str(context.get("sink") or context.get("sink_family") or "unknown")
    sanitizer = context.get("sanitizer_visible")
    sanitizer_text = (
        "visible; verify effectiveness"
        if sanitizer is True
        else "not visible"
        if sanitizer is False
        else "unknown"
    )
    data_classes = (
        ", ".join(str(value) for value in context.get("data_classes", []))
        or "unclassified"
    )
    risk_factors = (
        ", ".join(str(value) for value in context.get("risk_factors", [])[:5])
        or "none recorded"
    )
    cross = context.get("cross_references")
    cross = cross if isinstance(cross, dict) else {}
    cross_signals = _exposure_cross_reference_signals(cross)
    result = [
        "- **Sensitive-data path:** concern `"
        + _markdown_code(str(context.get("concern", "review")))
        + "`; sink `"
        + _markdown_code(exact_sink)
        + "` (family `"
        + _markdown_code(str(context.get("sink_family", "unknown")))
        + "`)"
        + "; SDK `"
        + _markdown_code(sdk)
        + "`; structural relevance `"
        + _markdown_code(str(context.get("structural_relevance", "unknown")))
        + "`; priority `"
        + _markdown_code(str(context.get("review_priority", "medium")))
        + "`; cross-tool triage `"
        + _markdown_code(str(context.get("triage_tier", "standard")))
        + "`; data classes `"
        + _markdown_code(data_classes)
        + "`; trust boundary `"
        + _markdown_code(str(context.get("trust_boundary", "unknown")))
        + "`; risk factors `"
        + _markdown_code(risk_factors)
        + "`; sanitizer `"
        + _markdown_code(sanitizer_text)
        + "`; joined evidence `"
        + _markdown_code(cross_signals)
        + "` - "
        + _markdown_text(str(context.get("recommended_action", "Review the path.")))
    ]
    result.extend(
        _markdown_sdk_dependency_context(context.get("sdk_dependency_context"))
    )
    steps = context.get("verification_steps")
    if isinstance(steps, list) and steps:
        result.append(
            "- **Exposure verification:** "
            + " ".join(
                f"{index}. {_markdown_text(str(step))}"
                for index, step in enumerate(steps, start=1)
            )
        )
    return result


def _markdown_sdk_dependency_context(value: Any) -> list[str]:
    summary = _sdk_dependency_context_summary(value)
    if not summary:
        return []
    citations = value.get("citations") if isinstance(value, dict) else None
    links: list[str] = []
    if isinstance(citations, list):
        for item in citations[:5]:
            if not isinstance(item, dict):
                continue
            identifier = _markdown_text(str(item.get("identifier") or "reference"))
            uri = item.get("uri")
            links.append(
                f"[{identifier}]({uri})"
                if isinstance(uri, str) and uri.startswith(("https://", "http://"))
                else f"`{_markdown_code(identifier)}`"
            )
    suffix = "; citations " + ", ".join(links) if links else ""
    result = [
        "- **SDK dependency cross-reference:** "
        + _markdown_text(summary)
        + suffix
        + ". This context raises review priority but does not prove SDK-mediated disclosure."
    ]
    clusters = value.get("advisory_clusters") if isinstance(value, dict) else None
    if isinstance(clusters, list):
        actions = [
            (
                str(
                    item.get("primary_identifier")
                    or item.get("cluster_id")
                    or "advisory"
                ),
                str(remediation.get("priority") or "P4"),
                str(remediation.get("recommended_action") or ""),
            )
            for item in clusters[:5]
            if isinstance(item, dict)
            and isinstance((remediation := item.get("remediation_context")), dict)
            and remediation.get("recommended_action")
        ]
        if actions:
            result.append(
                "- **SDK advisory action:** "
                + " ".join(
                    f"`{_markdown_code(priority)}` `{_markdown_code(identifier)}`: {_markdown_text(action)}"
                    for identifier, priority, action in actions[:3]
                )
            )
    return result


def _exposure_cross_reference_signals(context: dict[str, Any]) -> str:
    if not context.get("fusion_available"):
        return "fusion unavailable"
    signals = [
        "fusion " + str(context.get("fusion_review_tier") or "standard"),
        "corroboration " + str(context.get("corroboration") or "single-tool"),
    ]
    if context.get("changed_line") is True:
        signals.append("changed line")
    if context.get("line_covered") is False:
        signals.append("uncovered line")
    elif context.get("line_covered") is True:
        signals.append("covered line")
    states = context.get("reachability_states")
    if isinstance(states, list) and states:
        signals.append("reachability " + "/".join(str(value) for value in states[:3]))
    observations = context.get("runtime_observations")
    if isinstance(observations, list) and observations:
        signals.append("runtime " + "/".join(str(value) for value in observations[:3]))
    upstream = context.get("graph_upstream_files")
    if isinstance(upstream, int):
        signals.append(f"{upstream} upstream files")
    owners = context.get("owners")
    if isinstance(owners, list) and owners:
        signals.append("owners " + ", ".join(str(value) for value in owners[:3]))
    mapped = context.get("mapped_test_files")
    if isinstance(mapped, list) and mapped:
        signals.append("mapped tests " + ", ".join(str(value) for value in mapped[:3]))
    alignment = context.get("test_coverage_alignment")
    if isinstance(alignment, str):
        signals.append("validation " + alignment)
    priority = context.get("change_risk_priority")
    score = context.get("change_risk_score")
    if isinstance(priority, str):
        signals.append(
            f"change risk {priority}" + (f"/{score}" if isinstance(score, int) else "")
        )
    risks = context.get("structural_risk_kinds")
    if isinstance(risks, list) and risks:
        signals.append("structural " + ", ".join(str(value) for value in risks[:3]))
    return "; ".join(signals)


def _markdown_structural_context(finding: Finding) -> list[str]:
    structural = finding.evidence.get("structural_synthesis")
    if not isinstance(structural, dict):
        return []
    parts: list[str] = []
    disposition = structural.get("disposition")
    confidence = structural.get("confidence")
    if disposition:
        label = f"dead-code `{_markdown_code(str(disposition))}`"
        if confidence:
            label += f" ({_markdown_code(str(confidence))} confidence)"
        parts.append(label)
    island = structural.get("island")
    if isinstance(island, dict):
        parts.append(
            "island `"
            + _markdown_code(str(island.get("classification", "review")))
            + "` ("
            + str(int(island.get("lines_of_code", 0)))
            + " LOC, `"
            + _markdown_code(str(island.get("priority", "low")))
            + "` priority)"
        )
    cycle = structural.get("import_cycle")
    if isinstance(cycle, dict):
        parts.append(
            "import cycle `"
            + str(int(cycle.get("file_count", 0)))
            + "` files (`"
            + _markdown_code(str(cycle.get("priority", "low")))
            + "` priority)"
        )
    change = structural.get("change_impact")
    if isinstance(change, dict):
        test_count = (
            len(change.get("direct_test_files", []))
            + len(change.get("transitive_test_files", []))
            + len(change.get("associated_test_files", []))
        )
        parts.append(
            "change impact `"
            + _markdown_code(str(change.get("classification", "review")))
            + "` (risk `"
            + str(int(change.get("risk_score", 0)))
            + "`, mapped tests `"
            + str(test_count)
            + "`, validation `"
            + _markdown_code(
                str(change.get("test_coverage_alignment", "not-available"))
            )
            + "`)"
        )
    boundary = structural.get("island_boundary")
    if isinstance(boundary, dict):
        parts.append(
            "island boundary `"
            + _markdown_code(str(boundary.get("boundary_classification", "review")))
            + "`"
        )
    if not parts:
        return []
    action = structural.get("recommended_action")
    if not action and isinstance(island, dict):
        action = island.get("recommended_action")
    if not action and isinstance(cycle, dict):
        action = cycle.get("recommended_action")
    if not action and isinstance(change, dict):
        action = change.get("recommended_action")
    if not action and isinstance(boundary, dict):
        action = boundary.get("recommended_action")
    suffix = f" - {_markdown_text(str(action))}" if action else ""
    return ["- **Structural synthesis:** " + "; ".join(parts) + suffix]


def _html_graph_context(finding: Finding) -> str:
    context = finding.evidence.get("graph_context")
    if not isinstance(context, dict):
        return ""
    degree = int(context.get("degree", 0))
    upstream = int(context.get("two_hop_upstream_count", 0))
    downstream = int(context.get("two_hop_downstream_count", 0))
    interpretation = html.escape(str(context.get("interpretation", "")))
    corroboration = html.escape(
        _graph_corroboration_text(context.get("corroborating_evidence", {}))
    )
    corroboration_html = f" Corroboration: {corroboration}." if corroboration else ""
    return (
        "<section class='source-context'><h4>Graph-aware impact context</h4>"
        f"<p>Degree <strong>{degree}</strong>; two-hop upstream "
        f"<strong>{upstream}</strong>; two-hop downstream "
        f"<strong>{downstream}</strong>. {interpretation}.{corroboration_html}</p></section>"
    )


def _html_risk_path_context(finding: Finding) -> str:
    context = finding.evidence.get("risk_path")
    if not isinstance(context, dict):
        return ""
    if context.get("status") != "routed":
        reason = html.escape(str(context.get("reason") or "review model coverage"))
        return (
            "<section class='source-context'><h4>Static risk route</h4>"
            f"<p>No bounded declared-entry-point route: {reason}. This is an "
            "evidence gap, not proof that the code is unreachable.</p></section>"
        )
    entry = context.get("entry_point")
    entry = entry if isinstance(entry, dict) else {}
    files = context.get("files")
    file_values = files if isinstance(files, list) else []
    route = " → ".join(str(item) for item in file_values[:6])
    if len(file_values) > 6:
        route += f" → … (+{len(file_values) - 6})"
    validation = context.get("validation")
    runtime = context.get("runtime_context")
    validation = validation if isinstance(validation, dict) else {}
    runtime = runtime if isinstance(runtime, dict) else {}
    hotspot_ids = context.get("convergence_hotspot_ids")
    hotspot_html = (
        " <strong>Shared control points:</strong> "
        + ", ".join(
            "<code>" + html.escape(str(value)) + "</code>" for value in hotspot_ids[:5]
        )
        + "."
        if isinstance(hotspot_ids, list) and hotspot_ids
        else ""
    )
    test_hotspot_ids = context.get("validation_test_hotspot_ids")
    test_hotspot_html = (
        " <strong>Shared validation tests:</strong> "
        + ", ".join(
            "<code>" + html.escape(str(value)) + "</code>"
            for value in test_hotspot_ids[:5]
        )
        + "."
        if isinstance(test_hotspot_ids, list) and test_hotspot_ids
        else ""
    )
    campaigns = context.get("validation_campaigns")
    campaign_values = campaigns if isinstance(campaigns, list) else []
    campaign_html = ""
    if campaign_values and isinstance(campaign_values[0], dict):
        campaign = campaign_values[0]
        campaign_ids = ", ".join(
            str(value.get("campaign_id") or "unknown")
            for value in campaign_values[:5]
            if isinstance(value, dict)
        )
        selected = campaign.get("selected_test_files")
        selected_values = selected if isinstance(selected, list) else []
        snapshot = campaign.get("source_snapshot")
        snapshot = snapshot if isinstance(snapshot, dict) else {}
        control_text = _risk_campaign_control_text(campaign)
        factor_text = _risk_campaign_factor_text(campaign)
        tests = ", ".join(str(value) for value in selected_values[:3]) or "none mapped"
        campaign_html = (
            " <strong>Shared validation campaign(s):</strong> <code>"
            + html.escape(campaign_ids)
            + "</code>; first campaign selected tests "
            + html.escape(tests)
            + "; execution <code>"
            + html.escape(
                str(campaign.get("focused_test_validation_status") or "not-available")
            )
            + "</code>; aggregate coverage <code>"
            + html.escape(str(campaign.get("coverage_status") or "not-available"))
            + "</code>; alignment <code>"
            + html.escape(
                str(campaign.get("test_coverage_alignment") or "not-selected")
            )
            + "</code>; review <code>"
            + html.escape(str(campaign.get("review_tier") or "low"))
            + "/"
            + str(int(campaign.get("review_score") or 0))
            + "</code>"
            + ("; factors " + html.escape(factor_text) if factor_text else "")
            + "; revision <code>"
            + html.escape(
                str(snapshot.get("evidence_revision_binding") or "not-established")
            )
            + "</code>"
            + ("; " + html.escape(control_text) if control_text else "")
            + "."
        )
    return (
        "<section class='source-context'><h4>Static risk route</h4><p>"
        "Route <code>"
        + html.escape(str(context.get("route_id") or "unknown"))
        + "</code> from <code>"
        + html.escape(str(entry.get("declared_as") or entry.get("id") or "unknown"))
        + "</code> in <strong>"
        + str(int(context.get("hop_count") or 0))
        + "</strong> file hop(s): "
        + html.escape(route or str(entry.get("path") or "same file"))
        + ". <strong>Validation:</strong> "
        + html.escape(_risk_path_validation_signals(validation, runtime))
        + "."
        + hotspot_html
        + test_hotspot_html
        + campaign_html
        + "</p></section>"
    )


def _risk_campaign_control_text(campaign: dict[str, Any]) -> str:
    raw = campaign.get("control_point_context")
    control = raw if isinstance(raw, dict) else {}
    parts: list[str] = []
    if isinstance(control.get("graph_degree"), int):
        parts.append(f"degree {int(control['graph_degree'])}")
    if isinstance(control.get("maximum_complexity"), int):
        parts.append(
            "complexity "
            + str(int(control["maximum_complexity"]))
            + (
                f" ({control['maximum_complexity_rank']})"
                if control.get("maximum_complexity_rank")
                else ""
            )
        )
    if isinstance(control.get("change_risk_score"), int):
        parts.append(
            "change risk "
            + str(int(control["change_risk_score"]))
            + (
                f" ({control['change_priority']})"
                if control.get("change_priority")
                else ""
            )
        )
    uncovered = control.get("uncovered_changed_lines")
    if isinstance(uncovered, list) and uncovered:
        lines = ", ".join(str(line) for line in uncovered[:5])
        if len(uncovered) > 5:
            lines += f" (+{len(uncovered) - 5})"
        parts.append(f"uncovered changed lines {lines}")
    observations = control.get("runtime_observations")
    if isinstance(observations, list) and observations:
        parts.append("runtime " + ", ".join(str(value) for value in observations[:3]))
    return "; ".join(parts)


def _risk_campaign_factor_text(campaign: dict[str, Any]) -> str:
    raw = campaign.get("review_factors")
    factors = raw if isinstance(raw, list) else []
    values = [
        f"{factor.get('id')} +{int(factor.get('points') or 0)}"
        for factor in factors[:8]
        if isinstance(factor, dict) and factor.get("id") and factor.get("points")
    ]
    if len(factors) > 8:
        values.append(f"+{len(factors) - 8} more")
    return "; ".join(values)


def _html_fusion_context(finding: Finding) -> str:
    fusion = finding.evidence.get("fusion")
    if not isinstance(fusion, dict):
        return ""
    tier = html.escape(str(fusion.get("review_tier", "standard")))
    corroboration = html.escape(str(fusion.get("corroboration", "single-tool")))
    reasons = fusion.get("review_reasons", [])
    reason_text = "; ".join(str(value) for value in reasons[:5])
    advisory = fusion.get("advisory_context")
    advisory_text = ""
    if isinstance(advisory, dict) and advisory.get("cluster_id"):
        primary = str(advisory.get("primary_identifier") or advisory["cluster_id"])
        usage = _dependency_usage_summary(advisory.get("dependency_usage"))
        remediation = advisory.get("remediation_context")
        remediation_summary = _remediation_context_summary(remediation)
        action = (
            str(remediation.get("recommended_action") or "")
            if isinstance(remediation, dict)
            else ""
        )
        advisory_text = (
            " Advisory "
            + primary
            + ("; dependency use " + usage if usage else "")
            + ("; remediation " + remediation_summary if remediation_summary else "")
            + ("; action " + action if action else "")
            + "."
        )
    reason_html = f" {html.escape(reason_text)}." if reason_text else ""
    return (
        "<section class='source-context'><h4>Cross-referenced evidence</h4>"
        f"<p>Review tier <strong>{tier}</strong>; corroboration "
        f"<strong>{corroboration}</strong>.{reason_html}"
        f"{html.escape(advisory_text)}</p></section>"
    )


def _html_data_exposure_context(finding: Finding) -> str:
    context = finding.evidence.get("data_exposure")
    if not isinstance(context, dict):
        return ""
    concern = html.escape(str(context.get("concern", "review")))
    family = html.escape(str(context.get("sink_family", "unknown")))
    exact_sink = html.escape(str(context.get("sink") or family))
    sdk = html.escape(str(context.get("sdk") or "none identified"))
    relevance = html.escape(str(context.get("structural_relevance", "unknown")))
    priority = html.escape(str(context.get("review_priority", "medium")))
    data_classes = html.escape(
        ", ".join(str(value) for value in context.get("data_classes", []))
        or "unclassified"
    )
    trust_boundary = html.escape(str(context.get("trust_boundary", "unknown")))
    risk_factors = html.escape(
        ", ".join(str(value) for value in context.get("risk_factors", [])[:5])
        or "none recorded"
    )
    cross = context.get("cross_references")
    cross = cross if isinstance(cross, dict) else {}
    cross_signals = html.escape(_exposure_cross_reference_signals(cross))
    dependency = context.get("sdk_dependency_context")
    dependency_summary = _sdk_dependency_context_summary(dependency)
    dependency_html = ""
    if dependency_summary:
        citation_links: list[str] = []
        citations = (
            dependency.get("citations") if isinstance(dependency, dict) else None
        )
        if isinstance(citations, list):
            for item in citations[:5]:
                if not isinstance(item, dict):
                    continue
                identifier = html.escape(str(item.get("identifier") or "reference"))
                uri = item.get("uri")
                citation_links.append(
                    f"<a href='{html.escape(uri, quote=True)}' rel='noreferrer'>{identifier}</a>"
                    if isinstance(uri, str) and uri.startswith(("https://", "http://"))
                    else identifier
                )
        citations_html = (
            " Citations: " + ", ".join(citation_links) + "." if citation_links else ""
        )
        dependency_html = (
            "<h5>SDK dependency cross-reference</h5><p>"
            + html.escape(dependency_summary)
            + "."
            + citations_html
            + " This context raises review priority but does not prove SDK-mediated disclosure.</p>"
        )
    triage_tier = html.escape(str(context.get("triage_tier", "standard")))
    steps = context.get("verification_steps")
    steps_html = ""
    if isinstance(steps, list) and steps:
        steps_html = (
            "<h5>Verification plan</h5><ol>"
            + "".join(f"<li>{html.escape(str(step))}</li>" for step in steps)
            + "</ol>"
        )
    action = html.escape(str(context.get("recommended_action", "Review the path.")))
    return (
        "<section class='source-context'><h4>Sensitive-data exposure path</h4>"
        f"<p>Concern <strong>{concern}</strong>; sink <strong>{exact_sink}</strong> "
        f"(family <strong>{family}</strong>); "
        f"SDK <strong>{sdk}</strong>; structural relevance "
        f"<strong>{relevance}</strong>; priority <strong>{priority}</strong>; "
        f"cross-tool triage <strong>{triage_tier}</strong>; "
        f"data classes <strong>{data_classes}</strong>; trust boundary "
        f"<strong>{trust_boundary}</strong>; risk factors "
        f"<strong>{risk_factors}</strong>; joined evidence "
        f"<strong>{cross_signals}</strong>. {action}</p>{dependency_html}{steps_html}</section>"
    )


def _html_structural_context(finding: Finding) -> str:
    structural = finding.evidence.get("structural_synthesis")
    if not isinstance(structural, dict):
        return ""
    parts: list[str] = []
    disposition = structural.get("disposition")
    if disposition:
        parts.append(
            "Dead-code disposition <strong>"
            + html.escape(str(disposition))
            + "</strong>"
        )
    island = structural.get("island")
    if isinstance(island, dict):
        parts.append(
            "island <strong>"
            + html.escape(str(island.get("classification", "review")))
            + "</strong> ("
            + str(int(island.get("lines_of_code", 0)))
            + " LOC)"
        )
    cycle = structural.get("import_cycle")
    if isinstance(cycle, dict):
        parts.append(
            "import cycle across <strong>"
            + str(int(cycle.get("file_count", 0)))
            + "</strong> files"
        )
    change = structural.get("change_impact")
    if isinstance(change, dict):
        parts.append(
            "change impact <strong>"
            + html.escape(str(change.get("classification", "review")))
            + "</strong> (risk "
            + str(int(change.get("risk_score", 0)))
            + ")"
        )
    boundary = structural.get("island_boundary")
    if isinstance(boundary, dict):
        parts.append(
            "island boundary <strong>"
            + html.escape(str(boundary.get("boundary_classification", "review")))
            + "</strong>"
        )
    if not parts:
        return ""
    action = structural.get("recommended_action")
    if not action and isinstance(island, dict):
        action = island.get("recommended_action")
    if not action and isinstance(cycle, dict):
        action = cycle.get("recommended_action")
    if not action and isinstance(change, dict):
        action = change.get("recommended_action")
    if not action and isinstance(boundary, dict):
        action = boundary.get("recommended_action")
    action_html = f" {html.escape(str(action))}" if action else ""
    return (
        "<section class='source-context'><h4>Structural synthesis</h4><p>"
        + "; ".join(parts)
        + "."
        + action_html
        + "</p></section>"
    )


def _graph_corroboration_text(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    parts: list[str] = []
    coverage = value.get("coverage_percent")
    if isinstance(coverage, (int, float)) and not isinstance(coverage, bool):
        parts.append(f"coverage {float(coverage):.1f}%")
    states = value.get("reachability_states", [])
    if isinstance(states, list) and states:
        parts.append("reachability " + "/".join(str(item) for item in states[:3]))
    rank = value.get("maximum_complexity_rank")
    complexity = value.get("maximum_complexity")
    if rank and isinstance(complexity, int):
        parts.append(f"max complexity {complexity} ({rank})")
    scanners = value.get("neighboring_scanners", [])
    if isinstance(scanners, list) and scanners:
        parts.append("nearby scanners " + ", ".join(str(item) for item in scanners[:5]))
    return "; ".join(parts)


def _markdown_source_excerpt(finding: Finding) -> list[str]:
    location = _primary_snippet_location(finding)
    if location is None or location.snippet is None:
        artifact = _artifact_identity(finding)
        if artifact is not None:
            path, digest, size = artifact
            size_line = f"size: {size} bytes\n" if size is not None else ""
            return [
                f"**Artifact identity evidence - `{_markdown_code(path)}`:**",
                "",
                "```text",
                f"sha256:{digest}\n{size_line}".rstrip(),
                "```",
                "",
            ]
        return [
            f"**Source evidence:** {_missing_source_evidence_text(finding)}",
            "",
        ]
    start = location.snippet_start_line or location.start_line or 1
    lines = location.snippet.splitlines() or [""]
    numbered = []
    for offset, value in enumerate(lines):
        number = start + offset
        marker = ">" if _line_is_highlighted(location, number) else " "
        numbered.append(f"{marker} {number:>5} | {value}")
    body = "\n".join(numbered)
    fence = "`" * max(3, _longest_backtick_run(body) + 1)
    language = source_language(location.path)
    result = [
        f"**Source evidence - `{_markdown_code(_location_text(finding))}`:**",
        "",
        f"{fence}{language}",
        body,
        fence,
        "",
    ]
    if location.snippet_redacted:
        result.extend(
            [
                "_The secret-bearing line is deliberately redacted from every "
                + "report format. Inspect it only in the protected checkout._",
                "",
            ]
        )
    return result


def _html_source_excerpt(finding: Finding) -> str:
    location = _primary_snippet_location(finding)
    if location is None or location.snippet is None:
        artifact = _artifact_identity(finding)
        if artifact is not None:
            path, digest, size = artifact
            size_line = f"\nsize: {size} bytes" if size is not None else ""
            return (
                "<section class='source-context'><h4>Artifact identity evidence "
                "&mdash; "
                f"<code>{html.escape(path)}</code></h4>"
                "<pre aria-label='Artifact identity'><code>"
                f"sha256:{html.escape(digest)}{size_line}</code></pre></section>"
            )
        return (
            "<section class='source-context'><h4>Source evidence</h4>"
            f"<p>{html.escape(_missing_source_evidence_text(finding))}</p></section>"
        )
    start = location.snippet_start_line or location.start_line or 1
    lines = location.snippet.splitlines() or [""]
    rendered = "".join(
        "<span class='code-line"
        f"{' highlight' if _line_is_highlighted(location, start + offset) else ''}'>"
        f"<span class='line-number'>{start + offset}</span>"
        f"<span class='code-text'>{html.escape(value)}</span></span>"
        for offset, value in enumerate(lines)
    )
    note = (
        "<p class='redaction-note'>The secret-bearing line is deliberately "
        "redacted. Inspect it only in the protected checkout.</p>"
        if location.snippet_redacted
        else ""
    )
    return (
        "<section class='source-context'><h4>Source evidence &mdash; "
        f"<code>{html.escape(_location_text(finding))}</code></h4>"
        f"<pre aria-label='Source excerpt'>{rendered}</pre>{note}</section>"
    )


def _primary_snippet_location(finding: Finding) -> Location | None:
    return next(
        (location for location in finding.locations if location.snippet is not None),
        None,
    )


def _artifact_identity(finding: Finding) -> tuple[str, str, int | None] | None:
    path = finding.evidence.get("artifact_path")
    digest = finding.evidence.get("artifact_sha256")
    size = finding.evidence.get("artifact_size_bytes")
    if not isinstance(path, str) or not path or path == "<outside-target>":
        return None
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        return None
    normalized_size = (
        size
        if isinstance(size, int) and not isinstance(size, bool) and size >= 0
        else None
    )
    return path, digest, normalized_size


def _missing_source_evidence_text(finding: Finding) -> str:
    location = next((item for item in finding.locations if item.path), None)
    if location is not None and location.start_line is not None:
        return (
            "No safe local source excerpt was available; inspect the cited file and "
            "line in the protected checkout."
        )
    if location is not None:
        return (
            "No source excerpt applies; inspect the cited repository object and "
            "normalized scanner evidence."
        )
    return (
        "No local source location was supplied; review the normalized scanner evidence."
    )


def _line_is_highlighted(location: Location, number: int) -> bool:
    start = location.start_line or number
    end = location.end_line or start
    return start <= number <= end


def _highlighted_snippet(location: Location) -> str:
    if location.snippet is None:
        return ""
    snippet_start = location.snippet_start_line or location.start_line or 1
    return "\n".join(
        value
        for offset, value in enumerate(location.snippet.splitlines())
        if _line_is_highlighted(location, snippet_start + offset)
    )


def _longest_backtick_run(value: str) -> int:
    return max((len(match.group(0)) for match in re.finditer(r"`+", value)), default=0)


def _source_version(source: Source, tool_versions: dict[str, str]) -> str:
    version = source.version
    if version == "unknown":
        version = tool_versions.get(source.tool, "unknown")
    if version == "unknown":
        return "unknown"
    lowered = version.casefold()
    tool = source.tool.casefold()
    for prefix in (f"{tool} version: ", f"{tool} "):
        if lowered.startswith(prefix):
            return version[len(prefix) :]
    return version


def _html_classification(value: str) -> str:
    uri = _classification_uri(value)
    label = html.escape(value)
    if uri:
        return (
            f"<a class='badge' href='{html.escape(uri, quote=True)}' "
            f"rel='noreferrer'>{label}</a>"
        )
    return f"<span class='badge'>{label}</span>"


def _html_citation(citation: Citation) -> str:
    label = citation.identifier
    if citation.title and citation.title != citation.identifier:
        label += f" - {citation.title}"
    escaped = html.escape(label)
    uri = _reference_uri(citation)
    if uri:
        return (
            f"<a href='{html.escape(uri, quote=True)}' rel='noreferrer'>{escaped}</a>"
        )
    return escaped


def _first_reference_uri(finding: Finding) -> str | None:
    for citation in finding.citations:
        uri = _reference_uri(citation)
        if uri:
            return uri
    for classification in finding.classifications:
        uri = _classification_uri(classification)
        if uri:
            return uri
    return None


def _reference_uri(citation: Citation) -> str | None:
    if citation.uri:
        uri = _safe_http_reference(citation.uri)
        if uri:
            return uri
    return _classification_uri(citation.identifier)


def _safe_http_reference(value: str) -> str | None:
    if len(value) > _MAX_REFERENCE_URI or _has_unsafe_reference_character(value):
        return None
    return value if _is_well_formed_http_reference(value) else None


def _has_unsafe_reference_character(value: str) -> bool:
    return any(
        not character.isprintable()
        or character.isspace()
        or character in _UNSAFE_MARKDOWN_URI_CHARACTERS
        for character in value
    )


def _is_well_formed_http_reference(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.lower() in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _classification_uri(value: str) -> str | None:
    normalized = value.upper().split(":", 1)[0].strip()
    if normalized.startswith("CWE-") and normalized[4:].isdigit():
        return f"https://cwe.mitre.org/data/definitions/{normalized[4:]}.html"
    return None


def _write_json(path: Path, value: Any) -> None:
    _write_text(
        path,
        json.dumps(json_ready(value), indent=2, sort_keys=True, ensure_ascii=False)
        + "\n",
    )


def _write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8", newline="\n")


def _write_checksums(output: Path) -> None:
    entries = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.name == "checksums.sha256":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {path.relative_to(output).as_posix()}")
    _write_text(output / "checksums.sha256", "\n".join(entries) + "\n")


def _completed_tools(tools: list[ToolRun]) -> int:
    return sum(1 for tool in tools if tool.status.value == "completed")


def _applicable_tools(tools: list[ToolRun]) -> int:
    return sum(1 for tool in tools if tool.applicable)


def _applicable_scanner_gaps(tools: list[ToolRun]) -> list[ToolRun]:
    return [
        tool for tool in tools if tool.applicable and tool.status.value != "completed"
    ]


def _not_applicable_scanners(tools: list[ToolRun]) -> list[ToolRun]:
    return [tool for tool in tools if not tool.applicable]


def _entrypoint_integrity_counts(tools: list[ToolRun]) -> tuple[int, int, int]:
    states = _entrypoint_integrity_states(tools)
    return (
        len(states),
        sum(
            approved is True and unchanged is True
            for _, _, _, approved, unchanged in states
        ),
        sum(unchanged is True for _, _, _, _, unchanged in states),
    )


def _entrypoint_integrity_gap_counts(tools: list[ToolRun]) -> tuple[int, int, int]:
    states = _entrypoint_integrity_states(tools)
    return (
        sum(
            approved is not True or unchanged is not True
            for _, _, _, approved, unchanged in states
        ),
        sum(approved is not True for _, _, _, approved, _ in states),
        sum(unchanged is not True for _, _, _, _, unchanged in states),
    )


def _entrypoint_approval_candidate_counts(tools: list[ToolRun]) -> tuple[int, int]:
    candidates = [
        digest
        for _, _, digest, approved, unchanged in _entrypoint_integrity_states(tools)
        if approved is not True and unchanged is True
    ]
    return len(candidates), len(set(candidates))


def _entrypoint_integrity_states(
    tools: list[ToolRun],
) -> list[tuple[str, str, str, bool | None, bool | None]]:
    states: list[tuple[str, str, str, bool | None, bool | None]] = []
    for tool in tools:
        if tool.executable_sha256 is not None:
            states.append(
                (
                    tool.tool,
                    "primary",
                    tool.executable_sha256,
                    (
                        tool.executable_integrity_verified is True
                        and tool.executable_organization_approved
                    ),
                    tool.executable_unchanged,
                )
            )
        if tool.auxiliary_executable_sha256 is not None:
            states.append(
                (
                    tool.tool,
                    "helper",
                    tool.auxiliary_executable_sha256,
                    (
                        tool.auxiliary_executable_integrity_verified is True
                        and tool.auxiliary_executable_organization_approved
                    ),
                    tool.auxiliary_executable_unchanged,
                )
            )
    return states


def _executable_integrity_label(run: ToolRun) -> str:
    primary = _integrity_label(
        run.executable_sha256,
        (
            run.executable_integrity_verified is True
            and run.executable_organization_approved
        ),
        run.executable_unchanged,
    )
    if run.auxiliary_executable_sha256 is None:
        return primary
    auxiliary = _integrity_label(
        run.auxiliary_executable_sha256,
        (
            run.auxiliary_executable_integrity_verified is True
            and run.auxiliary_executable_organization_approved
        ),
        run.auxiliary_executable_unchanged,
    )
    return f"{primary}; helper: {auxiliary}"


def _integrity_label(
    digest: str | None,
    approved: bool | None,
    unchanged: bool | None,
) -> str:
    if digest is None:
        return "not checked"
    short_digest = digest[:12]
    if unchanged is False:
        return f"changed ({short_digest}...)"
    if approved and unchanged:
        return f"approved and unchanged ({short_digest}...)"
    if unchanged:
        return f"observed, not approved ({short_digest}...)"
    return f"observed, post-check unavailable ({short_digest}...)"


def _finding_sort_key(finding: Finding) -> tuple[int, int, int, int, str]:
    return finding_order_key(
        finding_id=finding.finding_id,
        severity=finding.severity,
        classifications=finding.classifications,
        evidence=finding.evidence,
        blocking=finding.blocking,
        status=finding.status,
    )


def _next_action(outcome: Outcome) -> str:
    return {
        Outcome.PASS: "No policy-blocking action is required.",
        Outcome.WARN: "Review the non-blocking findings and record disposition.",
        Outcome.FAIL: (
            "Remediate or govern blocking findings, then rerun before release or merge."
        ),
        Outcome.INCOMPLETE: (
            "Restore required scanner coverage or isolation evidence, then rerun; "
            "do not interpret this result as clean."
        ),
    }[outcome]


def _next_action_for_manifest(manifest: ScanManifest) -> str:
    if manifest.outcome is Outcome.INCOMPLETE and manifest.policy_reasons:
        return f"Resolve the first blocking evidence gap: {manifest.policy_reasons[0]}"
    return _next_action(manifest.outcome)


def _report_release_status(outcome: Outcome) -> str:
    return "PENDING EXTERNAL CONTROLS" if outcome is Outcome.PASS else "NOT APPROVED"


def _policy_disposition(outcome: Outcome) -> str:
    decision = _policy_decision_value(outcome)
    suffix = " (incomplete evidence)" if outcome is Outcome.INCOMPLETE else ""
    return f"`{decision}`{suffix}"


def _policy_decision_value(outcome: Outcome) -> str:
    return {
        Outcome.PASS: "ALLOW",
        Outcome.WARN: "REVIEW",
        Outcome.FAIL: "BLOCK",
        Outcome.INCOMPLETE: "BLOCK",
    }[outcome]


def _finding_priority(finding: Finding) -> str:
    return finding_priority(
        severity=finding.severity,
        classifications=finding.classifications,
        evidence=finding.evidence,
    )


def _owner_values(finding: Finding) -> list[str]:
    owners = finding.evidence.get("owners", [])
    return [str(value) for value in owners[:20]] if isinstance(owners, list) else []


def _finding_owners(finding: Finding) -> str:
    owners = _owner_values(finding)
    return ", ".join(f"`{_markdown_code(value)}`" for value in owners) or "Unassigned"


def _threat_intelligence_summary(finding: Finding) -> str:
    intelligence = finding.evidence.get("risk_intelligence", {})
    if not isinstance(intelligence, dict):
        return "No matched offline intelligence"
    values: list[str] = []
    known = intelligence.get("known_exploited", [])
    if isinstance(known, list) and known:
        values.append("CISA KEV: known exploitation")
    epss = intelligence.get("epss", [])
    if isinstance(epss, list) and epss:
        highest = max(
            (value for value in epss if isinstance(value, dict)),
            key=lambda value: float(value.get("probability", 0.0)),
            default=None,
        )
        if highest is not None:
            values.append(
                f"EPSS {float(highest.get('probability', 0.0)):.1%} "
                f"(percentile {float(highest.get('percentile', 0.0)):.1%})"
            )
    vex = intelligence.get("vex", [])
    if isinstance(vex, list) and vex:
        states = sorted(
            {
                str(value.get("state") or "unknown")
                for value in vex
                if isinstance(value, dict)
            }
        )
        values.append("VEX: " + ", ".join(states))
    return "; ".join(values) or "No matched offline intelligence"


def _coverage_action(run: ToolRun, manifest: ScanManifest) -> str:
    if not run.applicable:
        if (
            manifest.profile in {"production", "release"}
            and run.tool == "pysa"
            and manifest.inventory.python_files
        ):
            return (
                "Add a reviewed Pyre/Pysa configuration and models, stage Pysa "
                "on a supported native runner, and rerun."
            )
        if (
            manifest.profile in {"production", "release"}
            and manifest.inventory.declared_dependencies
            and run.tool in {"cyclonedx-py", "guarddog"}
        ):
            return (
                "Provide a supported reproducible dependency lock and run this "
                "control on a compatible native platform."
            )
        return (
            "No current action; rerun if the project gains content or a platform "
            "configuration that makes this scanner applicable."
        )
    actions = {
        "unavailable": (
            "Stage the approved executable and required offline data or rules, "
            "verify its checksum and version, then rerun."
        ),
        "failed": (
            "Inspect the sanitized evidence record, correct the scanner invocation "
            "or local assets, then rerun."
        ),
        "timed_out": (
            "Review the target scope and runner capacity, tune the scanner timeout "
            "under policy, then rerun."
        ),
        "parse_error": (
            "Verify the scanner version/output schema and update the adapter or pin "
            "a compatible version before rerunning."
        ),
        "skipped": "Confirm the skip reason is approved, then rerun if it changes.",
    }
    return actions.get(
        run.status.value,
        "Review the scanner diagnostic and restore completed coverage.",
    )


def _policy_action(reason: str) -> str:
    lowered = reason.casefold()
    if "network-isolation attestation" in lowered:
        return (
            "Run inside an independently enforced egress-denied boundary and pass "
            "--network-isolated only after the runner verifies that control."
        )
    if "full vcs checkout" in lowered:
        return (
            "Use a full immutable clone with history instead of an exported source "
            "directory, then rerun."
        )
    if "lock file" in lowered:
        return (
            "Generate and approve a reproducible lock file, preferably with artifact "
            "hashes, and rerun dependency and SBOM checks."
        )
    if "built wheel or source distribution" in lowered:
        return (
            "Build the immutable release distributions in the approved build lane, "
            "stage them under the configured artifacts path, and rerun."
        )
    if "data-flow" in lowered or "pysa" in lowered:
        return (
            "Add a reviewed Pyre/Pysa configuration and models, stage the approved "
            "scanner, and rerun."
        )
    if "scanner" in lowered:
        return (
            "Restore the named required scanner and its approved offline assets, "
            "then rerun."
        )
    return "Satisfy the stated policy requirement, attach evidence, and rerun."


def _assurance_row(
    manifest: ScanManifest,
    control: str,
    tools: tuple[str, ...],
    gap_action: str,
    clean_action: str,
    reference: str,
    findings: list[Finding],
    *,
    finding_areas: frozenset[str] | None = None,
) -> tuple[str, str, str, str, str]:
    selected = [run for run in manifest.tools if run.tool in tools]
    applicable = [run for run in selected if run.applicable]
    completed = [run for run in applicable if run.status.value == "completed"]
    if not selected:
        status = "not assessed by profile"
    elif not applicable:
        status = "not applicable to detected content"
    elif len(completed) == len(applicable):
        status = "verified for scan scope"
    elif completed:
        status = "partial coverage"
    else:
        status = "coverage gap"
    coverage_status = status
    relevant_findings = [
        finding
        for finding in findings
        if any(source.tool in tools for source in finding.sources)
        and (finding_areas is None or finding.area in finding_areas)
    ]
    if relevant_findings:
        status = (
            "findings require action"
            if status == "verified for scan scope"
            else f"{status}; findings require action"
        )
        finding_tools = sorted(
            {
                source.tool
                for finding in relevant_findings
                for source in finding.sources
                if source.tool in tools
            }
        )
        count = len(relevant_findings)
        noun = "finding" if count == 1 else "findings"
        finding_action = (
            f"Open action-plan.md and resolve {count} active {noun} attributed to "
            f"{', '.join(finding_tools)} before promotion."
        )
        action = (
            finding_action
            if coverage_status == "verified for scan scope"
            else f"{gap_action} Also, {finding_action}"
        )
    elif status == "verified for scan scope":
        action = clean_action
    elif status == "not applicable to detected content":
        action = (
            "No current action; reevaluate this control when relevant repository "
            "content or release inputs are added."
        )
    else:
        action = gap_action
    evidence = (
        ", ".join(
            f"{run.tool}: {'not applicable' if not run.applicable else run.status.value}"
            for run in selected
        )
        or "No relevant scanner was selected."
    )
    return control, status, evidence, action, reference


def _external_assurance_row(
    manifest: ScanManifest,
    control: str,
    tools: tuple[str, ...],
    required_action: str,
    attached_action: str,
    reference: str,
) -> tuple[str, str, str, str, str]:
    selected = [run for run in manifest.tools if run.tool in tools]
    completed = [
        run for run in selected if run.applicable and run.status.value == "completed"
    ]
    evidence = (
        ", ".join(
            f"{run.tool}: {'not applicable' if not run.applicable else run.status.value}"
            for run in selected
        )
        or "No bounded companion evidence was attached."
    )
    if completed:
        status = "applicable external evidence attached"
        action = attached_action
        evidence += "; evidence was ingested, not executed in the scan boundary"
    else:
        status = "external evidence required"
        action = required_action
        evidence += "; target code execution is prohibited in the scan boundary"
    return control, status, evidence, action, reference


def _sarif_name(rule_id: str) -> str:
    return "".join(character if character.isalnum() else "_" for character in rule_id)[
        :120
    ]


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _sarif_security_score(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 5.5,
        Severity.LOW: 3.0,
        Severity.INFORMATIONAL: 1.0,
        Severity.UNKNOWN: 0.0,
    }[severity]


def _markdown_text(value: str) -> str:
    escaped = value.replace("\\", "\\\\")
    for character in ("`", "*", "_", "{", "}", "[", "]", "<", ">", "#"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped.replace("\r", " ").replace("\n", " ")


def _markdown_code(value: str) -> str:
    return value.replace("`", "'").replace("\r", " ").replace("\n", " ")


def _markdown_table(value: str) -> str:
    return _markdown_text(value).replace("|", "\\|")
