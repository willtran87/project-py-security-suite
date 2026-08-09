from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .baseline_candidate import build_baseline_candidate
from .audit_package import create_audit_package, verify_audit_package
from .audience_report import AUDIENCES, build_audience_report, render_audience_markdown
from .config import ConfigurationError, PROFILE_TOOLS, load_config
from .config_provenance import build_config_provenance
from .doctor import assess_readiness, render_readiness
from .evidence_draft import build_governance_evidence_draft
from .evidence_pack import create_evidence_pack, verify_evidence_pack
from .finding_register import build_finding_register
from .github_annotations import build_github_annotations, render_github_commands
from .effectiveness_corpus import evaluate_report_corpus
from .execution import sanitize_terminal_text
from .orchestrator import scan_project
from .operational_trend import build_operational_trend
from .policy import exit_code
from .policy_simulation import simulate_policy
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
    BUNDLED_SCHEMA_RESOURCES,
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pysec",
        description=(
            "Run an offline-first portfolio of security scanners against a "
            "Python project and generate one coordinated report artifact."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a Python project")
    scan.add_argument("target", type=Path)
    scan.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new directory for the complete report artifact",
    )
    scan.add_argument(
        "--config",
        type=Path,
        help="repository configuration in TOML format",
    )
    scan.add_argument(
        "--policy",
        type=Path,
        help="organization policy in TOML format",
    )
    scan.add_argument(
        "--profile",
        choices=sorted(PROFILE_TOOLS),
        help="override the configured scan profile",
    )
    scan.add_argument(
        "--network-isolated",
        action="store_true",
        help=(
            "attest that an external egress-denied boundary is active; this "
            "flag does not create the sandbox"
        ),
    )
    scan.add_argument(
        "--diagnostic-without-isolation",
        action="store_true",
        help=(
            "run offline-configured scanners without an external isolation "
            "attestation; the policy result remains INCOMPLETE"
        ),
    )
    scan.add_argument(
        "--overwrite",
        action="store_true",
        help="replace an existing report directory after safety checks",
    )
    scan.add_argument(
        "--github-summary",
        action="store_true",
        help="append summary.md to GITHUB_STEP_SUMMARY after report generation",
    )

    doctor = subparsers.add_parser(
        "doctor",
        help="check profile prerequisites without executing scanners",
    )
    doctor.add_argument("target", type=Path)
    doctor.add_argument("--config", type=Path)
    doctor.add_argument("--policy", type=Path)
    doctor.add_argument("--profile", choices=sorted(PROFILE_TOOLS))
    doctor.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="operator text or machine-readable JSON",
    )

    attest = subparsers.add_parser(
        "attest", help="create a portable, optionally signed Security Passport"
    )
    attest.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    attest.add_argument(
        "--output", type=Path, required=True, metavar="PASSPORT_DIRECTORY"
    )
    signing = attest.add_mutually_exclusive_group(required=True)
    signing.add_argument("--signing-key", type=Path)
    signing.add_argument(
        "--unsigned",
        action="store_true",
        help="prepare an integrity-only passport for a separate approval signer",
    )
    attest.add_argument("--cosign-executable", default="cosign")
    attest.add_argument(
        "--signing-password-file",
        type=Path,
        help="bounded file supplying COSIGN_PASSWORD without command-line exposure",
    )
    attest.add_argument("--cosign-sha256", default="")
    attest.add_argument(
        "--allow-signing-network",
        action="store_true",
        help="authorize Cosign v3 to contact configured signing services",
    )
    attest.add_argument(
        "--signing-config",
        type=Path,
        help="reviewed Cosign v3 signing configuration (public or private service)",
    )
    attest.add_argument("--overwrite", action="store_true")

    sign_artifacts = subparsers.add_parser(
        "sign-artifacts",
        help="create digest-bound Sigstore bundles for release distributions",
    )
    sign_artifacts.add_argument("artifacts", type=Path, metavar="ARTIFACT_DIRECTORY")
    sign_artifacts.add_argument("--output", type=Path, required=True)
    sign_artifacts.add_argument("--signing-key", type=Path, required=True)
    sign_artifacts.add_argument("--signing-password-file", type=Path)
    sign_artifacts.add_argument("--cosign-executable", default="cosign")
    sign_artifacts.add_argument("--cosign-sha256", required=True)
    sign_artifacts.add_argument("--allow-signing-network", action="store_true")
    sign_artifacts.add_argument("--signing-config", type=Path)
    sign_artifacts.add_argument("--overwrite", action="store_true")

    prepare_signing = subparsers.add_parser(
        "prepare-signing",
        help="bind a verified report to an exact release payload for external signing",
    )
    prepare_signing.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    prepare_signing.add_argument("artifacts", type=Path, metavar="ARTIFACT_DIRECTORY")
    prepare_signing.add_argument("--output", type=Path, required=True)
    prepare_signing.add_argument("--overwrite", action="store_true")

    verify_signing = subparsers.add_parser(
        "verify-signing-request",
        help="verify that an approved signing request still matches an exact payload",
    )
    verify_signing.add_argument("request", type=Path, metavar="REQUEST_FILE")
    verify_signing.add_argument("artifacts", type=Path, metavar="ARTIFACT_DIRECTORY")
    verify_signing.add_argument("--request-sha256", required=True)
    verify_signing.add_argument("--format", choices=("text", "json"), default="text")
    verify_signing.add_argument("--output", type=Path, metavar="FILE")
    verify_signing.add_argument("--overwrite", action="store_true")

    verify = subparsers.add_parser(
        "verify", help="verify a Security Passport and optional source report"
    )
    verify.add_argument(
        "passport",
        type=Path,
        metavar="PASSPORT_DIRECTORY",
        help="portable passport directory created by 'pysec attest'",
    )
    verify.add_argument("--report", type=Path, metavar="REPORT_DIRECTORY")
    verify.add_argument(
        "--artifact-root",
        type=Path,
        metavar="DIRECTORY",
        help="root containing release files at their Passport subject paths",
    )
    verify.add_argument("--public-key", type=Path)
    verify.add_argument("--cosign-executable", default="cosign")
    verify.add_argument("--cosign-sha256", default="")
    verify.add_argument("--allow-unsigned", action="store_true")
    verify.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="machine-readable JSON or concise operator text",
    )
    verify.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="atomically write the JSON verification receipt",
    )
    verify.add_argument("--overwrite", action="store_true")

    verify_report_parser = subparsers.add_parser(
        "verify-report", help="verify a generated report checksum chain"
    )
    verify_report_parser.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    verify_report_parser.add_argument(
        "--format", choices=("text", "json"), default="text"
    )
    verify_report_parser.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="atomically write the portable JSON verification receipt",
    )
    verify_report_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace an existing report-verification receipt",
    )

    verify_inspection_parser = subparsers.add_parser(
        "verify-inspection",
        help="verify an inspection sidecar against its sealed report",
    )
    verify_inspection_parser.add_argument(
        "inspection", type=Path, metavar="INSPECTION_FILE"
    )
    verify_inspection_parser.add_argument(
        "--report", type=Path, required=True, metavar="REPORT_DIRECTORY"
    )
    verify_inspection_parser.add_argument(
        "--format", choices=("text", "json"), default="text"
    )
    verify_inspection_parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="expected prioritized-action limit used during export (0-100)",
    )
    verify_inspection_parser.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="atomically write the portable JSON verification receipt",
    )
    verify_inspection_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace an existing verification receipt",
    )

    inspect = subparsers.add_parser(
        "inspect", help="verify and summarize an existing report"
    )
    inspect.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    inspect.add_argument("--format", choices=("text", "json"), default="text")
    inspect.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help=(
            "atomically write the derived inspection beside, never inside, "
            "the sealed report"
        ),
    )
    inspect.add_argument(
        "--overwrite",
        action="store_true",
        help="replace an existing inspection output file",
    )
    inspect.add_argument(
        "--limit",
        type=int,
        default=5,
        help="number of prioritized actions to show (0-100)",
    )

    schema = subparsers.add_parser(
        "schema",
        help="print or export an installed versioned report schema",
    )
    schema.add_argument(
        "name",
        choices=sorted(BUNDLED_SCHEMA_RESOURCES),
        help="version-explicit bundled schema contract",
    )
    schema.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="atomically export the schema for disconnected consumers",
    )
    schema.add_argument(
        "--overwrite",
        action="store_true",
        help="replace an existing schema export",
    )

    list_tools = subparsers.add_parser(
        "list-tools", help="show scanners selected by each profile"
    )
    list_tools.add_argument("--profile", choices=sorted(PROFILE_TOOLS))
    list_tools.add_argument("--format", choices=("text", "json"), default="text")

    benchmark = subparsers.add_parser(
        "benchmark",
        help="measure a verified report against a digest-bound labeled corpus",
    )
    benchmark.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    benchmark.add_argument("--corpus", type=Path, required=True)
    benchmark.add_argument("--corpus-sha256", required=True)
    benchmark.add_argument("--format", choices=("text", "json"), default="text")
    benchmark.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="atomically publish the effectiveness evaluation outside the sealed report",
    )
    benchmark.add_argument("--overwrite", action="store_true")

    release_check = subparsers.add_parser(
        "release-check",
        help="aggregate verified report, trust, isolation, effectiveness, and passport evidence",
    )
    release_check.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    release_check.add_argument("--effectiveness-evaluation", type=Path)
    release_check.add_argument("--effectiveness-sha256", default="")
    release_check.add_argument("--minimum-effectiveness-labels", type=int, default=0)
    release_check.add_argument(
        "--minimum-effectiveness-positive-labels", type=int, default=0
    )
    release_check.add_argument(
        "--minimum-effectiveness-negative-labels", type=int, default=0
    )
    release_check.add_argument("--minimum-effectiveness-tools", type=int, default=0)
    release_check.add_argument(
        "--minimum-effectiveness-labels-per-tool", type=int, default=0
    )
    release_check.add_argument(
        "--required-effectiveness-tool",
        action="append",
        default=[],
        help="require labeled effectiveness evidence for this scanner (repeatable)",
    )
    release_check.add_argument("--passport-verification", type=Path)
    release_check.add_argument("--passport-verification-sha256", default="")
    release_check.add_argument("--require-passport", action="store_true")
    release_check.add_argument("--format", choices=("text", "json"), default="text")
    release_check.add_argument("--output", type=Path, metavar="FILE")
    release_check.add_argument("--overwrite", action="store_true")

    evidence_draft = subparsers.add_parser(
        "evidence-draft",
        help="export a non-authoritative governance evidence handoff",
    )
    evidence_draft.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    evidence_draft.add_argument("--format", choices=("text", "json"), default="text")
    evidence_draft.add_argument("--output", type=Path, metavar="FILE")
    evidence_draft.add_argument("--overwrite", action="store_true")

    promotion = subparsers.add_parser(
        "promotion-plan",
        help="consolidate lifecycle, assurance, baseline, reliability, and release actions",
    )
    promotion.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    promotion.add_argument("--release-readiness", type=Path)
    promotion.add_argument("--release-readiness-sha256", default="")
    promotion.add_argument(
        "--format", choices=("text", "json", "markdown", "html"), default="text"
    )
    promotion.add_argument("--output", type=Path, metavar="FILE")
    promotion.add_argument("--overwrite", action="store_true")

    baseline_candidate = subparsers.add_parser(
        "baseline-candidate",
        help="prepare a verified, revision-bound findings report for external approval",
    )
    baseline_candidate.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    baseline_candidate.add_argument(
        "--format", choices=("text", "json"), default="text"
    )
    baseline_candidate.add_argument("--output", type=Path, metavar="FILE")
    baseline_candidate.add_argument("--overwrite", action="store_true")

    trend = subparsers.add_parser(
        "trend", help="compare 2-100 sealed reports for operational regressions"
    )
    trend.add_argument("reports", type=Path, nargs="+", metavar="REPORT_DIRECTORY")
    trend.add_argument(
        "--performance-regression-percent",
        type=float,
        default=50.0,
        help="flag latest scanner duration increases above this percentage",
    )
    trend.add_argument("--maximum-total-seconds", type=float)
    trend.add_argument(
        "--tool-budget",
        action="append",
        default=[],
        metavar="TOOL=SECONDS",
        help="flag a latest scanner duration above its absolute budget (repeatable)",
    )
    trend.add_argument("--format", choices=("text", "json"), default="text")
    trend.add_argument("--output", type=Path, metavar="FILE")
    trend.add_argument("--overwrite", action="store_true")

    release_manifest = subparsers.add_parser(
        "release-manifest",
        help="bind independently approved release evidence into one closed manifest",
    )
    release_manifest.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    release_manifest.add_argument(
        "--evidence",
        action="append",
        required=True,
        metavar="NAME=PATH@SHA256",
        help="digest-bound JSON evidence; repeat for every release input",
    )
    release_manifest.add_argument("--format", choices=("text", "json"), default="text")
    release_manifest.add_argument("--output", type=Path, metavar="FILE")
    release_manifest.add_argument("--overwrite", action="store_true")

    verify_release_manifest = subparsers.add_parser(
        "verify-release-manifest",
        help="independently verify a closed release evidence manifest and its report",
    )
    verify_release_manifest.add_argument("manifest", type=Path, metavar="MANIFEST")
    verify_release_manifest.add_argument("--manifest-sha256", required=True)
    verify_release_manifest.add_argument("--report", type=Path, required=True)
    verify_release_manifest.add_argument(
        "--required-evidence",
        action="append",
        default=[],
        metavar="NAME",
        help="require an exact evidence name in the manifest (repeatable)",
    )
    verify_release_manifest.add_argument(
        "--evidence-location",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="relocate a manifest evidence item after artifact transfer (repeatable)",
    )
    verify_release_manifest.add_argument(
        "--format", choices=("text", "json"), default="text"
    )
    verify_release_manifest.add_argument("--output", type=Path, metavar="FILE")
    verify_release_manifest.add_argument("--overwrite", action="store_true")

    policy_simulation = subparsers.add_parser(
        "policy-simulate",
        help="evaluate a hypothetical admission policy against a sealed report",
    )
    policy_simulation.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    policy_simulation.add_argument("--block-severity", action="append", default=[])
    policy_simulation.add_argument("--require-tool", action="append", default=[])
    policy_simulation.add_argument(
        "--minimum-confidence",
        choices=("unknown", "low", "medium", "high"),
        default="unknown",
    )
    policy_simulation.add_argument("--maximum-blocking-findings", type=int, default=0)
    policy_simulation.add_argument("--format", choices=("text", "json"), default="text")
    policy_simulation.add_argument("--output", type=Path, metavar="FILE")
    policy_simulation.add_argument("--overwrite", action="store_true")

    finding_register = subparsers.add_parser(
        "finding-register",
        help="build durable finding lifecycle and SLA state from a sealed report",
    )
    finding_register.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    finding_register.add_argument("--previous", type=Path)
    finding_register.add_argument("--previous-sha256", default="")
    finding_register.add_argument("--format", choices=("text", "json"), default="text")
    finding_register.add_argument("--output", type=Path, metavar="FILE")
    finding_register.add_argument("--overwrite", action="store_true")

    annotations = subparsers.add_parser(
        "github-annotations",
        help="verify and render promotion-plan annotations for GitHub Actions",
    )
    annotations.add_argument("plan", type=Path, metavar="PROMOTION_PLAN")
    annotations.add_argument("--plan-sha256", required=True)
    annotations.add_argument("--report", type=Path, required=True)
    annotations.add_argument("--format", choices=("github", "json"), default="github")
    annotations.add_argument("--output", type=Path, metavar="FILE")
    annotations.add_argument("--overwrite", action="store_true")

    audit = subparsers.add_parser(
        "audit-package",
        help="create a deterministic portable package of a sealed report and evidence",
    )
    audit.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    audit.add_argument(
        "--evidence", action="append", default=[], metavar="NAME=PATH@SHA256"
    )
    audit.add_argument("--output", type=Path, required=True, metavar="ZIP_FILE")
    audit.add_argument("--overwrite", action="store_true")
    audit.add_argument("--format", choices=("text", "json"), default="text")

    verify_audit = subparsers.add_parser(
        "verify-audit-package",
        help="verify every file and embedded report in a portable audit package",
    )
    verify_audit.add_argument("package", type=Path, metavar="ZIP_FILE")
    verify_audit.add_argument("--package-sha256", required=True)
    verify_audit.add_argument("--format", choices=("text", "json"), default="text")
    verify_audit.add_argument("--output", type=Path, metavar="RECEIPT_FILE")
    verify_audit.add_argument("--overwrite", action="store_true")

    merge_coverage = subparsers.add_parser(
        "merge-coverage",
        help="merge digest-bound coverage.py JSON from multiple runtime scenarios",
    )
    merge_coverage.add_argument(
        "--scenario", action="append", required=True, metavar="NAME=PATH@SHA256"
    )
    merge_coverage.add_argument(
        "--output", type=Path, required=True, metavar="COVERAGE_JSON"
    )
    merge_coverage.add_argument("--overwrite", action="store_true")

    portfolio = subparsers.add_parser(
        "portfolio",
        help="aggregate 1-500 independently sealed repository reports",
    )
    portfolio.add_argument("reports", type=Path, nargs="+", metavar="REPORT_DIRECTORY")
    portfolio.add_argument("--format", choices=("text", "json"), default="text")
    portfolio.add_argument("--output", type=Path, metavar="FILE")
    portfolio.add_argument("--overwrite", action="store_true")

    config_provenance = subparsers.add_parser(
        "config-provenance",
        help="explain value-redacted origins of the validated effective configuration",
    )
    config_provenance.add_argument("--config", type=Path)
    config_provenance.add_argument("--policy", type=Path)
    config_provenance.add_argument("--profile", choices=tuple(PROFILE_TOOLS))
    config_provenance.add_argument("--format", choices=("text", "json"), default="text")
    config_provenance.add_argument("--output", type=Path, metavar="FILE")
    config_provenance.add_argument("--overwrite", action="store_true")

    audience_report = subparsers.add_parser(
        "audience-report",
        help="export one verified audience view from a promotion plan",
    )
    audience_report.add_argument("plan", type=Path, metavar="PROMOTION_PLAN")
    audience_report.add_argument("--plan-sha256", required=True)
    audience_report.add_argument("--report", type=Path, required=True)
    audience_report.add_argument("--audience", choices=AUDIENCES, required=True)
    audience_report.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text"
    )
    audience_report.add_argument("--output", type=Path, metavar="FILE")
    audience_report.add_argument("--overwrite", action="store_true")

    evidence_pack = subparsers.add_parser(
        "evidence-pack",
        help="atomically publish a closed, portable release evidence package",
    )
    evidence_pack.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    evidence_pack.add_argument(
        "--output", type=Path, required=True, metavar="PACK_DIRECTORY"
    )
    evidence_pack.add_argument("--previous-register", type=Path)
    evidence_pack.add_argument("--previous-register-sha256", default="")
    evidence_pack.add_argument("--previous-report", type=Path)
    evidence_pack.add_argument(
        "--artifacts", type=Path, help="exact wheel/sdist/zip signing payload"
    )
    evidence_pack.add_argument("--config", type=Path)
    evidence_pack.add_argument("--policy", type=Path)
    evidence_pack.add_argument("--profile", choices=tuple(PROFILE_TOOLS))
    release_inputs = evidence_pack.add_argument_group("governed release inputs")
    release_inputs.add_argument("--effectiveness-evaluation", type=Path)
    release_inputs.add_argument("--effectiveness-sha256", default="")
    release_inputs.add_argument("--minimum-effectiveness-labels", type=int, default=0)
    release_inputs.add_argument(
        "--minimum-effectiveness-positive-labels", type=int, default=0
    )
    release_inputs.add_argument(
        "--minimum-effectiveness-negative-labels", type=int, default=0
    )
    release_inputs.add_argument("--minimum-effectiveness-tools", type=int, default=0)
    release_inputs.add_argument(
        "--minimum-effectiveness-labels-per-tool", type=int, default=0
    )
    release_inputs.add_argument(
        "--required-effectiveness-tool", action="append", default=[]
    )
    release_inputs.add_argument("--passport-verification", type=Path)
    release_inputs.add_argument("--passport-verification-sha256", default="")
    release_inputs.add_argument("--require-passport", action="store_true")
    evidence_pack.add_argument("--block-severity", action="append", default=[])
    evidence_pack.add_argument("--require-tool", action="append", default=[])
    evidence_pack.add_argument(
        "--minimum-confidence",
        choices=("unknown", "low", "medium", "high"),
        default="unknown",
    )
    evidence_pack.add_argument("--maximum-blocking-findings", type=int, default=0)
    trend_options = evidence_pack.add_argument_group("historical performance policy")
    trend_options.add_argument(
        "--performance-regression-percent", type=float, default=50.0
    )
    trend_options.add_argument("--maximum-total-seconds", type=float)
    trend_options.add_argument(
        "--tool-budget", action="append", default=[], metavar="TOOL=SECONDS"
    )
    evidence_pack.add_argument("--overwrite", action="store_true")

    verify_evidence_pack_parser = subparsers.add_parser(
        "verify-evidence-pack",
        help="verify a closed evidence pack and its embedded audit archive",
    )
    verify_evidence_pack_parser.add_argument(
        "pack", type=Path, metavar="PACK_DIRECTORY"
    )
    verify_evidence_pack_parser.add_argument("--report", type=Path)
    verify_evidence_pack_parser.add_argument("--pack-sha256", default="")
    verify_evidence_pack_parser.add_argument(
        "--output", type=Path, metavar="RECEIPT_FILE"
    )
    verify_evidence_pack_parser.add_argument("--overwrite", action="store_true")

    reachability = subparsers.add_parser(
        "reachability",
        help="build an offline Python entry-point and reachability graph",
    )
    reachability.add_argument("target", type=Path)
    reachability.add_argument(
        "--entry-point",
        action="append",
        default=[],
        help="additional module:function root; repeat for multiple roots",
    )
    reachability.add_argument(
        "--source-root",
        action="append",
        default=[],
        help="target-relative Python source root; repeat for multiple roots",
    )
    reachability.add_argument(
        "--minimum-island-loc",
        type=int,
        default=100,
        help="minimum disconnected island size retained as a finding candidate",
    )
    reachability.add_argument(
        "--no-framework-roots",
        action="store_true",
        help="disable conservative decorator-based framework root discovery",
    )
    reachability.add_argument(
        "--coverage",
        type=Path,
        help="optional bounded coverage.py JSON evidence used for runtime corroboration",
    )
    reachability.add_argument(
        "--pretty",
        action="store_true",
        help="indent JSON for direct operator inspection",
    )

    reachability_diff = subparsers.add_parser(
        "reachability-diff",
        help="compare two digest-bound reachability graphs",
    )
    reachability_diff.add_argument("baseline", type=Path)
    reachability_diff.add_argument("current", type=Path)
    reachability_diff.add_argument("--baseline-sha256", required=True)
    reachability_diff.add_argument("--current-sha256", required=True)
    reachability_diff.add_argument("--format", choices=("text", "json"), default="text")
    reachability_diff.add_argument("--output", type=Path, metavar="FILE")
    reachability_diff.add_argument("--overwrite", action="store_true")
    return parser


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
        "schema": _schema_command,
        "benchmark": _benchmark_command,
        "release-check": _release_check_command,
        "evidence-draft": _evidence_draft_command,
        "promotion-plan": _promotion_plan_command,
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
        "doctor": _doctor_command,
        "attest": _attest_command,
        "verify": _verify_attestation_command,
        "verify-report": _verify_report_command,
        "verify-inspection": _verify_inspection_command,
        "inspect": _inspect_command,
        "scan": _scan_command,
    }
    return handlers[args.command](args)


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
        print(rendered_json)
    else:
        counts = result["counts"]
        print(
            f"{str(result['verdict']).upper()}: "
            f"{counts['state_regressions']} state regression(s), "
            f"{counts['new_disconnected_nodes']} new disconnected node(s), "
            f"{counts['new_reportable_islands']} new reportable island(s)"
        )
    return 0 if result["verdict"] == "pass" else 1


def _doctor_command(args: argparse.Namespace) -> int:
    config = load_config(
        organization_policy=args.policy,
        repository_config=args.config,
        profile_override=args.profile,
    )
    readiness = assess_readiness(target=args.target, config=config)
    print(
        json.dumps(readiness, indent=2, sort_keys=True)
        if args.format == "json"
        else render_readiness(readiness)
    )
    return 0 if readiness["ready"] else 2


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


def _benchmark_command(args: argparse.Namespace) -> int:
    if args.overwrite and not args.output:
        raise ValueError("benchmark --overwrite requires --output")
    result = evaluate_report_corpus(
        args.report,
        args.corpus,
        corpus_sha256=args.corpus_sha256,
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
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        _write_atomic_output(
            output=args.output,
            content=rendered,
            overwrite=args.overwrite,
            label="operational trend output",
            forbidden_root=args.reports[0],
        )
    if args.format == "json":
        print(rendered)
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
