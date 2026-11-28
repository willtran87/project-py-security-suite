"""Argument parser for the ``pysec`` command line.

Each subcommand is registered by its own builder function. The module only
imports lightweight constants so ``pysec --help`` and argument errors do not
load the scanning, reporting and trust machinery.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .audiences import AUDIENCES
from .benchmark_replay_genesis import BENCHMARK_REPLAY_GENESIS_SHA256
from .cli_benchmark_arguments import add_benchmark_commands
from .cli_recovery import add_recovery_commands
from .cli_release_arguments import add_release_check_command
from .cli_scan import add_scan_arguments
from .config_profiles import PROFILE_TOOLS
from .project_init import PROJECT_TEMPLATES
from .report_schema_resources import BUNDLED_SCHEMA_RESOURCES
from .version import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pysec",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Run an offline-first portfolio of security scanners against a "
            "Python project and generate one coordinated report artifact."
        ),
        epilog=(
            "Start here:\n"
            "  pysec init PROJECT --template library\n"
            "  pysec doctor PROJECT --config PROJECT/pysec.toml --explain\n"
            "  pysec provision-plan PROJECT --config PROJECT/pysec.toml\n"
            "  pysec scan PROJECT --config PROJECT/pysec.toml --network-isolated "
            "--output PROJECT/.artifacts/pysec-report\n"
            "  pysec inspect PROJECT/.artifacts/pysec-report"
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_recovery_commands(subparsers)
    _add_init_command(subparsers)
    _add_scan_command(subparsers)
    _add_encrypt_report_command(subparsers)
    _add_retention_status_command(subparsers)
    _add_purge_expired_report_command(subparsers)
    _add_doctor_command(subparsers)
    _add_provision_plan_command(subparsers)
    _add_attest_command(subparsers)
    _add_sign_artifacts_command(subparsers)
    _add_prepare_signing_command(subparsers)
    _add_verify_signing_request_command(subparsers)
    _add_verify_command(subparsers)
    _add_verify_report_command(subparsers)
    _add_verify_inspection_command(subparsers)
    _add_inspect_command(subparsers)
    _add_schema_command(subparsers)
    _add_list_tools_command(subparsers)
    _add_adapter_check_command(subparsers)
    _add_qualify_bundle_command(subparsers)
    _add_verify_native_bundle_command(subparsers)
    _add_generate_ci_command(subparsers)
    _add_generate_hooks_command(subparsers)
    _add_config_check_command(subparsers)
    add_benchmark_commands(
        subparsers,
        replay_genesis_sha256=BENCHMARK_REPLAY_GENESIS_SHA256,
    )
    _add_standards_manifest_build_command(subparsers)
    _add_standards_monitor_command(subparsers)
    _add_standards_monitor_verify_command(subparsers)
    add_release_check_command(subparsers)
    _add_evidence_draft_command(subparsers)
    _add_promotion_plan_command(subparsers)
    _add_closure_plan_command(subparsers)
    _add_compare_builds_command(subparsers)
    _add_normalize_sdist_command(subparsers)
    _add_baseline_candidate_command(subparsers)
    _add_trend_command(subparsers)
    _add_release_manifest_command(subparsers)
    _add_verify_release_manifest_command(subparsers)
    _add_policy_simulate_command(subparsers)
    _add_finding_register_command(subparsers)
    _add_github_annotations_command(subparsers)
    _add_audit_package_command(subparsers)
    _add_verify_audit_package_command(subparsers)
    _add_merge_coverage_command(subparsers)
    _add_portfolio_command(subparsers)
    _add_config_provenance_command(subparsers)
    _add_audience_report_command(subparsers)
    _add_evidence_pack_command(subparsers)
    _add_verify_evidence_pack_command(subparsers)
    _add_reachability_command(subparsers)
    _add_reachability_diff_command(subparsers)
    _add_advanced_diff_command(subparsers)
    return parser


def _add_init_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    initialize = subparsers.add_parser(
        "init", help="create a minimal offline-first repository configuration"
    )
    initialize.add_argument(
        "target", type=Path, help="existing repository directory to initialize"
    )
    initialize.add_argument(
        "--template",
        choices=PROJECT_TEMPLATES,
        default="library",
        help="project shape used for profile and reachability guidance",
    )
    initialize.add_argument(
        "--profile",
        choices=sorted(PROFILE_TOOLS),
        help="override the template-recommended scan profile",
    )
    initialize.add_argument(
        "--output",
        type=Path,
        help="configuration path inside TARGET (default: TARGET/pysec.toml)",
    )
    initialize.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="concise guidance or schema-governed initialization receipt",
    )
    initialize.add_argument(
        "--overwrite",
        action="store_true",
        help="explicitly replace an existing regular configuration file",
    )


def _add_scan_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    add_scan_arguments(subparsers.add_parser("scan", help="scan a Python project"))


def _add_encrypt_report_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    encrypt = subparsers.add_parser(
        "encrypt-report", help="encrypt a verified report for X25519 transport"
    )
    encrypt.add_argument("report", type=Path)
    encrypt.add_argument("--output", type=Path, required=True)
    encrypt.add_argument("--recipient-public-key", type=Path, required=True)
    encrypt.add_argument("--recipient-public-key-sha256", required=True)
    encrypt.add_argument("--key-lifecycle-receipt", type=Path, required=True)
    encrypt.add_argument("--key-lifecycle-receipt-sha256", required=True)
    encrypt.add_argument("--key-authority-public-key", type=Path, required=True)
    encrypt.add_argument("--key-authority-public-key-sha256", required=True)
    encrypt.add_argument("--key-lifecycle-signature", type=Path, required=True)
    encrypt.add_argument("--provider-attestation", type=Path, required=True)
    encrypt.add_argument("--provider-attestation-sha256", required=True)
    encrypt.add_argument("--provider-authority-public-key", type=Path, required=True)
    encrypt.add_argument("--provider-authority-public-key-sha256", required=True)
    encrypt.add_argument("--provider-attestation-signature", type=Path, required=True)
    encrypt.add_argument("--trusted-time-context", type=Path, required=True)
    encrypt.add_argument("--overwrite", action="store_true")
    encrypt.add_argument(
        "--delete-plaintext-after-encryption",
        action="store_true",
        help="delete the verified plaintext report after authenticated encryption",
    )


def _add_retention_status_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    retention = subparsers.add_parser(
        "retention-status", help="verify a report and evaluate its retention deadline"
    )
    retention.add_argument("report", type=Path)


def _add_purge_expired_report_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    purge = subparsers.add_parser(
        "purge-expired-report",
        help="delete a verified report after its retention deadline",
    )
    purge.add_argument("report", type=Path)
    purge.add_argument("--trusted-time-context", type=Path, required=True)


def _add_doctor_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    doctor = subparsers.add_parser(
        "doctor",
        help="check profile prerequisites without executing scanners",
    )
    doctor.add_argument(
        "target", type=Path, help="existing repository directory to assess"
    )
    doctor.add_argument("--config", type=Path, help="repository TOML configuration")
    doctor.add_argument("--policy", type=Path, help="organization TOML policy")
    doctor.add_argument(
        "--profile",
        choices=sorted(PROFILE_TOOLS),
        help="override the configured profile for this assessment",
    )
    doctor.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="operator text, machine-readable JSON, or GitHub-ready Markdown",
    )
    doctor.add_argument(
        "--explain",
        action="store_true",
        help="include ordered actions, reasons, identities, and selected controls",
    )
    doctor.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="atomically publish the rendered result",
    )
    doctor.add_argument(
        "--overwrite",
        action="store_true",
        help="explicitly replace an existing regular output file",
    )


def _add_provision_plan_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    provision = subparsers.add_parser(
        "provision-plan",
        help="plan offline prerequisites without downloading or changing files",
    )
    provision.add_argument("target", type=Path, help="repository directory to assess")
    provision.add_argument("--config", type=Path, help="repository TOML configuration")
    provision.add_argument("--policy", type=Path, help="organization TOML policy")
    provision.add_argument(
        "--profile",
        choices=sorted(PROFILE_TOOLS),
        help="override the configured profile",
    )
    provision.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="operator text, schema-governed JSON, or GitHub-ready Markdown",
    )
    provision.add_argument("--output", type=Path, metavar="FILE")
    provision.add_argument("--overwrite", action="store_true")


def _add_attest_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_sign_artifacts_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_prepare_signing_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    prepare_signing = subparsers.add_parser(
        "prepare-signing",
        help="bind a verified report to an exact release payload for external signing",
    )
    prepare_signing.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    prepare_signing.add_argument("artifacts", type=Path, metavar="ARTIFACT_DIRECTORY")
    prepare_signing.add_argument("--output", type=Path, required=True)
    prepare_signing.add_argument("--overwrite", action="store_true")


def _add_verify_signing_request_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_verify_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_verify_report_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_verify_inspection_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_inspect_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_schema_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_list_tools_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    list_tools = subparsers.add_parser(
        "list-tools", help="show scanners selected by each profile"
    )
    list_tools.add_argument("--profile", choices=sorted(PROFILE_TOOLS))
    list_tools.add_argument("--format", choices=("text", "json"), default="text")


def _add_adapter_check_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    adapter_check = subparsers.add_parser(
        "adapter-check",
        help="validate the non-executing adapter SDK and registry contract",
    )
    adapter_check.add_argument("--format", choices=("text", "json"), default="text")
    adapter_check.add_argument("--output", type=Path, metavar="FILE")
    adapter_check.add_argument("--overwrite", action="store_true")


def _add_qualify_bundle_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    qualify = subparsers.add_parser(
        "qualify-bundle",
        help="join adapter contracts and activation-free profile readiness",
    )
    qualify.add_argument("target", type=Path, help="repository used for applicability")
    qualify.add_argument("--config", type=Path)
    qualify.add_argument("--policy", type=Path)
    qualify.add_argument("--profile", choices=sorted(PROFILE_TOOLS))
    qualify.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text"
    )
    qualify.add_argument(
        "--effectiveness-evaluation",
        type=Path,
        help="digest-bound labeled-corpus evaluation produced by 'pysec benchmark'",
    )
    qualify.add_argument(
        "--effectiveness-report",
        type=Path,
        help="sealed report that produced the labeled-corpus evaluation",
    )
    qualify.add_argument("--effectiveness-sha256", default="")
    qualify.add_argument("--minimum-effectiveness-labels", type=int, default=0)
    qualify.add_argument("--minimum-effectiveness-tools", type=int, default=0)
    qualify.add_argument(
        "--required-effectiveness-tool",
        action="append",
        default=[],
        help="require behavioral evidence for this scanner (repeatable)",
    )
    qualify.add_argument("--output", type=Path, metavar="FILE")
    qualify.add_argument("--overwrite", action="store_true")


def _add_verify_native_bundle_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    verify_bundle = subparsers.add_parser(
        "verify-native-bundle",
        help="verify the closed native scanner bundle and offline wheelhouse",
    )
    verify_bundle.add_argument("bundle", type=Path, help="transferred bundle directory")
    verify_bundle.add_argument(
        "--manifest-sha256",
        default="",
        help="independently transferred approved manifest digest",
    )
    verify_bundle.add_argument(
        "--python",
        type=Path,
        help="trusted Python with pip used for no-index dependency resolution",
    )
    verify_bundle.add_argument(
        "--require-wheelhouse-closure",
        action="store_true",
        help="fail unless every declared Python environment resolves with --no-index",
    )
    verify_bundle.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text"
    )
    verify_bundle.add_argument("--output", type=Path, metavar="FILE")
    verify_bundle.add_argument("--overwrite", action="store_true")


def _add_generate_ci_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    generate_ci = subparsers.add_parser(
        "generate-ci",
        help="create a pinned GitHub workflow for a pre-provisioned isolated runner",
    )
    generate_ci.add_argument("target", type=Path, help="repository directory")
    generate_ci.add_argument(
        "--output",
        type=Path,
        help="workflow path inside target (default: .github/workflows/python-security.yml)",
    )
    generate_ci.add_argument(
        "--profile", choices=sorted(PROFILE_TOOLS), default="production"
    )
    generate_ci.add_argument("--config", default="pysec.toml", metavar="REPO_PATH")
    generate_ci.add_argument("--checkout-sha", required=True)
    generate_ci.add_argument("--upload-artifact-sha", required=True)
    generate_ci.add_argument("--upload-sarif-sha", required=True)
    generate_ci.add_argument("--policy-variable", default="PYSEC_ORGANIZATION_POLICY")
    generate_ci.add_argument(
        "--isolation-command",
        default="enterprise-verify-pysec-isolation",
        help="one-line organization-owned isolation verification command",
    )
    generate_ci.add_argument(
        "--runner-label",
        action="append",
        default=[],
        help="repeat for each required self-hosted runner label",
    )
    generate_ci.add_argument("--format", choices=("text", "json"), default="text")
    generate_ci.add_argument("--overwrite", action="store_true")


def _add_generate_hooks_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    generate_hooks = subparsers.add_parser(
        "generate-hooks",
        help="create safe local pre-commit diagnostics without running scanners",
    )
    generate_hooks.add_argument("target", type=Path, help="repository directory")
    generate_hooks.add_argument(
        "--output",
        type=Path,
        help="hook configuration inside target (default: .pre-commit-config.yaml)",
    )
    generate_hooks.add_argument(
        "--profile", choices=sorted(PROFILE_TOOLS), default="quick"
    )
    generate_hooks.add_argument("--config", default="pysec.toml", metavar="REPO_PATH")
    generate_hooks.add_argument("--format", choices=("text", "json"), default="text")
    generate_hooks.add_argument("--overwrite", action="store_true")


def _add_config_check_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    config_check = subparsers.add_parser(
        "config-check",
        help="validate configuration and provide migration and portability advice",
    )
    config_check.add_argument("--config", type=Path, required=True)
    config_check.add_argument("--policy", type=Path)
    config_check.add_argument("--profile", choices=sorted(PROFILE_TOOLS))
    config_check.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text"
    )
    config_check.add_argument("--output", type=Path, metavar="FILE")
    config_check.add_argument("--overwrite", action="store_true")


def _add_standards_manifest_build_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    standards_build = subparsers.add_parser(
        "standards-manifest-build",
        help="compile verified local baselines into a standards monitor manifest",
    )
    standards_build.add_argument("inventory", type=Path, metavar="BASELINE_INVENTORY")
    standards_build.add_argument("--standard", action="append", default=[])
    standards_build.add_argument("--output", type=Path, required=True, metavar="FILE")
    standards_build.add_argument("--overwrite", action="store_true")


def _add_standards_monitor_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    standards_monitor = subparsers.add_parser(
        "standards-monitor",
        help="quarantine publisher snapshots and report standards lifecycle changes",
    )
    standards_monitor.add_argument("manifest", type=Path, metavar="SOURCE_MANIFEST")
    standards_monitor.add_argument(
        "--output", type=Path, required=True, metavar="DIRECTORY"
    )
    standards_monitor.add_argument(
        "--authorize-network",
        action="store_true",
        help="confirm authorization for restricted HTTPS publisher retrieval",
    )
    standards_monitor.add_argument("--signing-key", type=Path)
    standards_monitor.add_argument("--overwrite", action="store_true")


def _add_standards_monitor_verify_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    standards_verify = subparsers.add_parser(
        "standards-monitor-verify",
        help="verify a signed standards publisher lifecycle report",
    )
    standards_verify.add_argument("report", type=Path)
    standards_verify.add_argument("--report-sha256", required=True)
    standards_verify.add_argument("--public-key", type=Path, required=True)


def _add_evidence_draft_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    evidence_draft = subparsers.add_parser(
        "evidence-draft",
        help="export a non-authoritative governance evidence handoff",
    )
    evidence_draft.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    evidence_draft.add_argument("--format", choices=("text", "json"), default="text")
    evidence_draft.add_argument("--output", type=Path, metavar="FILE")
    evidence_draft.add_argument("--overwrite", action="store_true")


def _add_promotion_plan_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    promotion = subparsers.add_parser(
        "promotion-plan",
        help="consolidate lifecycle, assurance, baseline, reliability, and release actions",
    )
    promotion.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    promotion.add_argument("--release-readiness", type=Path)
    promotion.add_argument("--release-readiness-sha256", default="")
    promotion.add_argument("--operational-trend", type=Path)
    promotion.add_argument("--operational-trend-sha256", default="")
    promotion.add_argument(
        "--format", choices=("text", "json", "markdown", "html"), default="text"
    )
    promotion.add_argument("--output", type=Path, metavar="FILE")
    promotion.add_argument("--overwrite", action="store_true")


def _add_closure_plan_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    closure = subparsers.add_parser(
        "closure-plan",
        help="turn a verified report into an owned, evidence-based closure backlog",
    )
    closure.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    closure.add_argument(
        "--coverage-target",
        type=float,
        default=90.0,
        help="combined module coverage target used to select hotspots (default: 90)",
    )
    closure.add_argument(
        "--hotspot-limit",
        type=int,
        default=10,
        help="maximum number of source coverage hotspots (default: 10)",
    )
    closure.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text"
    )
    closure.add_argument("--output", type=Path, metavar="FILE")
    closure.add_argument("--overwrite", action="store_true")


def _add_compare_builds_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    compare = subparsers.add_parser(
        "compare-builds",
        help="compare two independently produced artifact directories byte for byte",
    )
    compare.add_argument("first", type=Path, metavar="FIRST_BUILD_DIRECTORY")
    compare.add_argument("second", type=Path, metavar="SECOND_BUILD_DIRECTORY")
    compare.add_argument("--first-label", default="build-a")
    compare.add_argument("--second-label", default="build-b")
    compare.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text"
    )
    compare.add_argument("--output", type=Path, metavar="FILE")
    compare.add_argument("--overwrite", action="store_true")


def _add_normalize_sdist_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    normalize = subparsers.add_parser(
        "normalize-sdist",
        help="rewrite one .tar.gz source distribution with deterministic metadata",
    )
    normalize.add_argument("source", type=Path, metavar="SOURCE_TAR_GZ")
    normalize.add_argument("--output", type=Path, required=True, metavar="TAR_GZ")
    normalize.add_argument(
        "--source-date-epoch",
        type=int,
        required=True,
        help="reviewed non-negative Unix epoch applied to every archive header",
    )
    normalize.add_argument("--format", choices=("text", "json"), default="text")
    normalize.add_argument("--overwrite", action="store_true")


def _add_baseline_candidate_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_trend_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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
    trend.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    trend.add_argument("--output", type=Path, metavar="FILE")
    trend.add_argument("--overwrite", action="store_true")


def _add_release_manifest_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_verify_release_manifest_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_policy_simulate_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_finding_register_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_github_annotations_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_audit_package_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_verify_audit_package_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    verify_audit = subparsers.add_parser(
        "verify-audit-package",
        help="verify every file and embedded report in a portable audit package",
    )
    verify_audit.add_argument("package", type=Path, metavar="ZIP_FILE")
    verify_audit.add_argument("--package-sha256", required=True)
    verify_audit.add_argument("--format", choices=("text", "json"), default="text")
    verify_audit.add_argument("--output", type=Path, metavar="RECEIPT_FILE")
    verify_audit.add_argument("--overwrite", action="store_true")


def _add_merge_coverage_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_portfolio_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    portfolio = subparsers.add_parser(
        "portfolio",
        help="aggregate 1-500 independently sealed repository reports",
    )
    portfolio.add_argument("reports", type=Path, nargs="+", metavar="REPORT_DIRECTORY")
    portfolio.add_argument("--format", choices=("text", "json"), default="text")
    portfolio.add_argument("--output", type=Path, metavar="FILE")
    portfolio.add_argument("--overwrite", action="store_true")


def _add_config_provenance_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_audience_report_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_evidence_pack_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_verify_evidence_pack_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_reachability_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_reachability_diff_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
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


def _add_advanced_diff_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    advanced_diff = subparsers.add_parser(
        "advanced-diff",
        help="compare two digest-bound cross-evidence attack-surface analyses",
    )
    advanced_diff.add_argument("baseline", type=Path)
    advanced_diff.add_argument("current", type=Path)
    advanced_diff.add_argument("--baseline-sha256", required=True)
    advanced_diff.add_argument("--current-sha256", required=True)
    advanced_diff.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text"
    )
    advanced_diff.add_argument("--output", type=Path, metavar="FILE")
    advanced_diff.add_argument("--overwrite", action="store_true")
