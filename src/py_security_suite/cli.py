from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .config import ConfigurationError, PROFILE_TOOLS, load_config
from .doctor import assess_readiness, render_readiness
from .effectiveness_corpus import evaluate_report_corpus
from .execution import sanitize_terminal_text
from .orchestrator import scan_project
from .policy import exit_code
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
        "sign-artifacts": _sign_artifacts_command,
        "reachability": _reachability_command,
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
    verification = verify_attestation(
        passport=args.passport,
        report=args.report,
        public_key=args.public_key,
        artifact_root=args.artifact_root,
        cosign_executable=args.cosign_executable,
        cosign_sha256=args.cosign_sha256,
        allow_unsigned=args.allow_unsigned,
    )
    print(
        _render_attestation_verification(verification)
        if args.format == "text"
        else json.dumps(verification, sort_keys=True)
    )
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
    print(rendered)
    return 0


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
