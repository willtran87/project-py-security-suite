from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from . import __version__
from .config import ConfigurationError, PROFILE_TOOLS, load_config
from .doctor import assess_readiness, render_readiness
from .orchestrator import scan_project
from .policy import exit_code
from .passport import create_attestation, verify_attestation, verify_report
from .report_inspection import inspect_report, render_inspection


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
    verify.add_argument("--public-key", type=Path)
    verify.add_argument("--cosign-executable", default="cosign")
    verify.add_argument("--cosign-sha256", default="")
    verify.add_argument("--allow-unsigned", action="store_true")

    verify_report_parser = subparsers.add_parser(
        "verify-report", help="verify a generated report checksum chain"
    )
    verify_report_parser.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    verify_report_parser.add_argument(
        "--format", choices=("text", "json"), default="text"
    )

    inspect = subparsers.add_parser(
        "inspect", help="verify and summarize an existing report"
    )
    inspect.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    inspect.add_argument("--format", choices=("text", "json"), default="text")
    inspect.add_argument(
        "--limit",
        type=int,
        default=5,
        help="number of prioritized actions to show (0-100)",
    )

    list_tools = subparsers.add_parser(
        "list-tools", help="show scanners selected by each profile"
    )
    list_tools.add_argument("--profile", choices=sorted(PROFILE_TOOLS))
    list_tools.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "list-tools":
        profiles = (
            {args.profile: PROFILE_TOOLS[args.profile]}
            if args.profile
            else PROFILE_TOOLS
        )
        if args.format == "json":
            print(json.dumps(profiles, indent=2, sort_keys=True))
        else:
            for profile, tools in profiles.items():
                print(f"{profile}: {', '.join(tools)}")
        return 0
    try:
        if args.command == "doctor":
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
        if args.command == "attest":
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
        if args.command == "verify":
            verification = verify_attestation(
                passport=args.passport,
                report=args.report,
                public_key=args.public_key,
                cosign_executable=args.cosign_executable,
                cosign_sha256=args.cosign_sha256,
                allow_unsigned=args.allow_unsigned,
            )
            print(json.dumps(verification, sort_keys=True))
            return 0
        if args.command == "verify-report":
            verification = verify_report(args.report)
            if args.format == "json":
                print(json.dumps(verification, indent=2, sort_keys=True))
            else:
                print(
                    "VERIFIED: "
                    f"{verification['file_count']} files; "
                    f"outcome {str(verification['outcome']).upper()}; "
                    f"scan {verification['scan_id']}"
                )
            return 0
        if args.command == "inspect":
            inspection = inspect_report(args.report, limit=args.limit)
            print(
                json.dumps(inspection, indent=2, sort_keys=True)
                if args.format == "json"
                else render_inspection(inspection)
            )
            return 0
        if args.network_isolated and args.diagnostic_without_isolation:
            raise ValueError(
                "--network-isolated and --diagnostic-without-isolation "
                "cannot be used together"
            )
        target = args.target.expanduser().resolve()
        output = args.output.expanduser().resolve()
        _prepare_output(
            target=target,
            output=output,
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
        )
        if args.github_summary:
            _append_github_summary(output / "summary.md")
        print(
            f"{result.outcome.value.upper()}: {len(result.findings)} finding(s); "
            f"report: {output}"
        )
        return exit_code(result.outcome)
    except (ConfigurationError, OSError, ValueError) as exc:
        print(f"pysec: error: {exc}", file=sys.stderr)
        return 3


def _prepare_output(*, target: Path, output: Path, overwrite: bool) -> None:
    anchor = Path(output.anchor)
    if output == anchor or output.parent == anchor:
        raise ValueError(
            "report output must not be a filesystem root or top-level directory"
        )
    if output == target:
        raise ValueError("report output cannot be the scan target")
    if target.is_relative_to(output):
        raise ValueError("report output cannot contain the scan target")
    if output.is_symlink():
        raise ValueError("report output cannot be a symbolic link")
    if output.exists():
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
        shutil.rmtree(output)
    output.parent.mkdir(parents=True, exist_ok=True)


def _is_suite_report(marker: Path) -> bool:
    if not marker.is_file():
        return False
    try:
        document = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (
        isinstance(document, dict)
        and document.get("schema_version") == "1.0"
        and "suite_version" in document
        and "scan_id" in document
    )


def _append_github_summary(summary: Path) -> None:
    destination = os.environ.get("GITHUB_STEP_SUMMARY")
    if not destination:
        raise ValueError(
            "--github-summary requires the GITHUB_STEP_SUMMARY environment variable"
        )
    with Path(destination).open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(summary.read_text(encoding="utf-8"))
        handle.write("\n")
