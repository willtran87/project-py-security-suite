from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from . import __version__
from .config import ConfigurationError, PROFILE_TOOLS, load_config
from .orchestrator import scan_project
from .policy import exit_code


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

    subparsers.add_parser(
        "list-tools", help="show scanners selected by each profile"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "list-tools":
        for profile, tools in PROFILE_TOOLS.items():
            print(f"{profile}: {', '.join(tools)}")
        return 0
    try:
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
        raise ValueError("report output must not be a filesystem root or top-level directory")
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
