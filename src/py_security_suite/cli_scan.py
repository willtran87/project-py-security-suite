"""Scan command options and bounded progress rendering."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from collections.abc import Callable

from .config import PROFILE_TOOLS
from .scan_control import ScanProgress


def progress_sink(mode: str) -> Callable[[ScanProgress], None] | None:
    if mode == "none":
        return None

    def emit(event: ScanProgress) -> None:
        text = (
            json.dumps(asdict(event), sort_keys=True)
            if mode == "json"
            else f"{event.elapsed_seconds:.1f}s {event.stage} {event.state}"
            + (f" ({event.tool})" if event.tool else "")
        )
        print(text, file=sys.stderr, flush=True)

    return emit


def add_scan_arguments(scan: argparse.ArgumentParser) -> None:
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
    scan.add_argument(
        "--progress",
        choices=("none", "text", "json"),
        default="none",
        help="stage progress on stderr; JSON is newline-delimited",
    )
