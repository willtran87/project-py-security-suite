from __future__ import annotations

from pathlib import Path
from typing import Any


def add_release_check_command(subparsers: Any) -> None:
    """Register the release evidence and policy aggregation command."""

    release_check = subparsers.add_parser(
        "release-check",
        help=(
            "aggregate verified report, trust, isolation, effectiveness, "
            "provider, and passport evidence"
        ),
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
    release_check.add_argument(
        "--provider-conformance",
        type=Path,
        action="append",
        default=[],
        metavar="RECEIPT",
        help="portable signing-provider conformance receipt (repeatable)",
    )
    release_check.add_argument(
        "--provider-conformance-sha256",
        action="append",
        default=[],
        metavar="SHA256",
        help="approved digest paired with --provider-conformance (repeatable)",
    )
    release_check.add_argument(
        "--required-provider-id",
        action="append",
        default=[],
        metavar="ID",
        help="provider identity required by the release decision (repeatable)",
    )
    release_check.add_argument(
        "--maximum-provider-conformance-age-hours",
        type=int,
        default=168,
    )
    release_check.add_argument("--require-provider-conformance", action="store_true")
    release_check.add_argument("--format", choices=("text", "json"), default="text")
    release_check.add_argument("--output", type=Path, metavar="FILE")
    release_check.add_argument("--overwrite", action="store_true")
