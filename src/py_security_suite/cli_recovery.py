"""Recovery command keeps completed scanner work usable after renderer failures."""

from __future__ import annotations

import argparse
from pathlib import Path

from .reports import recover_reports


def add_recovery_commands(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "recover-report", help="render saved scan inputs into a new verified report"
    )
    parser.add_argument(
        "checkpoint",
        type=Path,
        help=".REPORT.recovery-* directory from the failed scan",
    )
    parser.add_argument(
        "--output", required=True, type=Path, help="new report directory"
    )

    decrypt = subparsers.add_parser(
        "decrypt-report", help="decrypt and verify an X25519 report archive"
    )
    decrypt.add_argument("encrypted", type=Path)
    decrypt.add_argument("--output", type=Path, required=True)
    decrypt.add_argument("--recipient-private-key", type=Path, required=True)
    decrypt.add_argument("--recipient-private-key-sha256", required=True)


def recovery_command(args: argparse.Namespace) -> int:
    recover_reports(args.checkpoint, args.output)
    print(f"Recovered report: {args.output}")
    return 0
