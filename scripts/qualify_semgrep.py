"""Qualify a fixed native scan profile; preserve all attempts, including failures."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from py_security_suite.adapters.semgrep import SEMGREP_JOBS
from py_security_suite.execution import run_command
from py_security_suite.path_safety import read_regular_file
from py_security_suite.strict_json import loads as strict_json_loads

if __package__:
    from .detection_stability import repeated_semgrep
else:
    from detection_stability import repeated_semgrep


def asset_identity(executable: Path, rules: Path) -> dict[str, str]:
    identities = {}
    for name, path in (("launcher", executable), ("rules", rules)):
        _, data = read_regular_file(path, name, maximum_bytes=32 * 1024**2)
        identities[name + "_sha256"] = hashlib.sha256(data).hexdigest()
    return identities


def qualify(
    source: Path, executable: Path, rules: Path, repetitions: int
) -> dict[str, Any]:
    assets = asset_identity(executable, rules)

    def execute() -> dict[str, Any]:
        if asset_identity(executable, rules) != assets:
            raise ValueError("native qualification assets changed")
        result = run_command(
            [
                str(executable),
                "scan",
                "--config",
                str(rules),
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--strict",
                "--no-git-ignore",
                f"--jobs={SEMGREP_JOBS}",
                str(source),
            ],
            cwd=source,
            timeout_seconds=600,
            max_output_bytes=32 * 1024**2,
        )
        if (
            result.exit_code
            or result.timed_out
            or result.stop_reason
            or result.output_limit_exceeded
        ):
            raise RuntimeError("native qualification did not finish")
        if asset_identity(executable, rules) != assets:
            raise ValueError("native qualification assets changed")
        return strict_json_loads(result.stdout)

    _, report = repeated_semgrep(execute, source, repetitions)
    return {
        "schema_version": "1.0",
        "profile": {"jobs": SEMGREP_JOBS, **assets},
        **report,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--semgrep", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3, choices=range(1, 6))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = qualify(
            args.source.absolute(),
            args.semgrep.absolute(),
            args.rules.absolute(),
            args.repetitions,
        )
    except (OSError, ValueError) as exc:
        report = {"passed": False, "error_category": type(exc).__name__}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
