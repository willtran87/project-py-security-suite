from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from py_security_suite import __version__
from py_security_suite.cli import build_parser
from py_security_suite.report_inspection import BUNDLED_SCHEMA_RESOURCES


_ROOT = Path(__file__).resolve().parents[1]
_BASELINE = _ROOT / "security" / "api-surface-1.0.json"


def _version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", value)
    if match is None:
        raise ValueError(f"invalid semantic version: {value}")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def _subcommands(parser: argparse.ArgumentParser) -> dict[str, Any]:
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict) and choices:
            return choices
    raise ValueError("CLI parser does not expose subcommands")


def _surface(parser: argparse.ArgumentParser) -> set[str]:
    values: set[str] = set()
    for action in parser._actions:
        options = getattr(action, "option_strings", [])
        long_options = [item for item in options if item.startswith("--")]
        if long_options:
            values.update(long_options)
        elif getattr(action, "dest", "") not in {"help", argparse.SUPPRESS}:
            values.add(str(action.dest))
    return values


def main() -> int:
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8"))
    if (
        baseline.get("schema_version") != "1.0"
        or baseline.get("compatibility_policy") != "additive-with-versioned-replacement"
    ):
        raise SystemExit("public API baseline contract is invalid")
    failures: list[str] = []
    if _version(__version__) < _version(str(baseline["minimum_package_version"])):
        failures.append("package version regressed below the public baseline")
    commands = _subcommands(build_parser())
    missing_commands = sorted(set(baseline["stable_cli_commands"]) - set(commands))
    if missing_commands:
        failures.append("removed stable CLI commands: " + ", ".join(missing_commands))
    for command, required in baseline["stable_cli_options"].items():
        parser = commands.get(command)
        if parser is None:
            continue
        missing = sorted(set(required) - _surface(parser))
        if missing:
            failures.append(f"{command} removed stable options: {', '.join(missing)}")
    missing_schemas = sorted(
        set(baseline["stable_schema_resources"]) - set(BUNDLED_SCHEMA_RESOURCES)
    )
    if missing_schemas:
        failures.append("removed stable schemas: " + ", ".join(missing_schemas))
    if failures:
        raise SystemExit("public API compatibility failed:\n" + "\n".join(failures))
    print(
        "public API compatibility passed for "
        f"{len(baseline['stable_cli_commands'])} commands, "
        f"{sum(len(items) for items in baseline['stable_cli_options'].values())} options, "
        f"and {len(baseline['stable_schema_resources'])} schemas"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
