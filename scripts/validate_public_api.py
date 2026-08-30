from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import re
import tomllib
from pathlib import Path
from typing import Any

from py_security_suite.cli import build_parser
from py_security_suite.report_inspection import BUNDLED_SCHEMA_RESOURCES
from py_security_suite.version import __version__


_ROOT = Path(__file__).resolve().parents[1]
_BASELINE = _ROOT / "security" / "api-surface-1.1.json"
_SCHEMA_ROOT = _ROOT / "src" / "py_security_suite" / "schemas"


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


def _actions(parser: argparse.ArgumentParser) -> dict[str, argparse.Action]:
    actions: dict[str, argparse.Action] = {}
    for action in parser._actions:
        names = list(getattr(action, "option_strings", [])) or [str(action.dest)]
        for name in names:
            actions[name] = action
    return actions


def _action_contract(action: argparse.Action) -> dict[str, Any]:
    converter = getattr(action, "type", None)
    choices = getattr(action, "choices", None)
    return {
        "action": type(action).__name__,
        "required": bool(getattr(action, "required", False)),
        "nargs": getattr(action, "nargs", None),
        "type": getattr(converter, "__name__", None),
        "choices": list(choices) if choices is not None else None,
    }


def _compatible_action(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    for name in ("action", "required", "nargs", "type"):
        if actual.get(name) != expected.get(name):
            return False
    expected_choices = expected.get("choices")
    actual_choices = actual.get("choices")
    if expected_choices is None:
        return actual_choices is None
    return isinstance(actual_choices, list) and set(expected_choices) <= set(
        actual_choices
    )


def _baseline_contract_failures(baseline: dict[str, Any]) -> list[str]:
    """Reject internally inconsistent baselines before comparing live behavior."""

    failures: list[str] = []
    commands = set(baseline.get("stable_cli_commands", []))
    options = baseline.get("stable_cli_options", {})
    contracts = baseline.get("stable_cli_option_contracts", {})
    schemas = set(baseline.get("stable_schema_resources", []))
    schema_digests = baseline.get("stable_schema_sha256", {})
    if not isinstance(options, dict) or set(options) != commands:
        failures.append("stable options must cover every stable command exactly")
    if not isinstance(contracts, dict) or set(contracts) != commands:
        failures.append("option contracts must cover every stable command exactly")
    if isinstance(options, dict) and isinstance(contracts, dict):
        for command, values in contracts.items():
            if not isinstance(values, dict) or set(values) != set(
                options.get(command, [])
            ):
                failures.append(
                    f"{command} option contracts must cover stable options exactly"
                )
    if not isinstance(schema_digests, dict) or set(schema_digests) != schemas:
        failures.append("every stable schema must have exactly one immutable digest")
    entry_points = baseline.get("stable_console_scripts")
    callables = baseline.get("stable_python_callables")
    exports = baseline.get("stable_python_exports")
    if not isinstance(entry_points, dict) or not entry_points:
        failures.append("stable console-script targets are missing")
    if (
        not isinstance(callables, dict)
        or not isinstance(entry_points, dict)
        or set(entry_points.values()) != set(callables)
    ):
        failures.append("stable Python callables must cover console-script targets")
    if not isinstance(exports, dict) or not exports:
        failures.append("stable package exports are missing")
    return failures


def _resolve_callable(target: str) -> Any:
    module_name, separator, attribute = target.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError(f"invalid Python callable target: {target}")
    return getattr(importlib.import_module(module_name), attribute)


def main() -> int:
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8"))
    if (
        baseline.get("schema_version") != "1.1"
        or baseline.get("compatibility_policy") != "additive-with-versioned-replacement"
    ):
        raise SystemExit("public API baseline contract is invalid")
    failures = _baseline_contract_failures(baseline)
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
    for command, contracts in baseline["stable_cli_option_contracts"].items():
        parser = commands.get(command)
        if parser is None:
            continue
        actions = _actions(parser)
        for name, expected in contracts.items():
            action = actions.get(name)
            if action is None:
                continue
            actual = _action_contract(action)
            if not _compatible_action(actual, expected):
                failures.append(
                    f"{command} changed stable option contract for {name}: "
                    f"expected {expected}, observed {actual}"
                )
    missing_schemas = sorted(
        set(baseline["stable_schema_resources"]) - set(BUNDLED_SCHEMA_RESOURCES)
    )
    if missing_schemas:
        failures.append("removed stable schemas: " + ", ".join(missing_schemas))
    for name, expected_digest in baseline["stable_schema_sha256"].items():
        resource = BUNDLED_SCHEMA_RESOURCES.get(name)
        if resource is None:
            continue
        actual_digest = hashlib.sha256(
            (_SCHEMA_ROOT / resource).read_bytes()
        ).hexdigest()
        if actual_digest != expected_digest:
            failures.append(
                f"stable schema {name} changed in place; publish a new version"
            )
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = project.get("project", {}).get("scripts", {})
    for name, target in baseline["stable_console_scripts"].items():
        if not isinstance(scripts, dict) or scripts.get(name) != target:
            failures.append(f"stable console script {name} no longer targets {target}")
    for target, expected_signature in baseline["stable_python_callables"].items():
        try:
            value = _resolve_callable(target)
        except (AttributeError, ImportError, ValueError) as exc:
            failures.append(f"stable Python callable {target} is unavailable: {exc}")
            continue
        actual_signature = str(inspect.signature(value))
        if actual_signature != expected_signature:
            failures.append(
                f"stable Python callable {target} changed signature: "
                f"expected {expected_signature}, observed {actual_signature}"
            )
    for module_name, expected_exports in baseline["stable_python_exports"].items():
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            failures.append(f"stable Python module {module_name} is unavailable: {exc}")
            continue
        actual_exports = set(getattr(module, "__all__", ()))
        missing = sorted(set(expected_exports) - actual_exports)
        if missing:
            failures.append(
                f"stable Python module {module_name} removed exports: {', '.join(missing)}"
            )
        for name, expected_kind in expected_exports.items():
            if (
                name in actual_exports
                and type(getattr(module, name)).__name__ != expected_kind
            ):
                failures.append(
                    f"stable Python export {module_name}.{name} changed kind"
                )
    if failures:
        raise SystemExit("public API compatibility failed:\n" + "\n".join(failures))
    print(
        "public API compatibility passed for "
        f"{len(baseline['stable_cli_commands'])} commands, "
        f"{sum(len(items) for items in baseline['stable_cli_options'].values())} options, "
        f"{len(baseline['stable_schema_resources'])} schemas, and "
        f"{len(baseline['stable_python_callables'])} Python callables"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
