from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import tomllib
from pathlib import Path
from typing import Any

from py_security_suite.cli import build_parser
from py_security_suite.report_inspection import BUNDLED_SCHEMA_RESOURCES
from py_security_suite.version import __version__

from scripts.validate_public_api import (
    _action_contract,
    _actions,
    _subcommands,
    _surface,
)


_ROOT = Path(__file__).resolve().parents[1]
_OUTPUT = _ROOT / "security" / "api-surface-1.1.json"
_SCHEMA_ROOT = _ROOT / "src" / "py_security_suite" / "schemas"


def build_baseline() -> dict[str, Any]:
    """Build the complete additive-compatibility contract from the live parser."""

    commands = _subcommands(build_parser())
    command_names = sorted(commands)
    options: dict[str, list[str]] = {}
    contracts: dict[str, dict[str, Any]] = {}
    for name in command_names:
        parser = commands[name]
        option_names = sorted(_surface(parser))
        actions = _actions(parser)
        options[name] = option_names
        contracts[name] = {
            option: _action_contract(actions[option]) for option in option_names
        }
    schemas = sorted(BUNDLED_SCHEMA_RESOURCES)
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    console_scripts = dict(project["project"]["scripts"])
    python_callables = {
        target: str(inspect.signature(_resolve_callable(target)))
        for target in sorted(set(console_scripts.values()))
    }
    package = importlib.import_module("py_security_suite")
    return {
        "schema_version": "1.1",
        "minimum_package_version": __version__,
        "compatibility_policy": "additive-with-versioned-replacement",
        "stable_cli_commands": command_names,
        "stable_cli_options": options,
        "stable_cli_option_contracts": contracts,
        "stable_schema_resources": schemas,
        "stable_schema_sha256": {
            name: hashlib.sha256(
                (_SCHEMA_ROOT / BUNDLED_SCHEMA_RESOURCES[name]).read_bytes()
            ).hexdigest()
            for name in schemas
        },
        "stable_console_scripts": console_scripts,
        "stable_python_callables": python_callables,
        "stable_python_exports": {
            "py_security_suite": {
                name: type(getattr(package, name)).__name__
                for name in sorted(package.__all__)
            }
        },
    }


def _resolve_callable(target: str) -> Any:
    module_name, _, attribute = target.partition(":")
    return getattr(importlib.import_module(module_name), attribute)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a candidate exhaustive public API compatibility baseline."
    )
    parser.add_argument("--output", type=Path, default=_OUTPUT)
    parser.add_argument(
        "--approve-replacement",
        action="store_true",
        help="required to replace the repository's immutable compatibility baseline",
    )
    arguments = parser.parse_args()
    output = arguments.output.resolve()
    if output == _OUTPUT.resolve() and not arguments.approve_replacement:
        raise SystemExit(
            "refusing to replace the compatibility baseline without "
            "--approve-replacement"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(build_baseline(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote public API candidate: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
