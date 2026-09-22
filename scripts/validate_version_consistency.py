"""Require one authoritative package version across build and runtime surfaces."""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path

from packaging.version import InvalidVersion, Version


_ROOT = Path(__file__).resolve().parents[1]


def authoritative_version() -> str:
    path = _ROOT / "src/py_security_suite/version.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    versions = [
        statement.value.value
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in statement.targets
        )
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    ]
    if len(versions) != 1:
        raise ValueError("version.py must define exactly one literal __version__")
    try:
        Version(versions[0])
    except InvalidVersion as error:
        raise ValueError("__version__ is not a valid packaging version") from error
    return versions[0]


def consistency_failures() -> list[str]:
    version = authoritative_version()
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    failures: list[str] = []
    if project["project"].get("dynamic") != ["version"]:
        failures.append("root project version must be dynamic")
    if project.get("tool", {}).get("setuptools", {}).get("dynamic", {}).get(
        "version"
    ) != {"attr": "py_security_suite.version.__version__"}:
        failures.append("setuptools must resolve version from version.__version__")
    prohibited = re.compile(
        rf"py-security-suite(?:-scanners)?(?::|==){re.escape(version)}"
    )
    for relative in (
        "scripts/build-scanner-image.ps1",
        "scripts/run-self-scan.ps1",
        "scripts/prepare-native-bundle.ps1",
    ):
        if prohibited.search((_ROOT / relative).read_text(encoding="utf-8")):
            failures.append(f"{relative} duplicates the authoritative version literal")
    return failures


def main() -> int:
    try:
        failures = consistency_failures()
    except (OSError, SyntaxError, KeyError, TypeError, ValueError) as error:
        print(f"version consistency failed: {error}", file=sys.stderr)
        return 1
    if failures:
        print(
            "version consistency failed:\n- " + "\n- ".join(failures), file=sys.stderr
        )
        return 1
    print(f"version consistency passed for {authoritative_version()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
