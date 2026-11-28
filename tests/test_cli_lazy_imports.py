from __future__ import annotations

import ast
import json
import subprocess
import sys
from importlib import import_module
from pathlib import Path

import py_security_suite.cli as cli


_CLI_SOURCE = Path(cli.__file__)
_HEAVY_MODULES = (
    "py_security_suite.config",
    "py_security_suite.orchestrator",
    "py_security_suite.reports",
    "py_security_suite.industry_assurance",
    "requests",
    "rfc3161ng",
)


def _type_checking_imports() -> dict[str, tuple[str, str]]:
    tree = ast.parse(_CLI_SOURCE.read_text(encoding="utf-8"))
    block = next(
        node
        for node in tree.body
        if isinstance(node, ast.If) and ast.unparse(node.test) == "TYPE_CHECKING"
    )
    imports: dict[str, tuple[str, str]] = {}
    for node in block.body:
        assert isinstance(node, ast.ImportFrom)
        module = "." * node.level + (node.module or "")
        for alias in node.names:
            imports[alias.asname or alias.name] = (module, alias.name)
    return imports


def test_lazy_import_table_matches_type_checking_imports() -> None:
    assert cli._LAZY_IMPORTS == _type_checking_imports()


def test_functions_using_lazy_names_bind_them_first() -> None:
    tree = ast.parse(_CLI_SOURCE.read_text(encoding="utf-8"))
    lazy = set(cli._LAZY_IMPORTS)
    missing = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name in {
            "__getattr__",
            "_load_command_dependencies",
        }:
            continue
        used = {
            name.id
            for name in ast.walk(node)
            if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Load)
        }
        if not used & lazy:
            continue
        calls = [
            statement
            for statement in node.body[:3]
            if isinstance(statement, ast.Expr)
            and ast.unparse(statement) == "_load_command_dependencies()"
        ]
        if not calls:
            missing.append(node.name)
    assert missing == []


def test_every_lazy_name_resolves_to_its_declared_object() -> None:
    for name, (module, attribute) in cli._LAZY_IMPORTS.items():
        expected = getattr(import_module(module, "py_security_suite"), attribute)
        assert getattr(cli, name) is expected, name


def test_unknown_attribute_is_still_an_attribute_error() -> None:
    try:
        cli.__getattr__("definitely_not_a_cli_name")
    except AttributeError:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("expected AttributeError")


def test_help_does_not_import_command_implementations() -> None:
    probe = (
        "import contextlib, io, json, sys\n"
        "from py_security_suite.cli import main\n"
        "with contextlib.redirect_stdout(io.StringIO()):\n"
        "    try:\n"
        "        main(['--help'])\n"
        "    except SystemExit:\n"
        "        pass\n"
        f"print(json.dumps([m for m in {list(_HEAVY_MODULES)!r} if m in sys.modules]))\n"
    )
    result = subprocess.run(  # noqa: S603 - fixed interpreter and probe
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )

    assert json.loads(result.stdout) == []
