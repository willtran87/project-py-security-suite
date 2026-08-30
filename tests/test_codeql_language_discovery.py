from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


_ROOT = Path(__file__).parent.parent


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "discover_codeql_languages", _ROOT / "scripts/discover_codeql_languages.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_discovery_groups_extensions_and_upgrades_kotlin_to_autobuild(
    tmp_path: Path,
) -> None:
    module = _script()
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "main.java").write_text("class Main {}\n", encoding="utf-8")
    (tmp_path / "helper.kt").write_text("fun helper() = true\n", encoding="utf-8")
    (tmp_path / "view.tsx").write_text("export default 1\n", encoding="utf-8")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: CI\n", encoding="utf-8")
    ignored = tmp_path / "node_modules"
    ignored.mkdir()
    (ignored / "vendor.go").write_text("package vendor\n", encoding="utf-8")

    assert module.discover(tmp_path) == [
        {
            "language": "actions",
            "build_mode": "none",
            "runner": "ubuntu-latest",
            "files": 1,
        },
        {
            "language": "java-kotlin",
            "build_mode": "autobuild",
            "runner": "ubuntu-latest",
            "files": 2,
        },
        {
            "language": "javascript-typescript",
            "build_mode": "none",
            "runner": "ubuntu-latest",
            "files": 1,
        },
        {
            "language": "python",
            "build_mode": "none",
            "runner": "ubuntu-latest",
            "files": 1,
        },
    ]


def test_empty_github_matrix_has_a_safe_noop_row(tmp_path: Path) -> None:
    module = _script()
    matrix = module.github_matrix(tmp_path, exclude=frozenset())
    assert matrix["include"] == [
        {
            "language": "none",
            "build_mode": "none",
            "runner": "ubuntu-latest",
            "files": 0,
        }
    ]
