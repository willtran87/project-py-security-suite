from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


_EXTENSIONS: dict[str, tuple[str, str, str]] = {
    ".c": ("c-cpp", "none", "ubuntu-latest"),
    ".cc": ("c-cpp", "none", "ubuntu-latest"),
    ".cpp": ("c-cpp", "none", "ubuntu-latest"),
    ".cxx": ("c-cpp", "none", "ubuntu-latest"),
    ".h": ("c-cpp", "none", "ubuntu-latest"),
    ".hpp": ("c-cpp", "none", "ubuntu-latest"),
    ".cs": ("csharp", "none", "ubuntu-latest"),
    ".go": ("go", "autobuild", "ubuntu-latest"),
    ".java": ("java-kotlin", "none", "ubuntu-latest"),
    ".js": ("javascript-typescript", "none", "ubuntu-latest"),
    ".jsx": ("javascript-typescript", "none", "ubuntu-latest"),
    ".kt": ("java-kotlin", "autobuild", "ubuntu-latest"),
    ".kts": ("java-kotlin", "autobuild", "ubuntu-latest"),
    ".py": ("python", "none", "ubuntu-latest"),
    ".rb": ("ruby", "none", "ubuntu-latest"),
    ".rs": ("rust", "none", "ubuntu-latest"),
    ".swift": ("swift", "autobuild", "macos-latest"),
    ".ts": ("javascript-typescript", "none", "ubuntu-latest"),
    ".tsx": ("javascript-typescript", "none", "ubuntu-latest"),
}
_IGNORED = frozenset(
    {
        ".git",
        ".artifacts",
        ".mypy_cache",
        ".pysec-tools",
        ".pytest_cache",
        ".tox",
        ".venv",
        "build",
        "dist",
        "htmlcov",
        "mutants",
        "node_modules",
        "site",
    }
)


def discover(root: Path) -> list[dict[str, Any]]:
    """Return one deterministic CodeQL configuration per discovered language."""
    counts: Counter[str] = Counter()
    configurations: dict[str, tuple[str, str]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in _IGNORED for part in path.parts):
            continue
        relative_parts = path.relative_to(root).parts
        configuration = (
            ("actions", "none", "ubuntu-latest")
            if len(relative_parts) >= 3
            and relative_parts[:2] == (".github", "workflows")
            and path.suffix.casefold() in {".yaml", ".yml"}
            else _EXTENSIONS.get(path.suffix.casefold())
        )
        if configuration is None:
            continue
        language, build_mode, runner = configuration
        counts[language] += 1
        existing = configurations.get(language)
        if existing and existing[0] != build_mode:
            # Kotlin requires a build and upgrades a Java-only no-build lane.
            build_mode = "autobuild"
        configurations[language] = (build_mode, runner)
    return [
        {
            "language": language,
            "build_mode": configurations[language][0],
            "runner": configurations[language][1],
            "files": counts[language],
        }
        for language in sorted(configurations)
    ]


def github_matrix(root: Path, *, exclude: frozenset[str]) -> dict[str, Any]:
    rows = [item for item in discover(root) if item["language"] not in exclude]
    if not rows:
        rows = [
            {
                "language": "none",
                "build_mode": "none",
                "runner": "ubuntu-latest",
                "files": 0,
            }
        ]
    return {"include": rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--github-matrix", action="store_true")
    parser.add_argument("--exclude", action="append", default=[])
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    payload: object = (
        github_matrix(root, exclude=frozenset(arguments.exclude))
        if arguments.github_matrix
        else discover(root)
    )
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
