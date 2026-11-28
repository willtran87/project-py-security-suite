"""Reject hand-maintained documentation metrics that drift from enforced code.

Counts quoted in prose are checked against the registries that define them.
The README additionally carries a generated ``pysec-readme-metrics`` marker;
run ``python -m scripts.validate_documentation_metrics --write`` to regenerate
that marker and every governed count phrase after a registry change.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from py_security_suite.assurance_catalog import export_assurance_catalog
from py_security_suite.config import PROFILE_TOOLS, SUPPORTED_TOOLS
from py_security_suite.report_inspection import BUNDLED_SCHEMA_RESOURCES

_ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(_ROOT))

from scripts.validate_architecture_limits import (  # noqa: E402
    _FILE_LINE_LIMITS,
    _FUNCTION_DECISION_LIMITS,
    _FUNCTION_LINE_LIMITS,
)


README_MARKER_KEYS = (
    "adapters",
    "standards",
    "watchlist",
    "profiles",
    "benchmarks",
    "adapter_specs",
    "execution_contracts",
)
_README_MARKER = re.compile(
    r"<!-- pysec-readme-metrics "
    + " ".join(rf"{key}=(\d+)" for key in README_MARKER_KEYS)
    + r" -->"
)

# (document, metric key, phrase pattern with exactly one numeric group).
# Every occurrence must equal the registry value and each phrase must appear.
_COUNT_PHRASES: tuple[tuple[str, str, str], ...] = (
    ("README.md", "adapters", r"\b(\d+) governed adapters\b"),
    ("README.md", "standards", r"\b(\d+) versioned references\b"),
    ("README.md", "watchlist", r"\b(\d+) quarantined watch items\b"),
    ("README.md", "profiles", r"\b(\d+) selectable profiles\b"),
    ("README.md", "benchmarks", r"\b(\d+) governed benchmark families\b"),
    ("README.md", "benchmarks", r"\b(\d+) pinned benchmark families\b"),
    ("README.md", "adapter_specs", r"\b(\d+) maintained adapters\b"),
    (
        "README.md",
        "execution_contracts",
        r"\b(\d+) maintained benchmark adapters\b",
    ),
    ("docs/design.md", "adapters", r"\b(\d+) governed adapters\b"),
    ("docs/design.md", "standards", r"\b(\d+) versioned standards references\b"),
    ("docs/design.md", "profiles", r"\b(\d+) assurance packs\b"),
    ("docs/design.md", "benchmarks", r"\b(\d+) governed benchmark families\b"),
    ("docs/design.md", "adapter_specs", r"\b(\d+) maintained adapters\b"),
    ("docs/index.md", "adapters", r"\b(\d+) governed adapters\b"),
    ("docs/index.md", "suite_profiles", r"\b(\d+) profiles\b"),
    ("docs/index.md", "standards", r"\b(\d+) standards references\b"),
    ("docs/index.md", "watchlist", r"\b(\d+) quarantined watch items\b"),
    ("docs/index.md", "profiles", r"\b(\d+) assurance packs\b"),
    ("docs/index.md", "benchmarks", r"\b(\d+) benchmark families\b"),
    ("docs/index.md", "adapter_specs", r"\b(\d+) maintained adapters\b"),
    (
        "docs/industry-standards-benchmarks.md",
        "standards",
        r"\b(\d+) version-explicit references\b",
    ),
    (
        "docs/industry-standards-benchmarks.md",
        "watchlist",
        r"\b(\d+) non-normative watch items\b",
    ),
    ("docs/industry-standards-benchmarks.md", "profiles", r"\b(\d+) built-in packs\b"),
    (
        "docs/industry-standards-benchmarks.md",
        "adapter_specs",
        r"\b(\d+)-adapter catalog\b",
    ),
)


def expected_counts() -> dict[str, int]:
    counts = export_assurance_catalog()["counts"]
    return {
        "adapters": len(SUPPORTED_TOOLS),
        "suite_profiles": len(PROFILE_TOOLS),
        "standards": int(counts["standards"]),
        "watchlist": int(counts["standards_watchlist"]),
        "profiles": int(counts["profiles"]),
        "benchmarks": int(counts["benchmarks"]),
        "adapter_specs": int(counts["adapter_specs"]),
        "execution_contracts": int(counts["execution_contracts"]),
    }


def readme_marker(expected: Mapping[str, int]) -> str:
    values = " ".join(f"{key}={expected[key]}" for key in README_MARKER_KEYS)
    return f"<!-- pysec-readme-metrics {values} -->"


def count_phrase_failures(
    documents: Mapping[str, str], expected: Mapping[str, int]
) -> list[str]:
    failures: list[str] = []
    for document, key, pattern in _COUNT_PHRASES:
        found = [int(value) for value in re.findall(pattern, documents[document])]
        if not found:
            failures.append(f"{document} no longer states {pattern!r}")
        elif set(found) != {expected[key]}:
            failures.append(
                f"{document} {pattern!r} states {sorted(set(found))}, "
                f"expected {expected[key]} ({key})"
            )
    readme = documents["README.md"]
    marker = _README_MARKER.search(readme)
    if marker is None:
        failures.append("README.md is missing the pysec-readme-metrics marker")
    elif marker.group(0) != readme_marker(expected):
        failures.append(
            "README.md pysec-readme-metrics marker is stale; run "
            "`python -m scripts.validate_documentation_metrics --write`"
        )
    return failures


def _count_replacer(value: str) -> Callable[[re.Match[str]], str]:
    def replace(match: re.Match[str]) -> str:
        whole = match.group(0)
        offset = match.start(0)
        return whole[: match.start(1) - offset] + value + whole[match.end(1) - offset :]

    return replace


def rewrite_count_phrases(
    documents: Mapping[str, str], expected: Mapping[str, int]
) -> dict[str, str]:
    updated = dict(documents)
    for document, key, pattern in _COUNT_PHRASES:
        updated[document] = re.sub(
            pattern, _count_replacer(str(expected[key])), updated[document]
        )
    readme = updated["README.md"]
    marker = readme_marker(expected)
    if _README_MARKER.search(readme):
        updated["README.md"] = _README_MARKER.sub(marker, readme)
    else:
        updated["README.md"] = readme.rstrip("\n") + "\n\n" + marker + "\n"
    return updated


def _governed_documents() -> dict[str, str]:
    return {
        document: (_ROOT / document).read_text(encoding="utf-8")
        for document in sorted({entry[0] for entry in _COUNT_PHRASES})
    }


def documentation_metric_failures() -> list[str]:
    design = (_ROOT / "docs/design.md").read_text(encoding="utf-8")
    index = (_ROOT / "docs/index.md").read_text(encoding="utf-8")
    architecture = re.search(
        r"pysec-architecture-metrics files=(\d+) function_lengths=(\d+) "
        r"decision_budgets=(\d+)",
        design,
    )
    failures: list[str] = []
    expected_architecture = (
        len(_FILE_LINE_LIMITS),
        len(_FUNCTION_LINE_LIMITS),
        len(_FUNCTION_DECISION_LIMITS),
    )
    if (
        architecture is None
        or tuple(map(int, architecture.groups())) != expected_architecture
    ):
        failures.append(
            "design architecture marker does not match enforced concentration budgets"
        )

    schemas = len(list((_ROOT / "src/py_security_suite/schemas").glob("*.json")))
    baseline = json.loads(
        (_ROOT / "security/api-surface-1.1.json").read_text(encoding="utf-8")
    )
    stable = baseline.get("stable_schema_resources", [])
    if not isinstance(stable, list):
        failures.append("public API stable_schema_resources must be an array")
        stable_count = -1
    else:
        stable_count = len(stable)
    schema_marker = re.search(
        r"pysec-schema-metrics files=(\d+) runtime_exports=(\d+) stable_contracts=(\d+)",
        index,
    )
    expected_schema = (schemas, len(BUNDLED_SCHEMA_RESOURCES), stable_count)
    if (
        schema_marker is None
        or tuple(map(int, schema_marker.groups())) != expected_schema
    ):
        failures.append(
            "index schema marker does not match runtime and compatibility data"
        )
    for stale in ("1,559 passed", "204 bundled JSON Schemas"):
        if stale in index:
            failures.append(f"index retains stale metric {stale!r}")
    failures.extend(count_phrase_failures(_governed_documents(), expected_counts()))
    return failures


def write_count_phrases() -> None:
    documents = _governed_documents()
    for document, text in rewrite_count_phrases(documents, expected_counts()).items():
        if text != documents[document]:
            (_ROOT / document).write_text(text, encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="regenerate the README marker and governed count phrases",
    )
    arguments = parser.parse_args(argv)
    try:
        if arguments.write:
            write_count_phrases()
        failures = documentation_metric_failures()
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"documentation metrics failed: {error}", file=sys.stderr)
        return 1
    if failures:
        print(
            "documentation metrics failed:\n- " + "\n- ".join(failures), file=sys.stderr
        )
        return 1
    print("documentation metrics match enforced repository contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
