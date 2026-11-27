from __future__ import annotations

from scripts.validate_documentation_metrics import (
    README_MARKER_KEYS,
    count_phrase_failures,
    documentation_metric_failures,
    expected_counts,
    readme_marker,
    rewrite_count_phrases,
)


def test_documented_repository_metrics_match_enforced_sources() -> None:
    assert documentation_metric_failures() == []


def _documents(readme: str) -> dict[str, str]:
    expected = expected_counts()
    return {
        "README.md": readme,
        "docs/design.md": (
            f"{expected['adapters']} governed adapters, "
            f"{expected['standards']} versioned standards references, "
            f"{expected['profiles']} assurance packs, "
            f"{expected['benchmarks']} governed benchmark families, "
            f"{expected['adapter_specs']} maintained adapters"
        ),
        "docs/index.md": (
            f"{expected['adapters']} governed adapters and "
            f"{expected['suite_profiles']} profiles, "
            f"{expected['standards']} standards references, "
            f"{expected['watchlist']} quarantined watch items, "
            f"{expected['profiles']} assurance packs, "
            f"{expected['benchmarks']} benchmark families, "
            f"{expected['adapter_specs']} maintained adapters"
        ),
        "docs/industry-standards-benchmarks.md": (
            f"{expected['standards']} version-explicit references, "
            f"{expected['watchlist']} non-normative watch items, "
            f"{expected['profiles']} built-in packs, "
            f"{expected['adapter_specs']}-adapter catalog"
        ),
    }


def test_readme_counts_and_marker_are_regenerated_from_registries() -> None:
    expected = expected_counts()
    stale_readme = (
        "1 governed adapters; 2 versioned references; 3 quarantined watch items; "
        "4 selectable profiles; 5 governed benchmark families; "
        "6 pinned benchmark families; 7 maintained adapters; "
        "8 maintained benchmark adapters\n"
    )
    documents = _documents(stale_readme)

    failures = count_phrase_failures(documents, expected)
    assert any("governed adapters" in failure for failure in failures)
    assert any("marker" in failure for failure in failures)

    regenerated = rewrite_count_phrases(documents, expected)
    assert count_phrase_failures(regenerated, expected) == []
    assert readme_marker(expected) in regenerated["README.md"]
    assert f"{expected['adapters']} governed adapters" in regenerated["README.md"]
    for key in README_MARKER_KEYS:
        assert f"{key}={expected[key]}" in regenerated["README.md"]


def test_missing_governed_phrase_is_reported() -> None:
    expected = expected_counts()
    documents = rewrite_count_phrases(_documents(""), expected)
    documents["docs/index.md"] = documents["docs/index.md"].replace(
        "benchmark families", "benchmark suites"
    )

    assert any(
        "docs/index.md no longer states" in failure
        for failure in count_phrase_failures(documents, expected)
    )
