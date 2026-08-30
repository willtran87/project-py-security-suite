from __future__ import annotations

from pathlib import Path


_WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "release-assurance.yml"
)


def test_release_artifacts_are_normalized_before_attestation() -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")

    derive_epoch = workflow.index("Derive source epoch from checked-out commit")
    build = workflow.index("uv build --no-sources")
    normalize = workflow.index("uv run pysec normalize-sdist")
    attest = workflow.index("Attest exact builder subjects")

    assert derive_epoch < build < normalize < attest
    assert "--source-date-epoch ([int64]$env:SOURCE_DATE_EPOCH)" in workflow
    assert "--output $sdists[0].FullName" in workflow
    assert "--overwrite" in workflow[normalize:attest]


def test_release_comparison_uses_distinct_canonical_linux_builders() -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")

    assert "runner: ubuntu-24.04" in workflow
    assert "runner: ubuntu-22.04" in workflow
    assert "uv run pysec compare-builds" in workflow
    assert "python -I scripts/verify_release_independent.py" in workflow
    assert (
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release-assurance.yml"'
    ) in workflow


def test_release_verification_is_retained_with_the_release_artifacts() -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")

    assert ".artifacts/independent-release-verification.json" in workflow
    assert workflow.index("verify_release_independent.py") < workflow.index(
        "Install and exercise the exact wheel offline"
    )
