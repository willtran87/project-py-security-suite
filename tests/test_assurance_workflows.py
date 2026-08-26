from __future__ import annotations

from pathlib import Path


_ROOT = Path(__file__).parent.parent


def _workflow(name: str) -> str:
    return (_ROOT / ".github/workflows" / name).read_text(encoding="utf-8")


def test_ci_enforces_coverage_and_cross_platform_python_314() -> None:
    workflow = _workflow("ci.yml")

    assert 'python-version: "3.14"' in workflow
    assert "os: windows-latest" in workflow
    assert "os: macos-latest" in workflow
    assert "coverage report --fail-under=80" in workflow
    assert "--fail-under=90" in workflow
    assert "- test-assurance" in workflow


def test_cross_platform_tests_use_a_canonical_temporary_root() -> None:
    workflow = _workflow("ci.yml")

    assert "Prepare canonical test temporary directory" in workflow
    assert "PYSEC_TEST_TEMP: ${{ runner.temp }}/pysec-tests" in workflow
    assert "TMP: ${{ runner.temp }}/pysec-tests" in workflow
    assert "TEMP: ${{ runner.temp }}/pysec-tests" in workflow
    assert "TMPDIR: ${{ runner.temp }}/pysec-tests" in workflow


def test_deep_assurance_executes_self_scan_and_mutation_testing() -> None:
    workflow = _workflow("deep-assurance.yml")

    assert "./scripts/run-self-scan.ps1" in workflow
    assert "uv run --frozen mutmut run" in workflow
    assert "--suspicious-policy=failure --untested-policy=failure" in workflow


def test_external_security_workflow_fails_closed_on_authority_gaps() -> None:
    workflow = _workflow("external-security-assurance.yml")

    assert "environment: production-security-isolation" in workflow
    assert "enterprise-verify-pysec-isolation.exe" in workflow
    assert "-ScanProfile production -NetworkIsolated" in workflow
    assert 'schema_version -ne "2.0"' in workflow
    assert "true_positive -lt 10" in workflow
    assert "true_negative -lt 10" in workflow
    assert "environment: authorized-dynamic-security" in workflow
    assert "--phases examples,coverage,fuzzing,stateful" in workflow
    assert "--require-tools nuclei,zap,restler,oast,datadog-iast,mobsf" in workflow


def test_release_publish_requires_protected_identity_and_public_roundtrip() -> None:
    external = _workflow("external-release-verification.yml")
    publish = _workflow("publish-pypi.yml")

    assert "environment: independent-release-verification" in external
    assert "pysec-independent-builder" in external
    assert "sha256sum" in external
    assert "environment: pypi-production" in publish
    assert "INDEPENDENT_RUN_ID" in publish
    assert ".github/workflows/external-release-verification.yml" in publish
    assert (
        "pypa/gh-action-pypi-publish@a892a5a61159132606e93a2fa6f4358831b04d26"
        in publish
    )
    assert "gh attestation verify" in publish
    assert "post-publish-roundtrip" in publish
    assert "publish-roundtrip/bin/pysec --help" in publish
