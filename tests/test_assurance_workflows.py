from __future__ import annotations

from pathlib import Path
import re


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


def test_required_pr_workflows_do_not_duplicate_branch_push_runs() -> None:
    for name in ("ci.yml", "codeql.yml"):
        workflow = _workflow(name)

        assert re.search(
            r"(?m)^  push:\n    branches: \[main\]\n  pull_request:$",
            workflow,
        )


def test_actionlint_declares_every_protected_runner_label() -> None:
    config = (_ROOT / ".github/actionlint.yaml").read_text(encoding="utf-8")

    for label in (
        "pysec-dynamic",
        "pysec-independent-builder",
        "pysec-isolated",
        "pysec-signing",
        "release-evidence",
    ):
        assert f"    - {label}\n" in config

    assert "ignore:" not in config


def test_ci_enforces_digest_verified_actionlint() -> None:
    workflow = _workflow("ci.yml")
    native_bundle = (_ROOT / "scripts/prepare-native-bundle.ps1").read_text(
        encoding="utf-8"
    )

    assert 'ACTIONLINT_VERSION: "1.7.12"' in workflow
    actionlint_digest = "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"  # pragma: allowlist secret
    assert f"ACTIONLINT_LINUX_AMD64_SHA256: {actionlint_digest}" in workflow
    assert "sha256sum --check --strict" in workflow
    assert "actionlint -no-color" in workflow
    assert '[string]$ActionlintVersion = "1.7.12"' in native_bundle


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
    assert "uv run --frozen python scripts/run_mutation_assurance.py" in workflow
    assert "MUTATION_SHARD: ${{ matrix.shard }}" in workflow
    assert '--shard-index "$MUTATION_SHARD" --shard-count 6' in workflow
    assert "scripts/validate_mutation_assurance.py" in workflow
    assert 'uv sync --locked --all-groups --python "3.13"' in workflow
    assert "mutmut export-cicd-stats" in workflow
    assert "--minimum-score 0" in workflow
    assert "--minimum-score 70" in workflow


def test_fuzz_workflow_extracts_missing_coverage_without_shell_short_circuit() -> None:
    workflow = _workflow("fuzz.yml")

    assert '--seed-target="$FUZZ_TARGET"' in workflow
    assert "match($0, /cov: [0-9]+/)" in workflow
    assert 'if [[ -z "$coverage"' in workflow


def test_external_security_workflow_fails_closed_on_authority_gaps() -> None:
    workflow = _workflow("external-security-assurance.yml")

    assert "environment: production-security-isolation" in workflow
    assert "enterprise-verify-pysec-isolation.exe" in workflow
    assert "-ScanProfile production -NetworkIsolated" in workflow
    assert 'schema_version -ne "2.0"' in workflow
    assert "$evaluation.corpus.labels -lt 200" in workflow
    assert "true_positive -lt 80" in workflow
    assert "true_negative -lt 80" in workflow
    assert "environment: authorized-dynamic-security" in workflow
    assert '--phases "examples,coverage,fuzzing,stateful"' in workflow
    assert '--report "junit,ndjson"' in workflow
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
    assert re.search(r"pypa/gh-action-pypi-publish@[0-9a-f]{40}(?:\s|$)", publish)
    assert "gh attestation verify" in publish
    assert "post-publish-roundtrip" in publish
    assert "publish-roundtrip/bin/pysec --help" in publish


def test_pypi_publish_verifies_without_oidc_and_publishes_without_code() -> None:
    publish = _workflow("publish-pypi.yml")
    verify_job = publish[
        publish.index("\n  verify:\n") : publish.index("\n  publish:\n")
    ]
    publish_job = publish[
        publish.index("\n  publish:\n") : publish.index("\n  post-publish-roundtrip:\n")
    ]

    assert "id-token" not in verify_job
    assert "environment: pypi-production" not in verify_job
    assert '[[ "$(jq -r .event <<< "$run")" == "push" ]]' in verify_job
    assert '"$release_ref" == "main"' in verify_job
    assert "^v[0-9]" in verify_job
    assert (
        'git merge-base --is-ancestor "$EXPECTED_HEAD_SHA" refs/remotes/origin/main'
        in verify_job
    )
    assert "python -I scripts/verify_release_independent.py" in verify_job

    assert "environment: pypi-production" in publish_job
    assert "needs: verify" in publish_job
    permissions = publish_job[publish_job.index("permissions:") :]
    permissions = permissions[: permissions.index("    env:")]
    assert re.findall(r"(?m)^      ([a-z-]+):", permissions) == ["id-token"]
    assert "actions/checkout" not in publish_job
    assert "python " not in publish_job
    assert "actions/download-artifact@" in publish_job
    assert "needs: [verify, publish]" in publish


def test_release_path_jobs_use_pinned_runner_images() -> None:
    for name in (
        "detection-accuracy.yml",
        "release-assurance.yml",
        "release-evidence.yml",
        "release-promotion.yml",
        "publish-pypi.yml",
        "deep-assurance.yml",
    ):
        assert "ubuntu-latest" not in _workflow(name), name


def test_ci_cancels_only_superseded_pull_request_runs() -> None:
    workflow = _workflow("ci.yml")

    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in workflow
    assert "cancel-in-progress: true" not in workflow


def test_scheduled_dependency_audit_covers_root_and_companion_locks() -> None:
    workflow = _workflow("scheduled-dependency-audit.yml")

    assert "schedule:" in workflow
    assert "workflow_dispatch:" in workflow
    assert "permissions: {}" in workflow
    assert "persist-credentials: false" in workflow
    assert "uv run --frozen pip-audit" in workflow
    assert "uv export --project companion" in workflow
    for uses in re.findall(r"uses: (\S+)", workflow):
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", uses), uses


def test_dependabot_tracks_uv_locks_and_the_scanner_image() -> None:
    config = (_ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
    entries = re.findall(
        r"(?m)^  - package-ecosystem: (\S+)\n    directory: (\S+)$", config
    )

    assert set(entries) == {
        ("github-actions", "/"),
        ("uv", "/"),
        ("uv", "/companion"),
        ("uv", "/containers/scanner"),
        ("docker", "/containers/scanner"),
        ("pip", "/docs"),
    }
    assert config.count("    groups:\n") == len(entries)


def test_release_admission_bootstraps_only_from_trusted_main() -> None:
    for name in ("release-evidence.yml", "release-promotion.yml"):
        workflow = _workflow(name)

        assert "ref: refs/heads/main" in workflow
        assert "ref: ${{ inputs.expected_head_sha }}" not in workflow
        assert '[[ "$GITHUB_REF" == "refs/heads/main" ]]' in workflow
        assert '[[ "$MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]]' in workflow
        assert "before installing or executing repository code" in workflow
        assert "python -I scripts/extract_github_artifact.py" in workflow
        assert "unzip " not in workflow
    assert '[[ "$SOURCE_RUN_ID" =~ ^[1-9][0-9]*$ ]]' in _workflow(
        "release-evidence.yml"
    )
    assert '[[ "$EVIDENCE_RUN_ID" =~ ^[1-9][0-9]*$ ]]' in _workflow(
        "release-promotion.yml"
    )
