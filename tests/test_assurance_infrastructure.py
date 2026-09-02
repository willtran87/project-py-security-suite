from __future__ import annotations

import tomllib
from pathlib import Path


_ROOT = Path(__file__).parent.parent


def test_deep_assurance_uses_sealed_database_input_and_aggregate_gate() -> None:
    workflow = (_ROOT / ".github/workflows/deep-assurance.yml").read_text(
        encoding="utf-8"
    )
    prepare = workflow.index("scripts/prepare_scanner_database.py")
    build = workflow.index("scripts/build-scanner-image.ps1")
    scan = workflow.index("scripts/run-self-scan.ps1")

    assert prepare < build < scan
    assert "-OsvDatabaseDirectory .artifacts/deep-self-scan-inputs/osv-pypi" in workflow
    assert "name: Deep assurance required gate" in workflow
    assert "needs: [end-to-end-self-scan, mutation-assurance]" in workflow
    assert 'all(.[]; .result == "success")' in workflow
    assert "pull_request:" in workflow
    assert "Attest the exact scanner image evidence" in workflow
    assert "deep-self-scan-image-${{ github.sha }}" in workflow
    assert "retention-days: 180" not in workflow
    release_workflow = (_ROOT / ".github/workflows/release-assurance.yml").read_text(
        encoding="utf-8"
    )
    assert "uses: ./.github/workflows/deep-assurance.yml" in release_workflow
    assert "needs: deep-assurance" in release_workflow


def test_scanner_build_cannot_resolve_the_mutable_database_url() -> None:
    dockerfile = (_ROOT / "containers/scanner/Dockerfile").read_text(encoding="utf-8")
    build_script = (_ROOT / "scripts/build-scanner-image.ps1").read_text(
        encoding="utf-8"
    )

    assert "osv-vulnerabilities.storage.googleapis.com" not in dockerfile
    assert "COPY --from=osv_database" in dockerfile
    assert "OSV_PYPI_DATABASE_SHA256" in dockerfile
    assert "dockerfile:1@sha256:" in dockerfile
    assert "slim-bookworm@sha256:" in dockerfile
    assert "OSV_SCANNER_LINUX_AMD64_SHA256" not in dockerfile
    assert "pip install --require-hashes" in dockerfile
    assert "containers/scanner/requirements.lock" in dockerfile
    assert "PYTHONPATH=/opt/pysec-suite/src" in dockerfile
    assert '"bomFormat": "CycloneDX"' in dockerfile
    assert '"specVersion": "1.6"' in dockerfile
    assert '"dependencies": dependencies' in dockerfile
    assert "io.pysec.installed-metadata.sha256" in dockerfile
    assert "io.pysec.bom-graph.sha256" in dockerfile
    assert "!= root_name" in dockerfile
    assert "root_dependencies" in dockerfile
    assert '"hashes":' not in dockerfile
    assert "pip install --no-deps /opt/pysec-suite" not in dockerfile
    scanner_project = (_ROOT / "containers/scanner/pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert '"bandit==1.9.4"' in scanner_project
    assert 'py-security-suite = { path = "../.." }' in scanner_project
    assert "[Parameter(Mandatory = $true)]" in build_script
    assert "Get-FileHash" in build_script
    assert '--build-context "osv_database=$databaseDirectory"' in build_script
    assert "unexpected artifact kind" in build_script
    assert "unexpected build input" in build_script
    assert "unauthorized source" in build_script
    assert "size does not match its metadata" in build_script
    assert "scanner-image-evidence.json" in build_script
    assert "python-sbom.cdx.json" in build_script
    assert "python_sbom_sha256" in build_script
    assert "target.chmod(0o444)" in dockerfile
    assert "chmod 0444 /opt/osv-db/osv-scanner/PyPI/all.zip" in dockerfile
    assert "--user 42424:42424" in build_script
    assert "arbitrary-uid-assets-readable" in build_script


def test_self_scan_preserves_non_root_host_output_ownership_on_unix() -> None:
    launcher = (_ROOT / "scripts/run-self-scan.ps1").read_text(encoding="utf-8")

    assert "$IsLinux -or $IsMacOS" in launcher
    assert "(& id -u).Trim()" in launcher
    assert "(& id -g).Trim()" in launcher
    assert '"--user", "${runtimeUid}:${runtimeGid}"' in launcher
    assert '"HOME=/tmp"' in launcher
    assert '"XDG_CACHE_HOME=/tmp/.cache"' in launcher


def test_mutation_assurance_copies_only_required_companion_support_code() -> None:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["tool"]["mutmut"]["source_paths"] == [
        "src/",
        "companion/__init__.py",
        "companion/strict_json.py",
    ]
    assert {
        "src/py_security_suite/execution_policy.py",
        "src/py_security_suite/failure_domain.py",
        "src/py_security_suite/isolation_probe.py",
        "src/py_security_suite/operation_receipt.py",
        "src/py_security_suite/release_readiness.py",
        "src/py_security_suite/trusted_observation.py",
    } <= set(project["tool"]["mutmut"]["only_mutate"])


def test_mutation_assurance_preloads_fork_sensitive_native_crypto() -> None:
    workflow = (_ROOT / ".github/workflows/deep-assurance.yml").read_text(
        encoding="utf-8"
    )
    launcher = (_ROOT / "scripts/run_mutation_assurance.py").read_text(encoding="utf-8")

    assert "MUTATION_SHARD: ${{ matrix.shard }}" in workflow
    assert '--shard-index "$MUTATION_SHARD" --shard-count 6' in workflow
    assert "scripts/validate_mutation_assurance.py" in workflow
    assert "--minimum-score 70" in workflow
    assert "shard: [0, 1, 2, 3, 4, 5]" in workflow
    assert 'uv sync --locked --all-groups --python "3.13"' in workflow
    assert "preload_fork_sensitive_crypto_runtime()" in launcher
    assert "serialization.load_pem_private_key" in launcher
    assert "x509.NameAttribute" in launcher


def test_deep_assurance_cancels_only_superseded_pull_request_runs() -> None:
    workflow = (_ROOT / ".github/workflows/deep-assurance.yml").read_text(
        encoding="utf-8"
    )

    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in workflow
    assert "github.event.pull_request.number || github.ref" in workflow


def test_ci_rejects_a_stale_scanner_dependency_export() -> None:
    workflow = (_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "Verify scanner dependency lock export" in workflow
    assert "uv export --frozen --project containers/scanner" in workflow
    assert "--no-emit-local" in workflow
    assert "diff --strip-trailing-cr" in workflow
    assert "recursive-include containers *.lock" in (_ROOT / "MANIFEST.in").read_text(
        encoding="utf-8"
    )


def test_strict_type_and_lint_surfaces_are_ratchet_expanded() -> None:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    strict_files = set(project["tool"]["pyright"]["include"])

    assert "C4" in project["tool"]["ruff"]["lint"]["select"]
    assert {
        "src/py_security_suite/benchmark_input_validation.py",
        "src/py_security_suite/benchmark_semantic_evidence.py",
        "src/py_security_suite/bounded_subprocess.py",
        "src/py_security_suite/failure_domain.py",
        "src/py_security_suite/isolation_probe.py",
        "src/py_security_suite/orchestrator.py",
        "src/py_security_suite/path_safety.py",
        "src/py_security_suite/release_readiness.py",
        "src/py_security_suite/reports.py",
        "src/py_security_suite/strict_json.py",
    } <= strict_files
    workflow = (_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "Enforce the strict primary type-contract surface" in workflow
    assert "--config-file src/py_security_suite/rules/mypy.ini" in workflow
