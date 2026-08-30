from __future__ import annotations

from pathlib import Path
from typing import Any

from .repository_file_policy import maintained_repository_files
from .models import ToolRun, ToolStatus
from .path_safety import read_regular_file
from .strict_json import canonical_bytes

import hashlib


_MANIFESTS: dict[str, frozenset[str]] = {
    "python": frozenset(
        {"uv.lock", "poetry.lock", "pipfile.lock", "requirements.txt", "pyproject.toml"}
    ),
    "javascript": frozenset(
        {
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
        }
    ),
    "rust": frozenset({"cargo.lock", "cargo.toml"}),
    "go": frozenset({"go.sum", "go.mod"}),
    "ruby": frozenset({"gemfile", "gemfile.lock"}),
    "php": frozenset({"composer.json", "composer.lock"}),
    "jvm": frozenset(
        {
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "gradle.lockfile",
            "dependencies.lock",
            "libs.versions.toml",
        }
    ),
    "dotnet": frozenset({"packages.lock.json", "packages.config", "paket.lock"}),
    "container": frozenset(
        {
            "dockerfile",
            "containerfile",
            "compose.yaml",
            "compose.yml",
            "docker-compose.yaml",
            "docker-compose.yml",
        }
    ),
}


def dependency_surface_artifact(
    target: Path,
    tool_runs: list[ToolRun] | None = None,
    derived_artifacts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Inventory dependency ecosystems and prove their applicable analyzer coverage."""
    manifests: dict[str, list[str]] = {name: [] for name in _MANIFESTS}
    for path in maintained_repository_files(target):
        folded = path.name.casefold()
        for ecosystem, names in _MANIFESTS.items():
            matches_pattern = (
                ecosystem == "python"
                and folded.startswith("requirements")
                and folded.endswith(".txt")
            ) or (
                ecosystem == "dotnet"
                and path.suffix.casefold() in {".csproj", ".fsproj", ".vbproj"}
            )
            if (folded in names or matches_pattern) and len(manifests[ecosystem]) < 200:
                manifests[ecosystem].append(path.relative_to(target).as_posix())
    manifests = {
        ecosystem: sorted(paths) for ecosystem, paths in manifests.items() if paths
    }
    completed = {
        run.tool: run for run in tool_runs or [] if run.status is ToolStatus.COMPLETED
    }
    coverage: list[dict[str, Any]] = []
    for ecosystem, paths in sorted(manifests.items()):
        for relative in paths:
            required_vulnerability_tools = (
                {"oci-image"} if ecosystem == "container" else {"osv-scanner"}
            )
            vulnerability_tools = sorted(
                completed.keys() & required_vulnerability_tools
            )
            semantic_required = ecosystem not in {"python", "container"}
            semantic_tools = sorted(completed.keys() & {"polyglot", "codeql"})
            resolved_identity = _resolved_dependency_identity(
                ecosystem, relative, paths
            )
            _, payload = read_regular_file(
                target / relative,
                "dependency manifest",
                maximum_bytes=256 * 1024 * 1024,
                boundary=target,
            )
            manifest_sha256 = hashlib.sha256(payload).hexdigest()
            vulnerability_receipt = _vulnerability_receipt(
                ecosystem,
                relative,
                manifest_sha256,
                derived_artifacts or {},
            )
            covered = (
                resolved_identity
                and bool(vulnerability_tools)
                and vulnerability_receipt is not None
                and (not semantic_required or bool(semantic_tools))
            )
            analyzers = [
                completed[name] for name in vulnerability_tools + semantic_tools
            ]
            coverage.append(
                {
                    "ecosystem": ecosystem,
                    "manifest": relative,
                    "manifest_sha256": manifest_sha256,
                    "vulnerability_tools": vulnerability_tools,
                    "semantic_tools": semantic_tools,
                    "semantic_analysis_required": semantic_required,
                    "resolved_dependency_identity": resolved_identity,
                    "resolution_basis": (
                        "lock-or-checksum-manifest"
                        if _is_lock_manifest(ecosystem, relative)
                        else (
                            "source-bound-built-artifact"
                            if ecosystem == "container"
                            else "paired-lock-or-checksum-manifest"
                        )
                    ),
                    "execution_receipts": [
                        {
                            "tool": run.tool,
                            "command_sha256": hashlib.sha256(
                                canonical_bytes(run.command)
                            ).hexdigest(),
                            "status": run.status.value,
                            "coverage_scope": _coverage_scope(run.tool),
                            "coverage_basis": _coverage_basis(run.tool),
                            "manifest_reported": (
                                run.tool == "osv-scanner"
                                and vulnerability_receipt is not None
                            ),
                            "manifest_sha256": (
                                manifest_sha256
                                if run.tool == "osv-scanner"
                                and vulnerability_receipt is not None
                                else ""
                            ),
                            "output_receipt_sha256": (
                                str(vulnerability_receipt["receipt_sha256"])
                                if run.tool == "osv-scanner"
                                and vulnerability_receipt is not None
                                else ""
                            ),
                        }
                        for run in analyzers
                    ],
                    "covered": covered,
                }
            )
    return {
        "schema_version": "1.1",
        "analysis": "multi-ecosystem-dependency-surface",
        "manifests": manifests,
        "ecosystem_count": len(manifests),
        "coverage_evaluated": tool_runs is not None,
        "coverage": coverage,
        "complete": tool_runs is not None and all(item["covered"] for item in coverage),
    }


def _vulnerability_receipt(
    ecosystem: str,
    relative: str,
    manifest_sha256: str,
    artifacts: dict[str, Any],
) -> dict[str, Any] | None:
    if ecosystem == "container":
        artifact = artifacts.get("oci-image-summary.json")
        if (
            isinstance(artifact, dict)
            and artifact.get("schema_version") == "2.0"
            and isinstance(artifact.get("evidence_binding"), dict)
            and artifact["evidence_binding"].get("authenticated") is True
            and artifact["evidence_binding"].get("verified") is True
        ):
            return {
                "receipt_sha256": hashlib.sha256(canonical_bytes(artifact)).hexdigest()
            }
        return None
    receipt = artifacts.get("osv-manifest-receipts.json")
    if not isinstance(receipt, dict):
        return None
    receipt_sha256 = receipt.get("receipt_sha256")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if (
        not isinstance(receipt_sha256, str)
        or hashlib.sha256(canonical_bytes(unsigned)).hexdigest() != receipt_sha256
    ):
        return None
    manifests = receipt.get("manifests")
    if not isinstance(manifests, list):
        return None
    if any(
        isinstance(item, dict)
        and item.get("manifest") == relative
        and item.get("manifest_sha256") == manifest_sha256
        for item in manifests
    ):
        return receipt
    return None


def _coverage_basis(tool: str) -> str:
    return {
        "osv-scanner": "recursive-lockfile-and-manifest-scan",
        "codeql": "repository-semantic-database",
        "polyglot": "authenticated-source-bound-language-matrix",
        "oci-image": "authenticated-source-bound-built-artifact",
    }.get(tool, "completed-analyzer-command")


def _coverage_scope(tool: str) -> str:
    return {
        "osv-scanner": "source-tree",
        "codeql": "source-tree",
        "polyglot": "source-bound-external-evidence",
        "oci-image": "source-bound-built-artifact",
    }.get(tool, "declared-command")


def _resolved_dependency_identity(
    ecosystem: str, relative: str, ecosystem_paths: list[str]
) -> bool:
    if ecosystem == "container" or _is_lock_manifest(ecosystem, relative):
        return True
    parent = Path(relative).parent
    return any(
        Path(candidate).parent == parent and _is_lock_manifest(ecosystem, candidate)
        for candidate in ecosystem_paths
    )


def _is_lock_manifest(ecosystem: str, relative: str) -> bool:
    name = Path(relative).name.casefold()
    return name in {
        "uv.lock",
        "poetry.lock",
        "pipfile.lock",
        "requirements.txt",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "cargo.lock",
        "go.sum",
        "gemfile.lock",
        "composer.lock",
        "gradle.lockfile",
        "dependencies.lock",
        "packages.lock.json",
        "paket.lock",
    } or (
        ecosystem == "python"
        and name.startswith("requirements")
        and name.endswith(".txt")
    )
