from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass
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


@dataclass(frozen=True)
class DependencyInventory:
    """Manifest identities collected once inside the sealed source snapshot."""

    root: Path
    manifests: tuple[tuple[str, str, str], ...]
    discovered: tuple[tuple[str, int], ...]


def inventory_dependencies(target: Path) -> DependencyInventory:
    manifests: list[tuple[str, str, str]] = []
    discovered = dict.fromkeys(_MANIFESTS, 0)
    for path in maintained_repository_files(target):
        folded = path.name.casefold()
        for ecosystem, names in _MANIFESTS.items():
            matches = (
                ecosystem == "python"
                and folded.startswith("requirements")
                and folded.endswith(".txt")
            ) or (
                ecosystem == "dotnet"
                and path.suffix.casefold() in {".csproj", ".fsproj", ".vbproj"}
            )
            if folded not in names and not matches:
                continue
            discovered[ecosystem] += 1
            if discovered[ecosystem] <= 200:
                _, payload = read_regular_file(
                    path,
                    "dependency manifest",
                    maximum_bytes=256 * 1024 * 1024,
                    boundary=target,
                )
                manifests.append(
                    (
                        ecosystem,
                        path.relative_to(target).as_posix(),
                        hashlib.sha256(payload).hexdigest(),
                    )
                )
    return DependencyInventory(
        target.resolve(), tuple(sorted(manifests)), tuple(sorted(discovered.items()))
    )


def dependency_surface_artifact(
    target: Path,
    tool_runs: list[ToolRun] | None = None,
    derived_artifacts: dict[str, Any] | None = None,
    *,
    inventory: DependencyInventory | None = None,
) -> dict[str, Any]:
    """Inventory dependency ecosystems and prove their applicable analyzer coverage."""
    inventory = inventory or inventory_dependencies(target)
    if inventory.root != target.resolve():
        raise ValueError("dependency inventory belongs to a different snapshot")
    manifests: dict[str, list[str]] = {}
    digests: dict[str, str] = {}
    for ecosystem, relative, digest in inventory.manifests:
        manifests.setdefault(ecosystem, []).append(relative)
        digests[relative] = digest
    accounting = {
        ecosystem: {
            "discovered": count,
            "analyzed": len(manifests.get(ecosystem, [])),
            "omitted": max(0, count - 200),
        }
        for ecosystem, count in inventory.discovered
        if count
    }
    omitted = sum(item["omitted"] for item in accounting.values())
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
            manifest_sha256 = digests[relative]
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
        "schema_version": "1.2",
        "analysis": "multi-ecosystem-dependency-surface",
        "manifests": manifests,
        "ecosystem_count": len(manifests),
        "coverage_evaluated": tool_runs is not None,
        "coverage": coverage,
        "inventory_counts": accounting,
        "manifest_limit_per_ecosystem": 200,
        "omitted_manifests": omitted,
        "complete": tool_runs is not None
        and not omitted
        and all(item["covered"] for item in coverage),
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


def validate_dependency_accounting(value: Any) -> None:
    """Cross-check the inventory limit against completeness before publication."""
    if value.get("schema_version") != "1.2":
        return
    counts = value["inventory_counts"]
    manifests = value["manifests"]
    if set(counts) != set(manifests) or value["ecosystem_count"] != len(manifests):
        raise ValueError("dependency inventory ecosystem accounting differs")
    for ecosystem, count in counts.items():
        analyzed = len(manifests[ecosystem])
        if (
            count["analyzed"] != analyzed
            or analyzed != min(count["discovered"], 200)
            or count["omitted"] != count["discovered"] - analyzed
        ):
            raise ValueError("dependency inventory manifest accounting differs")
    omitted = sum(count["omitted"] for count in counts.values())
    expected = {
        (ecosystem, path) for ecosystem, paths in manifests.items() for path in paths
    }
    observed = [(row["ecosystem"], row["manifest"]) for row in value["coverage"]]
    complete = (
        value["coverage_evaluated"]
        and not omitted
        and all(row["covered"] for row in value["coverage"])
    )
    if (
        value["omitted_manifests"] != omitted
        or set(observed) != expected
        or len(observed) != len(expected)
        or value["complete"] != complete
    ):
        raise ValueError("dependency inventory coverage accounting differs")


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
