from __future__ import annotations

from typing import Any

from .config import PROFILE_TOOLS, SUPPORTED_TOOLS
from .models import ToolRun, ToolStatus


_LAYERS = {
    "source_security": frozenset(
        {"bandit", "semgrep", "pysa", "codeql", "devskim", "flawfinder"}
    ),
    "secrets": frozenset(
        {"detect-secrets", "gitleaks", "trufflehog", "secret-verification"}
    ),
    "dependencies": frozenset(
        {"osv-scanner", "cyclonedx-py", "grype", "guarddog", "pipdeptree", "deptry"}
    ),
    "quality": frozenset(
        {
            "ruff-quality",
            "pylint",
            "mypy",
            "pyright",
            "vulture",
            "radon",
            "coverage",
            "junit",
            "diff-cover",
        }
    ),
    "architecture": frozenset({"tach", "reachability", "graphify"}),
    "runtime": frozenset(PROFILE_TOOLS["runtime"]),
    # Keep this layer narrower than the convenience profile of the same name.
    # That profile intentionally includes baseline source scanners, which must
    # not make a source-only run look like supply-chain evidence completed.
    "supply_chain": frozenset(
        {
            "cyclonedx-py",
            "gitleaks",
            "grype",
            "guarddog",
            "osv-scanner",
            "scancode",
            "syft",
            "trivy",
            "trufflehog",
        }
    ),
    "artifact": frozenset(PROFILE_TOOLS["artifact"]),
}


def capability_manifest(profile: str, runs: list[ToolRun]) -> dict[str, Any]:
    selected = set(PROFILE_TOOLS[profile])
    completed = {run.tool for run in runs if run.status is ToolStatus.COMPLETED}
    applicable = {run.tool for run in runs if run.applicable}
    gaps = {
        run.tool
        for run in runs
        if run.applicable and run.status is not ToolStatus.COMPLETED
    }
    return {
        "schema_version": "1.0",
        "analysis": "generated-profile-and-execution-capability-truth",
        "profile": profile,
        "available_tool_count": len(SUPPORTED_TOOLS),
        "available_profile_count": len(PROFILE_TOOLS),
        "profiles": [
            {"name": name, "selected_tool_count": len(tools)}
            for name, tools in sorted(PROFILE_TOOLS.items())
        ],
        "selected_tool_count": len(selected),
        "selected_tools": sorted(selected),
        "not_selected_tools": sorted(SUPPORTED_TOOLS - selected),
        "applicable_tool_count": len(applicable),
        "applicable_tools": sorted(applicable),
        "completed_tool_count": len(completed),
        "completed_tools": sorted(completed),
        "execution_gap_count": len(gaps),
        "execution_gaps": sorted(gaps),
        "layers": {
            name: {
                "selected": bool(selected & tools),
                "applicable": bool(applicable & tools),
                "completed": sorted(completed & tools),
                "execution_gaps": sorted(gaps & tools),
            }
            for name, tools in sorted(_LAYERS.items())
        },
        "claim_boundary": (
            "Available tools are portfolio capabilities, selected tools are profile intent, "
            "and only completed applicable tools contributed observations to this scan."
        ),
    }
