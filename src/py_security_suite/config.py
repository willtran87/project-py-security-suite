from __future__ import annotations

import copy
import re
import tomllib
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any
from collections.abc import Mapping

from .models import Severity
from .path_safety import resolve_regular_file


class ConfigurationError(ValueError):
    pass


PROFILE_TOOLS: dict[str, tuple[str, ...]] = {
    "quick": ("bandit", "detect-secrets"),
    "standard": (
        "bandit",
        "semgrep",
        "detect-secrets",
        "osv-scanner",
    ),
    "extended": (
        "bandit",
        "semgrep",
        "detect-secrets",
        "osv-scanner",
        "cyclonedx-py",
        "ruff",
        "zizmor",
    ),
    "deep": (
        "bandit",
        "semgrep",
        "detect-secrets",
        "osv-scanner",
        "cyclonedx-py",
        "ruff",
        "zizmor",
        "pysa",
        "codeql",
    ),
    "supply-chain": (
        "bandit",
        "semgrep",
        "detect-secrets",
        "osv-scanner",
        "cyclonedx-py",
        "ruff",
        "zizmor",
        "trivy",
        "guarddog",
        "scancode",
        "gitleaks",
        "trufflehog",
    ),
    "artifact": (
        "syft",
        "grype",
        "check-wheel-contents",
        "twine",
        "pypi-attestations",
        "cosign",
    ),
    "quality": (
        "ruff-quality",
        "ruff-format",
        "pylint",
        "mypy",
        "pyright",
        "deptry",
        "vulture",
        "radon",
        "tach",
        "coverage",
        "junit",
        "diff-cover",
        "psscriptanalyzer",
        "shellcheck",
        "actionlint",
        "hadolint",
        "reuse",
    ),
    "iac-deep": (
        "checkov",
        "trivy",
        "hadolint",
        "actionlint",
        "zizmor",
    ),
    "governance": (
        "scorecard",
        "reuse",
        "zizmor",
        "actionlint",
    ),
    "repo": (
        "bandit",
        "semgrep",
        "detect-secrets",
        "osv-scanner",
        "cyclonedx-py",
        "ruff",
        "ruff-quality",
        "ruff-format",
        "pylint",
        "mypy",
        "pyright",
        "deptry",
        "vulture",
        "radon",
        "tach",
        "coverage",
        "junit",
        "diff-cover",
        "psscriptanalyzer",
        "shellcheck",
        "zizmor",
        "actionlint",
        "hadolint",
        "pysa",
        "trivy",
        "guarddog",
        "scancode",
        "gitleaks",
        "trufflehog",
        "devskim",
        "flawfinder",
        "reuse",
        "checkov",
        "scorecard",
        "codeql",
    ),
    "comprehensive": (
        "bandit",
        "semgrep",
        "detect-secrets",
        "osv-scanner",
        "cyclonedx-py",
        "ruff",
        "ruff-quality",
        "ruff-format",
        "pylint",
        "mypy",
        "pyright",
        "deptry",
        "vulture",
        "radon",
        "tach",
        "coverage",
        "junit",
        "diff-cover",
        "psscriptanalyzer",
        "shellcheck",
        "zizmor",
        "actionlint",
        "hadolint",
        "pysa",
        "trivy",
        "guarddog",
        "scancode",
        "gitleaks",
        "trufflehog",
        "devskim",
        "flawfinder",
        "reuse",
        "codeql",
        "syft",
        "grype",
        "check-wheel-contents",
        "twine",
        "pypi-attestations",
        "checkov",
        "cosign",
        "scorecard",
    ),
    "production": (
        "bandit",
        "semgrep",
        "detect-secrets",
        "osv-scanner",
        "cyclonedx-py",
        "ruff",
        "ruff-format",
        "pylint",
        "pyright",
        "deptry",
        "radon",
        "tach",
        "coverage",
        "junit",
        "diff-cover",
        "psscriptanalyzer",
        "shellcheck",
        "zizmor",
        "actionlint",
        "hadolint",
        "pysa",
        "trivy",
        "guarddog",
        "scancode",
        "gitleaks",
        "trufflehog",
        "devskim",
        "flawfinder",
        "reuse",
        "codeql",
        "checkov",
        "scorecard",
    ),
    "release": (
        "bandit",
        "semgrep",
        "detect-secrets",
        "osv-scanner",
        "cyclonedx-py",
        "ruff",
        "ruff-quality",
        "ruff-format",
        "pylint",
        "mypy",
        "pyright",
        "deptry",
        "vulture",
        "radon",
        "tach",
        "coverage",
        "junit",
        "diff-cover",
        "psscriptanalyzer",
        "shellcheck",
        "zizmor",
        "actionlint",
        "hadolint",
        "pysa",
        "trivy",
        "guarddog",
        "scancode",
        "gitleaks",
        "trufflehog",
        "devskim",
        "flawfinder",
        "reuse",
        "codeql",
        "syft",
        "grype",
        "check-wheel-contents",
        "twine",
        "pypi-attestations",
        "checkov",
        "cosign",
        "scorecard",
    ),
}

_REPOSITORY_INSIGHT_TOOLS = (
    "conftest",
    "kics",
    "pipdeptree",
    "git-sizer",
    "validate-pyproject",
    "vale",
    "kube-linter",
)
_TRUSTED_LANE_EVIDENCE_TOOLS = (
    "hypothesis",
    "schemathesis",
    "crosshair",
    "atheris",
    "mutmut",
    "zap",
    "pytm",
    "check-manifest",
    "clamav",
    "github-attestation",
)
_RELEASE_ASSURANCE_EVIDENCE_TOOLS = (
    "in-toto",
    "oci-image",
    "reproducible-build",
    "yara",
)

# Keep the original quick/standard contracts stable. Broader profiles gain the
# new static policy/health perspectives and passive evidence channels.
PROFILE_TOOLS["repo-health"] = _REPOSITORY_INSIGHT_TOOLS
for _profile in ("quality", "repo", "comprehensive", "production", "release"):
    PROFILE_TOOLS[_profile] = tuple(
        dict.fromkeys(PROFILE_TOOLS[_profile] + _REPOSITORY_INSIGHT_TOOLS)
    )
for _profile in ("repo", "comprehensive", "production", "release"):
    PROFILE_TOOLS[_profile] = tuple(
        dict.fromkeys(PROFILE_TOOLS[_profile] + _TRUSTED_LANE_EVIDENCE_TOOLS)
    )
PROFILE_TOOLS["iac-deep"] = tuple(
    dict.fromkeys(PROFILE_TOOLS["iac-deep"] + ("conftest", "kics", "kube-linter"))
)
PROFILE_TOOLS["artifact"] = tuple(
    dict.fromkeys(
        PROFILE_TOOLS["artifact"]
        + ("check-manifest", "clamav", "github-attestation")
        + _RELEASE_ASSURANCE_EVIDENCE_TOOLS
    )
)
for _profile in ("comprehensive", "release"):
    PROFILE_TOOLS[_profile] = tuple(
        dict.fromkeys(PROFILE_TOOLS[_profile] + _RELEASE_ASSURANCE_EVIDENCE_TOOLS)
    )
for _profile in ("quality", "repo", "comprehensive", "production", "release"):
    PROFILE_TOOLS[_profile] = tuple(
        dict.fromkeys(PROFILE_TOOLS[_profile] + ("reachability",))
    )

SUPPORTED_TOOLS = frozenset(
    tool for profile_tools in PROFILE_TOOLS.values() for tool in profile_tools
)


@dataclass(slots=True)
class IsolationConfig:
    network: str = "deny"
    require_attestation: bool = True
    execute_target_code: bool = False


@dataclass(slots=True)
class ExecutionConfig:
    max_workers: int = 4
    max_output_bytes: int = 16 * 1024 * 1024


@dataclass(slots=True)
class PolicyConfig:
    required_scanners: tuple[str, ...] = ()
    block_severities: tuple[Severity, ...] = (
        Severity.CRITICAL,
        Severity.HIGH,
    )
    incomplete_is_blocking: bool = True
    risk_acceptance_path: Path | None = None
    risk_acceptance_sha256: str = ""


@dataclass(slots=True)
class ReportsConfig:
    include_sanitized_evidence: bool = True
    baseline_path: Path | None = None
    baseline_sha256: str = ""


@dataclass(slots=True)
class IntelligenceConfig:
    kev_path: Path | None = None
    kev_sha256: str = ""
    epss_path: Path | None = None
    epss_sha256: str = ""
    vex_path: Path | None = None
    vex_sha256: str = ""
    maximum_age_days: float = 3.0
    epss_high_probability: float = 0.1
    epss_high_percentile: float = 0.9


@dataclass(slots=True)
class TrustConfig:
    catalog_path: Path | None = None
    catalog_sha256: str = ""


@dataclass(slots=True)
class ToolConfig:
    enabled: bool = True
    executable: str = ""
    timeout_seconds: int = 300
    rules_path: Path | None = None
    database_path: Path | None = None
    artifacts_path: Path | None = None
    provenance_path: Path | None = None
    auxiliary_executable: str = ""
    repository_url: str = ""
    executable_sha256: str = ""
    auxiliary_executable_sha256: str = ""
    minimum_coverage_percent: float = 80.0
    maximum_database_age_days: float = 10.0
    compare_branch: str = ""
    public_key_path: Path | None = None
    certificate_identity: str = ""
    certificate_oidc_issuer: str = ""
    minimum_island_loc: int = 100
    entry_points: tuple[str, ...] = ()
    source_roots: tuple[str, ...] = ()
    discover_framework_roots: bool = True
    coverage_path: Path | None = None


@dataclass(slots=True)
class SuiteConfig:
    schema_version: str = "1"
    profile: str = "standard"
    isolation: IsolationConfig = field(default_factory=IsolationConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    reports: ReportsConfig = field(default_factory=ReportsConfig)
    intelligence: IntelligenceConfig = field(default_factory=IntelligenceConfig)
    trust: TrustConfig = field(default_factory=TrustConfig)
    tools: dict[str, ToolConfig] = field(default_factory=dict)

    @property
    def selected_tools(self) -> tuple[str, ...]:
        return PROFILE_TOOLS[self.profile]

    @property
    def required_tools(self) -> tuple[str, ...]:
        return self.policy.required_scanners or self.selected_tools


def _default_mapping() -> dict[str, Any]:
    bundled_rules = Path(
        str(files("py_security_suite").joinpath("rules/python-security.yml"))
    )
    bundled_gitleaks = Path(
        str(files("py_security_suite").joinpath("rules/gitleaks.toml"))
    )
    bundled_trufflehog_excludes = Path(
        str(files("py_security_suite").joinpath("rules/trufflehog-exclude.txt"))
    )
    bundled_mypy = Path(str(files("py_security_suite").joinpath("rules/mypy.ini")))
    bundled_vulture = Path(
        str(files("py_security_suite").joinpath("rules/vulture.toml"))
    )
    bundled_actionlint = Path(
        str(files("py_security_suite").joinpath("rules/actionlint.yaml"))
    )
    bundled_hadolint = Path(
        str(files("py_security_suite").joinpath("rules/hadolint.yaml"))
    )
    bundled_pylint = Path(str(files("py_security_suite").joinpath("rules/pylint.ini")))
    bundled_psscriptanalyzer = Path(
        str(files("py_security_suite").joinpath("rules/psscriptanalyzer.psd1"))
    )
    bundled_pyright = Path(
        str(files("py_security_suite").joinpath("rules/pyrightconfig.json"))
    )
    return {
        "schema_version": "1",
        "profile": "standard",
        "isolation": {
            "network": "deny",
            "require_attestation": True,
            "execute_target_code": False,
        },
        "execution": {
            "max_workers": 4,
            "max_output_bytes": 16 * 1024 * 1024,
        },
        "policy": {
            "required_scanners": [],
            "block_severities": ["critical", "high"],
            "incomplete_is_blocking": True,
            "risk_acceptance_path": None,
            "risk_acceptance_sha256": "",
        },
        "reports": {
            "include_sanitized_evidence": True,
            "baseline_path": None,
            "baseline_sha256": "",
        },
        "intelligence": {
            "kev_path": None,
            "kev_sha256": "",
            "epss_path": None,
            "epss_sha256": "",
            "vex_path": None,
            "vex_sha256": "",
            "maximum_age_days": 3.0,
            "epss_high_probability": 0.1,
            "epss_high_percentile": 0.9,
        },
        "trust": {
            "catalog_path": None,
            "catalog_sha256": "",
        },
        "tools": {
            "bandit": {
                "enabled": True,
                "executable": "bandit",
                "timeout_seconds": 300,
            },
            "semgrep": {
                "enabled": True,
                "executable": "semgrep",
                "timeout_seconds": 600,
                "rules_path": str(bundled_rules),
            },
            "detect-secrets": {
                "enabled": True,
                "executable": "detect-secrets",
                "timeout_seconds": 300,
            },
            "osv-scanner": {
                "enabled": True,
                "executable": "osv-scanner",
                "timeout_seconds": 300,
                "database_path": None,
            },
            "cyclonedx-py": {
                "enabled": True,
                "executable": "cyclonedx-py",
                "timeout_seconds": 300,
            },
            "ruff": {
                "enabled": True,
                "executable": "ruff",
                "timeout_seconds": 300,
            },
            "ruff-quality": {
                "enabled": True,
                "executable": "ruff",
                "timeout_seconds": 300,
            },
            "ruff-format": {
                "enabled": True,
                "executable": "ruff",
                "timeout_seconds": 300,
            },
            "pylint": {
                "enabled": True,
                "executable": "pylint",
                "timeout_seconds": 600,
                "rules_path": str(bundled_pylint),
            },
            "mypy": {
                "enabled": True,
                "executable": "mypy",
                "timeout_seconds": 600,
                "rules_path": str(bundled_mypy),
            },
            "pyright": {
                "enabled": True,
                "executable": "node",
                "timeout_seconds": 600,
                "rules_path": str(bundled_pyright),
                "database_path": None,
            },
            "deptry": {
                "enabled": True,
                "executable": "deptry",
                "timeout_seconds": 600,
            },
            "vulture": {
                "enabled": True,
                "executable": "vulture",
                "timeout_seconds": 300,
                "rules_path": str(bundled_vulture),
            },
            "radon": {
                "enabled": True,
                "executable": "radon",
                "timeout_seconds": 300,
            },
            "tach": {
                "enabled": True,
                "executable": "tach",
                "timeout_seconds": 300,
            },
            "reachability": {
                "enabled": True,
                "executable": "pysec",
                "timeout_seconds": 600,
                "minimum_island_loc": 100,
                "entry_points": [],
                "source_roots": [],
                "discover_framework_roots": True,
                "coverage_path": None,
            },
            "coverage": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 300,
                "artifacts_path": "coverage.json",
                "minimum_coverage_percent": 80.0,
            },
            "junit": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 300,
                "artifacts_path": "junit.xml",
            },
            "hypothesis": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "hypothesis-junit.xml",
            },
            "schemathesis": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "schemathesis-junit.xml",
            },
            "diff-cover": {
                "enabled": True,
                "executable": "diff-cover",
                "timeout_seconds": 300,
                "artifacts_path": "coverage.xml",
                "minimum_coverage_percent": 80.0,
                "compare_branch": "origin/main",
            },
            "psscriptanalyzer": {
                "enabled": True,
                "executable": "powershell.exe",
                "timeout_seconds": 600,
                "rules_path": str(bundled_psscriptanalyzer),
                "database_path": None,
            },
            "shellcheck": {
                "enabled": True,
                "executable": "shellcheck",
                "timeout_seconds": 300,
            },
            "zizmor": {
                "enabled": True,
                "executable": "zizmor",
                "timeout_seconds": 300,
            },
            "actionlint": {
                "enabled": True,
                "executable": "actionlint",
                "timeout_seconds": 300,
                "rules_path": str(bundled_actionlint),
            },
            "hadolint": {
                "enabled": True,
                "executable": "hadolint",
                "timeout_seconds": 300,
                "rules_path": str(bundled_hadolint),
            },
            "pysa": {
                "enabled": True,
                "executable": "pyre",
                "timeout_seconds": 1200,
            },
            "trivy": {
                "enabled": True,
                "executable": "trivy",
                "timeout_seconds": 900,
                "database_path": None,
            },
            "checkov": {
                "enabled": True,
                "executable": "checkov",
                "timeout_seconds": 1200,
            },
            "guarddog": {
                "enabled": True,
                "executable": "guarddog",
                "timeout_seconds": 900,
            },
            "scancode": {
                "enabled": True,
                "executable": "scancode",
                "timeout_seconds": 1800,
            },
            "gitleaks": {
                "enabled": True,
                "executable": "gitleaks",
                "timeout_seconds": 900,
                "rules_path": str(bundled_gitleaks),
            },
            "trufflehog": {
                "enabled": True,
                "executable": "trufflehog",
                "timeout_seconds": 900,
                "rules_path": str(bundled_trufflehog_excludes),
            },
            "devskim": {
                "enabled": True,
                "executable": "devskim",
                "timeout_seconds": 900,
            },
            "flawfinder": {
                "enabled": True,
                "executable": "flawfinder",
                "timeout_seconds": 600,
            },
            "reuse": {
                "enabled": True,
                "executable": "reuse",
                "timeout_seconds": 600,
            },
            "codeql": {
                "enabled": True,
                "executable": "run-codeql",
                "timeout_seconds": 1800,
                "database_path": None,
                "auxiliary_executable": "codeql",
            },
            "syft": {
                "enabled": True,
                "executable": "syft",
                "timeout_seconds": 600,
                "artifacts_path": "dist",
            },
            "grype": {
                "enabled": True,
                "executable": "grype",
                "timeout_seconds": 900,
                "database_path": None,
                "artifacts_path": "dist",
            },
            "check-wheel-contents": {
                "enabled": True,
                "executable": "check-wheel-contents",
                "timeout_seconds": 300,
                "artifacts_path": "dist",
            },
            "twine": {
                "enabled": True,
                "executable": "twine",
                "timeout_seconds": 300,
                "artifacts_path": "dist",
            },
            "pypi-attestations": {
                "enabled": True,
                "executable": "pypi-attestations",
                "timeout_seconds": 300,
                "artifacts_path": "dist",
                "provenance_path": "dist",
                "database_path": None,
                "repository_url": "",
            },
            "cosign": {
                "enabled": True,
                "executable": "cosign",
                "timeout_seconds": 300,
                "artifacts_path": "dist",
                "provenance_path": "dist",
                "database_path": None,
                "public_key_path": None,
                "certificate_identity": "",
                "certificate_oidc_issuer": "",
            },
            "scorecard": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "scorecard.json",
            },
            "conftest": {
                "enabled": True,
                "executable": "conftest",
                "timeout_seconds": 600,
                "rules_path": None,
            },
            "kics": {
                "enabled": True,
                "executable": "kics",
                "timeout_seconds": 1200,
                "rules_path": None,
            },
            "pipdeptree": {
                "enabled": True,
                "executable": "pipdeptree",
                "timeout_seconds": 300,
                "auxiliary_executable": "",
            },
            "git-sizer": {
                "enabled": True,
                "executable": "git-sizer",
                "timeout_seconds": 600,
            },
            "validate-pyproject": {
                "enabled": True,
                "executable": "validate-pyproject",
                "timeout_seconds": 300,
            },
            "vale": {
                "enabled": True,
                "executable": "vale",
                "timeout_seconds": 600,
                "rules_path": None,
            },
            "kube-linter": {
                "enabled": True,
                "executable": "kube-linter",
                "timeout_seconds": 600,
            },
            "crosshair": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "crosshair.json",
            },
            "atheris": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "atheris.json",
            },
            "mutmut": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "mutmut.json",
            },
            "check-manifest": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "check-manifest.json",
            },
            "clamav": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "clamav.json",
            },
            "github-attestation": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "github-attestation.json",
            },
            "zap": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "zap.json",
            },
            "pytm": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "pytm.json",
            },
            "in-toto": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "in-toto.json",
            },
            "reproducible-build": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "reproducible-build.json",
            },
            "oci-image": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "oci-image.json",
            },
            "yara": {
                "enabled": True,
                "executable": "pysec-evidence",
                "timeout_seconds": 60,
                "artifacts_path": "yara.json",
            },
        },
    }


def _deep_merge(base: dict[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _deep_merge(dict(result[key]), value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _load_toml(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        resolved = resolve_regular_file(path, "configuration file")
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc
    try:
        with resolved.open("rb") as handle:
            value = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigurationError(f"invalid TOML in {resolved}: {exc}") from exc
    return value


def _ensure_known(mapping: Mapping[str, Any]) -> None:
    top = {
        "schema_version",
        "profile",
        "isolation",
        "execution",
        "policy",
        "reports",
        "intelligence",
        "trust",
        "tools",
    }
    sections = {
        "isolation": {"network", "require_attestation", "execute_target_code"},
        "execution": {"max_workers", "max_output_bytes"},
        "policy": {
            "required_scanners",
            "block_severities",
            "incomplete_is_blocking",
            "risk_acceptance_path",
            "risk_acceptance_sha256",
        },
        "reports": {
            "include_sanitized_evidence",
            "baseline_path",
            "baseline_sha256",
        },
        "intelligence": {
            "kev_path",
            "kev_sha256",
            "epss_path",
            "epss_sha256",
            "vex_path",
            "vex_sha256",
            "maximum_age_days",
            "epss_high_probability",
            "epss_high_percentile",
        },
        "trust": {"catalog_path", "catalog_sha256"},
    }
    unknown = set(mapping) - top
    if unknown:
        raise ConfigurationError(f"unknown top-level settings: {sorted(unknown)}")
    for section, allowed in sections.items():
        value = mapping.get(section, {})
        if not isinstance(value, Mapping):
            raise ConfigurationError(f"[{section}] must be a table")
        extra = set(value) - allowed
        if extra:
            raise ConfigurationError(
                f"unknown settings in [{section}]: {sorted(extra)}"
            )
    tools = mapping.get("tools", {})
    if not isinstance(tools, Mapping):
        raise ConfigurationError("[tools] must be a table")
    allowed_tool_keys = {
        "enabled",
        "executable",
        "timeout_seconds",
        "rules_path",
        "database_path",
        "artifacts_path",
        "provenance_path",
        "auxiliary_executable",
        "repository_url",
        "executable_sha256",
        "auxiliary_executable_sha256",
        "minimum_coverage_percent",
        "maximum_database_age_days",
        "compare_branch",
        "public_key_path",
        "certificate_identity",
        "certificate_oidc_issuer",
        "minimum_island_loc",
        "entry_points",
        "source_roots",
        "discover_framework_roots",
        "coverage_path",
    }
    for name, value in tools.items():
        if name not in SUPPORTED_TOOLS:
            raise ConfigurationError(f"unknown tool: {name}")
        if not isinstance(value, Mapping):
            raise ConfigurationError(f"[tools.{name}] must be a table")
        extra = set(value) - allowed_tool_keys
        if extra:
            raise ConfigurationError(
                f"unknown settings in [tools.{name}]: {sorted(extra)}"
            )


def _reject_weaker_repository_policy(
    organization: Mapping[str, Any], repository: Mapping[str, Any]
) -> None:
    _reject_weaker_isolation(
        organization.get("isolation", {}), repository.get("isolation", {})
    )
    _reject_weaker_policy_settings(
        organization.get("policy", {}), repository.get("policy", {})
    )
    _reject_weaker_evidence_settings(
        organization.get("intelligence", {}),
        repository.get("intelligence", {}),
        section="intelligence",
        digests=("kev_sha256", "epss_sha256", "vex_sha256"),
    )
    _reject_weaker_evidence_settings(
        organization.get("reports", {}),
        repository.get("reports", {}),
        section="reports",
        digests=("baseline_sha256",),
    )
    _reject_weaker_evidence_settings(
        organization.get("trust", {}),
        repository.get("trust", {}),
        section="trust",
        digests=("catalog_sha256",),
    )
    _reject_weaker_tool_settings(
        organization.get("tools", {}), repository.get("tools", {})
    )


def _reject_weaker_isolation(
    organization: Mapping[str, Any], repository: Mapping[str, Any]
) -> None:
    if (
        organization.get("network") == "deny"
        and repository.get("network", "deny") != "deny"
    ):
        raise ConfigurationError(
            "repository configuration cannot weaken network denial"
        )
    if (
        organization.get("execute_target_code") is False
        and repository.get("execute_target_code", False) is not False
    ):
        raise ConfigurationError(
            "repository configuration cannot enable target code execution"
        )
    if (
        organization.get("require_attestation") is True
        and repository.get("require_attestation", True) is not True
    ):
        raise ConfigurationError(
            "repository configuration cannot disable isolation attestation"
        )


def _reject_weaker_policy_settings(
    organization: Mapping[str, Any], repository: Mapping[str, Any]
) -> None:
    org_required = set(organization.get("required_scanners", []))
    if "required_scanners" in repository:
        repo_required = set(repository["required_scanners"])
        if not org_required.issubset(repo_required):
            raise ConfigurationError(
                "repository required_scanners must include every organization-required scanner"
            )
    org_block = set(organization.get("block_severities", []))
    if "block_severities" in repository:
        repo_block = set(repository["block_severities"])
        if not org_block.issubset(repo_block):
            raise ConfigurationError(
                "repository block_severities cannot weaken organization policy"
            )
    if (
        organization.get("incomplete_is_blocking") is True
        and repository.get("incomplete_is_blocking", True) is not True
    ):
        raise ConfigurationError(
            "repository configuration cannot make incomplete scans non-blocking"
        )
    approved_acceptance = str(organization.get("risk_acceptance_sha256") or "").lower()
    if (
        approved_acceptance
        and "risk_acceptance_sha256" in repository
        and str(repository.get("risk_acceptance_sha256") or "").lower()
        != approved_acceptance
    ):
        raise ConfigurationError(
            "repository configuration cannot change the approved risk_acceptance_sha256"
        )


def _reject_weaker_tool_settings(organization: object, repository: object) -> None:
    if isinstance(organization, Mapping) and isinstance(repository, Mapping):
        for name, org_tool in organization.items():
            if not isinstance(org_tool, Mapping):
                continue
            repo_tool = repository.get(name, {})
            if not isinstance(repo_tool, Mapping):
                continue
            for setting in (
                "executable_sha256",
                "auxiliary_executable_sha256",
            ):
                approved = str(org_tool.get(setting) or "").lower()
                if (
                    approved
                    and setting in repo_tool
                    and str(repo_tool.get(setting) or "").lower() != approved
                ):
                    raise ConfigurationError(
                        f"repository configuration cannot change the approved "
                        f"{name} {setting}"
                    )
            if name == "coverage" and "minimum_coverage_percent" in repo_tool:
                try:
                    organization_minimum = float(
                        org_tool.get("minimum_coverage_percent", 0.0)
                    )
                    repository_minimum = float(repo_tool["minimum_coverage_percent"])
                except (TypeError, ValueError) as exc:
                    raise ConfigurationError(
                        "minimum_coverage_percent must be numeric"
                    ) from exc
                if repository_minimum < organization_minimum:
                    raise ConfigurationError(
                        "repository configuration cannot lower the organization "
                        "minimum coverage percent"
                    )
            if name == "reachability":
                _reject_weaker_reachability(org_tool, repo_tool)


def _reject_weaker_reachability(
    organization: Mapping[str, Any], repository: Mapping[str, Any]
) -> None:
    if "minimum_island_loc" in repository:
        try:
            organization_threshold = int(organization.get("minimum_island_loc", 100))
            repository_threshold = int(repository["minimum_island_loc"])
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                "reachability minimum_island_loc must be an integer"
            ) from exc
        if repository_threshold > organization_threshold:
            raise ConfigurationError(
                "repository configuration cannot raise the organization "
                "reachability minimum_island_loc"
            )
    organization_roots = set(organization.get("entry_points", []))
    if "entry_points" in repository and not organization_roots.issubset(
        set(repository["entry_points"])
    ):
        raise ConfigurationError(
            "repository reachability entry_points must include every "
            "organization-required root"
        )
    organization_sources = set(organization.get("source_roots", []))
    if "source_roots" in repository and not organization_sources.issubset(
        set(repository["source_roots"])
    ):
        raise ConfigurationError(
            "repository reachability source_roots must include every "
            "organization-required source root"
        )
    if (
        organization.get("discover_framework_roots") is True
        and repository.get("discover_framework_roots", True) is not True
    ):
        raise ConfigurationError(
            "repository configuration cannot disable framework root discovery"
        )
    organization_coverage = organization.get("coverage_path")
    if (
        organization_coverage
        and "coverage_path" in repository
        and repository.get("coverage_path") != organization_coverage
    ):
        raise ConfigurationError(
            "repository configuration cannot replace the organization reachability "
            "coverage_path"
        )


def _reject_weaker_evidence_settings(
    organization: object,
    repository: object,
    *,
    section: str,
    digests: tuple[str, ...],
) -> None:
    if not isinstance(organization, Mapping) or not isinstance(repository, Mapping):
        return
    for setting in digests:
        approved = str(organization.get(setting) or "").lower()
        supplied = str(repository.get(setting) or "").lower()
        if approved and setting in repository and supplied != approved:
            raise ConfigurationError(
                f"repository configuration cannot change the approved "
                f"{section}.{setting}"
            )


def _to_config(mapping: Mapping[str, Any]) -> SuiteConfig:
    profile = str(mapping["profile"])
    if profile not in PROFILE_TOOLS:
        raise ConfigurationError(
            f"unsupported profile {profile!r}; choose from {sorted(PROFILE_TOOLS)}"
        )
    if str(mapping["schema_version"]) != "1":
        raise ConfigurationError("only configuration schema_version '1' is supported")

    isolation = _isolation_config(mapping["isolation"])
    execution = _execution_config(mapping["execution"])
    policy = _policy_config(mapping["policy"], profile)
    reports = _reports_config(mapping["reports"])
    intelligence = _intelligence_config(mapping["intelligence"])
    trust = _trust_config(mapping["trust"])
    tool_configs = _tool_configs(mapping["tools"])
    _validate_required_tools(
        policy.required_scanners or PROFILE_TOOLS[profile], tool_configs
    )

    return SuiteConfig(
        schema_version="1",
        profile=profile,
        isolation=isolation,
        execution=execution,
        policy=policy,
        reports=reports,
        intelligence=intelligence,
        trust=trust,
        tools=tool_configs,
    )


def _isolation_config(data: Mapping[str, Any]) -> IsolationConfig:
    config = IsolationConfig(
        network=str(data["network"]),
        require_attestation=bool(data["require_attestation"]),
        execute_target_code=bool(data["execute_target_code"]),
    )
    if config.network != "deny":
        raise ConfigurationError("the current release only supports network = 'deny'")
    if config.execute_target_code:
        raise ConfigurationError("scanner profiles cannot execute target project code")
    return config


def _execution_config(data: Mapping[str, Any]) -> ExecutionConfig:
    try:
        config = ExecutionConfig(
            max_workers=int(data["max_workers"]),
            max_output_bytes=int(data["max_output_bytes"]),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("execution limits must be integers") from exc
    if not 1 <= config.max_workers <= 16:
        raise ConfigurationError("execution.max_workers must be between 1 and 16")
    if config.max_output_bytes < 1024:
        raise ConfigurationError("execution.max_output_bytes must be at least 1024")
    return config


def _policy_config(data: Mapping[str, Any], profile: str) -> PolicyConfig:
    try:
        block_severities = tuple(
            Severity(str(value).lower()) for value in data["block_severities"]
        )
    except ValueError as exc:
        raise ConfigurationError(f"invalid policy severity: {exc}") from exc
    if profile in {"production", "release"} and Severity.MEDIUM not in block_severities:
        block_severities = (*block_severities, Severity.MEDIUM)
    acceptance = data.get("risk_acceptance_path")
    acceptance_sha256 = str(data.get("risk_acceptance_sha256") or "").lower()
    _validate_digest("policy", "risk_acceptance_sha256", acceptance_sha256)
    return PolicyConfig(
        required_scanners=tuple(str(value) for value in data["required_scanners"]),
        block_severities=block_severities,
        incomplete_is_blocking=bool(data["incomplete_is_blocking"]),
        risk_acceptance_path=(
            Path(str(acceptance)).expanduser() if acceptance else None
        ),
        risk_acceptance_sha256=acceptance_sha256,
    )


def _reports_config(data: Mapping[str, Any]) -> ReportsConfig:
    baseline = data.get("baseline_path")
    baseline_sha256 = str(data.get("baseline_sha256") or "").lower()
    _validate_digest("reports", "baseline_sha256", baseline_sha256)
    if bool(baseline) != bool(baseline_sha256):
        raise ConfigurationError(
            "reports.baseline_path and reports.baseline_sha256 must be configured together"
        )
    return ReportsConfig(
        include_sanitized_evidence=bool(data["include_sanitized_evidence"]),
        baseline_path=Path(str(baseline)).expanduser() if baseline else None,
        baseline_sha256=baseline_sha256,
    )


def _intelligence_config(data: Mapping[str, Any]) -> IntelligenceConfig:
    paths = {
        name: Path(str(data[name])).expanduser() if data.get(name) else None
        for name in ("kev_path", "epss_path", "vex_path")
    }
    digests = {
        name: str(data.get(name) or "").lower()
        for name in ("kev_sha256", "epss_sha256", "vex_sha256")
    }
    for setting, value in digests.items():
        _validate_digest("intelligence", setting, value)
    for prefix in ("kev", "epss", "vex"):
        if bool(paths[f"{prefix}_path"]) != bool(digests[f"{prefix}_sha256"]):
            raise ConfigurationError(
                f"intelligence.{prefix}_path and intelligence.{prefix}_sha256 "
                "must be configured together"
            )
    try:
        config = IntelligenceConfig(
            kev_path=paths["kev_path"],
            kev_sha256=digests["kev_sha256"],
            epss_path=paths["epss_path"],
            epss_sha256=digests["epss_sha256"],
            vex_path=paths["vex_path"],
            vex_sha256=digests["vex_sha256"],
            maximum_age_days=float(data["maximum_age_days"]),
            epss_high_probability=float(data["epss_high_probability"]),
            epss_high_percentile=float(data["epss_high_percentile"]),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("intelligence numeric settings are invalid") from exc
    if not 0.1 <= config.maximum_age_days <= 3650.0:
        raise ConfigurationError(
            "intelligence.maximum_age_days must be between 0.1 and 3650"
        )
    for threshold_name, threshold_value in (
        ("epss_high_probability", config.epss_high_probability),
        ("epss_high_percentile", config.epss_high_percentile),
    ):
        if not 0.0 <= threshold_value <= 1.0:
            raise ConfigurationError(
                f"intelligence.{threshold_name} must be between 0 and 1"
            )
    return config


def _trust_config(data: Mapping[str, Any]) -> TrustConfig:
    path = data.get("catalog_path")
    digest = str(data.get("catalog_sha256") or "").lower()
    _validate_digest("trust", "catalog_sha256", digest)
    if bool(path) != bool(digest):
        raise ConfigurationError(
            "trust.catalog_path and trust.catalog_sha256 must be configured together"
        )
    return TrustConfig(
        catalog_path=Path(str(path)).expanduser() if path else None,
        catalog_sha256=digest,
    )


def _tool_configs(data: Mapping[str, Any]) -> dict[str, ToolConfig]:
    return {name: _tool_config(name, value) for name, value in data.items()}


def _tool_config(name: str, data: Mapping[str, Any]) -> ToolConfig:
    rules = data.get("rules_path")
    database = data.get("database_path")
    artifacts = data.get("artifacts_path")
    provenance = data.get("provenance_path")
    public_key = data.get("public_key_path")
    coverage_path = data.get("coverage_path")
    entry_points = data.get("entry_points", [])
    source_roots = data.get("source_roots", [])
    if not isinstance(entry_points, (list, tuple)) or not isinstance(
        source_roots, (list, tuple)
    ):
        raise ConfigurationError(f"{name} entry_points and source_roots must be arrays")
    if not isinstance(data.get("discover_framework_roots", True), bool):
        raise ConfigurationError(
            f"{name} discover_framework_roots must be true or false"
        )
    try:
        timeout = int(data["timeout_seconds"])
        coverage_minimum = float(data.get("minimum_coverage_percent", 80.0))
        database_maximum_age = float(data.get("maximum_database_age_days", 10.0))
        minimum_island_loc = int(data.get("minimum_island_loc", 100))
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"{name} numeric settings are invalid") from exc
    config = ToolConfig(
        enabled=bool(data["enabled"]),
        executable=str(data["executable"]),
        timeout_seconds=timeout,
        rules_path=Path(rules).expanduser() if rules else None,
        database_path=Path(database).expanduser() if database else None,
        artifacts_path=Path(artifacts).expanduser() if artifacts else None,
        provenance_path=Path(provenance).expanduser() if provenance else None,
        auxiliary_executable=str(data.get("auxiliary_executable") or ""),
        repository_url=str(data.get("repository_url") or ""),
        executable_sha256=str(data.get("executable_sha256") or "").lower(),
        auxiliary_executable_sha256=str(
            data.get("auxiliary_executable_sha256") or ""
        ).lower(),
        minimum_coverage_percent=coverage_minimum,
        maximum_database_age_days=database_maximum_age,
        compare_branch=str(data.get("compare_branch") or ""),
        public_key_path=Path(public_key).expanduser() if public_key else None,
        certificate_identity=str(data.get("certificate_identity") or ""),
        certificate_oidc_issuer=str(data.get("certificate_oidc_issuer") or ""),
        minimum_island_loc=minimum_island_loc,
        entry_points=tuple(str(value) for value in entry_points),
        source_roots=tuple(str(value) for value in source_roots),
        discover_framework_roots=bool(data.get("discover_framework_roots", True)),
        coverage_path=Path(coverage_path).expanduser() if coverage_path else None,
    )
    _validate_tool_config(name, config)
    return config


def _validate_tool_config(name: str, config: ToolConfig) -> None:
    if config.timeout_seconds < 1:
        raise ConfigurationError(f"{name} timeout_seconds must be positive")
    _validate_digest(name, "executable_sha256", config.executable_sha256)
    _validate_digest(
        name,
        "auxiliary_executable_sha256",
        config.auxiliary_executable_sha256,
    )
    if not 0.0 <= config.minimum_coverage_percent <= 100.0:
        raise ConfigurationError(
            f"{name} minimum_coverage_percent must be between 0 and 100"
        )
    if not 1 <= config.minimum_island_loc <= 1_000_000:
        raise ConfigurationError(
            f"{name} minimum_island_loc must be between 1 and 1000000"
        )
    for setting, values in (
        ("entry_points", config.entry_points),
        ("source_roots", config.source_roots),
    ):
        if len(values) > 256 or any(
            not value.strip() or len(value) > 500 for value in values
        ):
            raise ConfigurationError(f"{name} {setting} contains invalid values")
    if not 0.1 <= config.maximum_database_age_days <= 3650.0:
        raise ConfigurationError(
            f"{name} maximum_database_age_days must be between 0.1 and 3650"
        )


def _validate_digest(name: str, setting: str, value: str) -> None:
    if value and re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ConfigurationError(
            f"{name} {setting} must be exactly 64 hexadecimal characters"
        )


def _validate_required_tools(
    required: tuple[str, ...], tool_configs: Mapping[str, ToolConfig]
) -> None:
    for required_tool in required:
        if required_tool not in SUPPORTED_TOOLS:
            raise ConfigurationError(f"unsupported required scanner: {required_tool}")
        if not tool_configs[required_tool].enabled:
            raise ConfigurationError(
                f"required scanner {required_tool!r} cannot be disabled"
            )


def load_config(
    *,
    organization_policy: Path | None = None,
    repository_config: Path | None = None,
    profile_override: str | None = None,
) -> SuiteConfig:
    defaults = _default_mapping()
    organization = _load_toml(organization_policy)
    repository = _load_toml(repository_config)
    _ensure_known(organization)
    _ensure_known(repository)
    protected_base = _deep_merge(defaults, organization)
    _reject_weaker_repository_policy(protected_base, repository)
    merged = _deep_merge(protected_base, repository)
    if profile_override is not None:
        merged["profile"] = profile_override
        if not merged["policy"]["required_scanners"]:
            merged["policy"]["required_scanners"] = []
    return _to_config(merged)
