from __future__ import annotations

import copy
import tomllib
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping

from .models import Severity


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
    ),
    "comprehensive": (
        "bandit",
        "semgrep",
        "detect-secrets",
        "osv-scanner",
        "cyclonedx-py",
        "ruff",
        "zizmor",
        "pysa",
        "trivy",
        "guarddog",
        "scancode",
        "gitleaks",
        "trufflehog",
        "codeql",
        "syft",
        "grype",
        "check-wheel-contents",
        "twine",
        "pypi-attestations",
    ),
    "production": (
        "bandit",
        "semgrep",
        "detect-secrets",
        "osv-scanner",
        "cyclonedx-py",
        "ruff",
        "zizmor",
        "pysa",
        "trivy",
        "guarddog",
        "scancode",
        "gitleaks",
        "trufflehog",
        "codeql",
    ),
    "release": (
        "bandit",
        "semgrep",
        "detect-secrets",
        "osv-scanner",
        "cyclonedx-py",
        "ruff",
        "zizmor",
        "pysa",
        "trivy",
        "guarddog",
        "scancode",
        "gitleaks",
        "trufflehog",
        "codeql",
        "syft",
        "grype",
        "check-wheel-contents",
        "twine",
        "pypi-attestations",
    ),
}

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


@dataclass(slots=True)
class ReportsConfig:
    include_sanitized_evidence: bool = True


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


@dataclass(slots=True)
class SuiteConfig:
    schema_version: str = "1"
    profile: str = "standard"
    isolation: IsolationConfig = field(default_factory=IsolationConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    reports: ReportsConfig = field(default_factory=ReportsConfig)
    tools: dict[str, ToolConfig] = field(default_factory=dict)

    @property
    def selected_tools(self) -> tuple[str, ...]:
        return PROFILE_TOOLS[self.profile]

    @property
    def required_tools(self) -> tuple[str, ...]:
        return self.policy.required_scanners or self.selected_tools


def _default_mapping() -> dict[str, Any]:
    bundled_rules = Path(str(files("py_security_suite").joinpath("rules/python-security.yml")))
    bundled_gitleaks = Path(
        str(files("py_security_suite").joinpath("rules/gitleaks.toml"))
    )
    bundled_trufflehog_excludes = Path(
        str(files("py_security_suite").joinpath("rules/trufflehog-exclude.txt"))
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
        },
        "reports": {"include_sanitized_evidence": True},
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
            "zizmor": {
                "enabled": True,
                "executable": "zizmor",
                "timeout_seconds": 300,
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
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ConfigurationError(f"configuration file does not exist: {resolved}")
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
        "tools",
    }
    sections = {
        "isolation": {"network", "require_attestation", "execute_target_code"},
        "execution": {"max_workers", "max_output_bytes"},
        "policy": {
            "required_scanners",
            "block_severities",
            "incomplete_is_blocking",
        },
        "reports": {"include_sanitized_evidence"},
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
    org_iso = organization.get("isolation", {})
    repo_iso = repository.get("isolation", {})
    if org_iso.get("network") == "deny" and repo_iso.get("network", "deny") != "deny":
        raise ConfigurationError("repository configuration cannot weaken network denial")
    if (
        org_iso.get("execute_target_code") is False
        and repo_iso.get("execute_target_code", False) is not False
    ):
        raise ConfigurationError(
            "repository configuration cannot enable target code execution"
        )
    if (
        org_iso.get("require_attestation") is True
        and repo_iso.get("require_attestation", True) is not True
    ):
        raise ConfigurationError(
            "repository configuration cannot disable isolation attestation"
        )

    org_policy = organization.get("policy", {})
    repo_policy = repository.get("policy", {})
    org_required = set(org_policy.get("required_scanners", []))
    if "required_scanners" in repo_policy:
        repo_required = set(repo_policy["required_scanners"])
        if not org_required.issubset(repo_required):
            raise ConfigurationError(
                "repository required_scanners must include every organization-required scanner"
            )
    org_block = set(org_policy.get("block_severities", []))
    if "block_severities" in repo_policy:
        repo_block = set(repo_policy["block_severities"])
        if not org_block.issubset(repo_block):
            raise ConfigurationError(
                "repository block_severities cannot weaken organization policy"
            )
    if (
        org_policy.get("incomplete_is_blocking") is True
        and repo_policy.get("incomplete_is_blocking", True) is not True
    ):
        raise ConfigurationError(
            "repository configuration cannot make incomplete scans non-blocking"
        )


def _to_config(mapping: Mapping[str, Any]) -> SuiteConfig:
    profile = str(mapping["profile"])
    if profile not in PROFILE_TOOLS:
        raise ConfigurationError(
            f"unsupported profile {profile!r}; choose from {sorted(PROFILE_TOOLS)}"
        )
    if str(mapping["schema_version"]) != "1":
        raise ConfigurationError("only configuration schema_version '1' is supported")

    isolation_data = mapping["isolation"]
    isolation = IsolationConfig(
        network=str(isolation_data["network"]),
        require_attestation=bool(isolation_data["require_attestation"]),
        execute_target_code=bool(isolation_data["execute_target_code"]),
    )
    if isolation.network != "deny":
        raise ConfigurationError("the current release only supports network = 'deny'")
    if isolation.execute_target_code:
        raise ConfigurationError(
            "scanner profiles cannot execute target project code"
        )

    execution_data = mapping["execution"]
    execution = ExecutionConfig(
        max_workers=int(execution_data["max_workers"]),
        max_output_bytes=int(execution_data["max_output_bytes"]),
    )
    if not 1 <= execution.max_workers <= 16:
        raise ConfigurationError("execution.max_workers must be between 1 and 16")
    if execution.max_output_bytes < 1024:
        raise ConfigurationError("execution.max_output_bytes must be at least 1024")

    policy_data = mapping["policy"]
    try:
        configured_block_severities = tuple(
            Severity(str(value).lower()) for value in policy_data["block_severities"]
        )
    except ValueError as exc:
        raise ConfigurationError(f"invalid policy severity: {exc}") from exc
    block_severities = configured_block_severities
    if profile in {"production", "release"} and Severity.MEDIUM not in block_severities:
        block_severities = (*block_severities, Severity.MEDIUM)
    required = tuple(str(value) for value in policy_data["required_scanners"])
    policy = PolicyConfig(
        required_scanners=required,
        block_severities=block_severities,
        incomplete_is_blocking=bool(policy_data["incomplete_is_blocking"]),
    )

    reports = ReportsConfig(
        include_sanitized_evidence=bool(
            mapping["reports"]["include_sanitized_evidence"]
        )
    )
    tool_configs: dict[str, ToolConfig] = {}
    for name, data in mapping["tools"].items():
        rules = data.get("rules_path")
        database = data.get("database_path")
        artifacts = data.get("artifacts_path")
        provenance = data.get("provenance_path")
        tool_configs[name] = ToolConfig(
            enabled=bool(data["enabled"]),
            executable=str(data["executable"]),
            timeout_seconds=int(data["timeout_seconds"]),
            rules_path=Path(rules).expanduser() if rules else None,
            database_path=Path(database).expanduser() if database else None,
            artifacts_path=Path(artifacts).expanduser() if artifacts else None,
            provenance_path=Path(provenance).expanduser() if provenance else None,
            auxiliary_executable=str(data.get("auxiliary_executable") or ""),
            repository_url=str(data.get("repository_url") or ""),
        )
        if tool_configs[name].timeout_seconds < 1:
            raise ConfigurationError(f"{name} timeout_seconds must be positive")

    for required_tool in required or PROFILE_TOOLS[profile]:
        if required_tool not in SUPPORTED_TOOLS:
            raise ConfigurationError(f"unsupported required scanner: {required_tool}")
        if not tool_configs[required_tool].enabled:
            raise ConfigurationError(
                f"required scanner {required_tool!r} cannot be disabled"
            )

    return SuiteConfig(
        schema_version="1",
        profile=profile,
        isolation=isolation,
        execution=execution,
        policy=policy,
        reports=reports,
        tools=tool_configs,
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
