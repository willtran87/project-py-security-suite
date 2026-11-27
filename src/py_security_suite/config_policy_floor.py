"""Organization-controlled floors for repository-selectable policy settings."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


PRODUCTION_PROFILES = frozenset({"production", "release"})
# (setting, protected organization value, repository default, message)
_PROTECTED_ISOLATION = (
    ("network", "deny", "deny", "weaken network denial"),
    ("execute_target_code", False, False, "enable target code execution"),
    ("require_attestation", True, True, "disable isolation attestation"),
    ("require_evidence", True, True, "disable isolation evidence"),
)


def isolation_settings_error(
    organization: Mapping[str, Any], repository: Mapping[str, Any]
) -> str:
    for setting, protected, default, message in _PROTECTED_ISOLATION:
        if organization.get(setting) == protected and type(
            organization.get(setting)
        ) is type(protected):
            value = repository.get(setting, default)
            if value != protected or type(value) is not type(protected):
                return f"repository configuration cannot {message}"
    return ""


def policy_settings_error(
    organization: Mapping[str, Any], repository: Mapping[str, Any]
) -> str:
    for setting, label in (
        ("required_scanners", "must include every organization-required scanner"),
        ("block_severities", "cannot weaken organization policy"),
    ):
        if setting in repository and not set(organization.get(setting, [])) <= set(
            repository[setting]
        ):
            return f"repository {setting} {label}"
    if (
        organization.get("incomplete_is_blocking") is True
        and repository.get("incomplete_is_blocking", True) is not True
    ):
        return "repository configuration cannot make incomplete scans non-blocking"
    approved = str(organization.get("risk_acceptance_sha256") or "").lower()
    if (
        approved
        and "risk_acceptance_sha256" in repository
        and str(repository.get("risk_acceptance_sha256") or "").lower() != approved
    ):
        return (
            "repository configuration cannot change the approved risk_acceptance_sha256"
        )
    return ""


def profile_floor_error(
    floor: object,
    profile: object,
    profile_tools: Mapping[str, tuple[str, ...]],
) -> str:
    """Return an error when ``profile`` is weaker than the organization ``floor``.

    Production and release carry policy gates beyond their scanner set, so they
    can only be replaced by themselves (or release for production). Other
    profiles may only move to a profile that runs every floor scanner.
    """
    if floor is None or floor == profile:
        return ""
    floor_name, profile_name = str(floor), str(profile)
    if floor_name not in profile_tools or profile_name not in profile_tools:
        return ""  # unsupported names are rejected by profile validation
    if floor_name in PRODUCTION_PROFILES:
        stronger = floor_name == "production" and profile_name == "release"
    else:
        stronger = set(profile_tools[floor_name]) <= set(profile_tools[profile_name])
    if stronger:
        return ""
    return (
        f"profile {profile_name!r} is weaker than the organization-required "
        f"profile {floor_name!r}; repository configuration and --profile may "
        "only raise scan strictness"
    )


def risk_acceptance_authority_error(
    profile: object,
    policy: Mapping[str, Any],
    organization_policy: object,
) -> str:
    """Require an organization-pinned acceptance digest in production/release."""
    if str(profile) not in PRODUCTION_PROFILES or not policy.get(
        "risk_acceptance_path"
    ):
        return ""
    approved = ""
    if isinstance(organization_policy, Mapping):
        approved = str(organization_policy.get("risk_acceptance_sha256") or "")
    configured = str(policy.get("risk_acceptance_sha256") or "")
    if not approved or approved.lower() != configured.lower():
        return (
            "production and release risk_acceptance_path requires a "
            "risk_acceptance_sha256 pinned by the organization policy"
        )
    return ""
