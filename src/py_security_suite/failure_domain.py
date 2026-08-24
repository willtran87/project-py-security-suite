from __future__ import annotations

_FIELDS = {
    "organization",
    "host_identity_sha256",
    "control_plane_sha256",
    "implementation_sha256",
}


def verify_failure_domain(value: object, label: str) -> dict[str, str]:
    """Validate one deployment-owned authority failure-domain identity."""

    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError(f"{label} failure-domain fields do not match")
    normalized = {name: str(value[name]).strip().casefold() for name in _FIELDS}
    if not normalized["organization"] or any(
        not _digest(normalized[name])
        for name in (
            "host_identity_sha256",
            "control_plane_sha256",
            "implementation_sha256",
        )
    ):
        raise ValueError(f"{label} failure-domain identity is invalid")
    return normalized


def require_independent_failure_domains(
    first: object, second: object, *, labels: tuple[str, str]
) -> tuple[dict[str, str], dict[str, str]]:
    """Require organizational, host, control-plane, and implementation diversity."""

    left = verify_failure_domain(first, labels[0])
    right = verify_failure_domain(second, labels[1])
    if any(left[name] == right[name] for name in _FIELDS):
        raise ValueError(
            f"{labels[0]} and {labels[1]} do not span independent failure domains"
        )
    return left, right


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
