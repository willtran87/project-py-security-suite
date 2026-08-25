from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ActivationGuidance:
    """Structured ownership and closure guidance for a conditional control."""

    category: str
    owner: str
    activation_trigger: str
    required_action: str
    evidence_required: str


def activation_guidance(tool: str, reason: str | None) -> ActivationGuidance:
    """Classify one N/A diagnostic into deterministic, actionable guidance."""
    message = (reason or "").casefold()
    guidance = ActivationGuidance(
        category="content_absent",
        owner="repository-maintainers",
        activation_trigger="Relevant supported repository content is introduced.",
        required_action=(
            "Add the supported content, keep the control enabled, and rerun the "
            "same profile so applicability is recalculated."
        ),
        evidence_required="A completed scanner result in the next sealed report.",
    )
    if "trusted publisher" in message:
        return ActivationGuidance(
            category="release_configuration",
            owner="release-engineering",
            activation_trigger=(
                "A PyPI Trusted Publisher release workflow is configured."
            ),
            required_action=(
                "Configure the reviewed Trusted Publisher identity, publish through "
                "the controlled lane, and attach the digest-bound attestation evidence."
            ),
            evidence_required=(
                "PyPI attestation bound to the exact distribution digest."
            ),
        )
    if "target python environment" in message:
        return ActivationGuidance(
            category="target_environment",
            owner="python-platform",
            activation_trigger="An approved target Python environment is available.",
            required_action=(
                "Configure the immutable target environment path and rerun dependency "
                "health analysis without resolving packages from the network."
            ),
            evidence_required=(
                "Environment identity plus completed dependency-tree evidence."
            ),
        )
    if "openapi schema or pre-generated schemathesis" in message:
        return ActivationGuidance(
            category="companion_evidence",
            owner="application-security",
            activation_trigger=(
                "The project exposes an OpenAPI contract or imported test evidence."
            ),
            required_action=(
                "Stage the reviewed local OpenAPI document or import bounded "
                "Schemathesis evidence from the trusted test lane, bind its digest, "
                "and rerun."
            ),
            evidence_required=(
                "Digest-bound Schemathesis result and input contract identity."
            ),
        )
    if "pre-generated" in message:
        return ActivationGuidance(
            category="companion_evidence",
            owner="application-security",
            activation_trigger=f"Approved {tool} companion evidence is generated.",
            required_action=(
                f"Generate {tool} evidence in its approved isolated companion lane, "
                "import it through the strict evidence contract, and rerun."
            ),
            evidence_required=(
                f"Digest-bound {tool} evidence with producer and subject identity."
            ),
        )
    if any(
        value in message
        for value in (
            "no approved local",
            "not configured",
            "configuration was found",
            "no repository pysa",
        )
    ):
        return ActivationGuidance(
            category="missing_configuration",
            owner="security-policy",
            activation_trigger=f"A reviewed local {tool} configuration is approved.",
            required_action=(
                f"Stage the approved offline {tool} configuration or policy assets, "
                "record their digests, and rerun readiness before scanning."
            ),
            evidence_required="Configuration digest and completed scanner result.",
        )
    if "does not support" in message or "run this profile on" in message:
        return ActivationGuidance(
            category="platform_constraint",
            owner="platform-security",
            activation_trigger="A supported isolated companion platform is available.",
            required_action=(
                f"Run {tool} on the documented supported platform and import its "
                "digest-bound evidence without weakening the native profile."
            ),
            evidence_required=(
                "Platform identity, tool digest, and sealed companion result."
            ),
        )
    return guidance


def readiness_guidance(
    *, tool: str, status: str, reason: str | None
) -> tuple[str, str]:
    """Return the readiness category and operator action for one scanner state."""
    message = (reason or "").casefold()
    if status == "ready":
        return "ready", "No action; execute in the approved isolated scan lane."
    if status == "disabled":
        return (
            "disabled",
            "Enable the scanner or document an organization-approved exception.",
        )
    if "organization approval is missing" in message:
        return (
            "missing_approval",
            "Submit the exact observed primary and auxiliary digests for independent "
            "provenance review and organization approval.",
        )
    if status == "unavailable" and any(
        value in message
        for value in (
            "certificate_identity",
            "certificate_oidc_issuer",
            "database_path is required",
            "not configured",
        )
    ):
        return (
            "missing_configuration",
            "Configure the named approved local path or identity setting and rerun "
            "preflight.",
        )
    if status == "unavailable" and any(
        value in message
        for value in (
            "approved rules are missing",
            "pre-staged",
            "staged offline",
            "staged psscriptanalyzer",
            "staged pyright",
        )
    ):
        return (
            "missing_evidence",
            "Stage the approved offline rules, database, module, or executable asset "
            "and rerun preflight.",
        )
    if status == "unavailable":
        return (
            "unavailable",
            "Install or restore the approved executable and required offline assets.",
        )
    if status != "not_applicable":
        return "attention", "Review the scanner prerequisite state."

    activation = activation_guidance(tool, reason)
    category = {
        "release_configuration": "missing_configuration",
        "target_environment": "missing_configuration",
        "companion_evidence": "missing_evidence",
    }.get(activation.category, activation.category)
    if "openapi schema or pre-generated schemathesis" in message:
        return (
            category,
            "Configure the local OpenAPI schema or generate Schemathesis evidence "
            "in its trusted companion lane, bind its digest, and rerun.",
        )
    action = {
        "release_configuration": (
            "Configure the approved release identity and rerun preflight."
        ),
        "target_environment": (
            "Configure the approved target Python environment and rerun preflight."
        ),
        "companion_evidence": (
            "Generate the named evidence in its trusted companion lane, bind its "
            "digest, and rerun."
        ),
        "missing_configuration": (
            "Configure an approved local policy, environment, or evidence path and "
            "rerun preflight."
        ),
        "platform_constraint": (
            "Run this control on a supported companion platform and import its "
            "digest-bound evidence."
        ),
        "content_absent": (
            "No current action; the control becomes applicable when supported "
            "repository content appears."
        ),
    }[activation.category]
    return category, action
