from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import ToolRun, ToolStatus
from .assurance_profile import verify_governance_quorum
from .execution import sha256_file
from .path_safety import read_regular_file
from .strict_json import canonical_bytes, loads as strict_loads


def security_requirements_coverage_artifact(
    boundary_graph: dict[str, Any],
    tool_runs: list[ToolRun],
    artifacts: dict[str, Any],
) -> dict[str, Any]:
    """Map exact, versioned external requirements to retained suite evidence."""
    languages = set((boundary_graph.get("languages") or {}).keys())
    edges = boundary_graph.get("edges") or []
    successful_tools = {
        run.tool for run in tool_runs if run.status == ToolStatus.COMPLETED
    }
    web = any(
        isinstance(edge, dict) and edge.get("kind") == "network-endpoint"
        for edge in edges
    ) or any(
        isinstance(file, dict)
        and str(file.get("path") or "")
        .casefold()
        .endswith(("openapi.json", "openapi.yaml", "openapi.yml"))
        for file_set in (boundary_graph.get("language_file_sets") or {}).values()
        if isinstance(file_set, dict)
        for file in (file_set.get("files") or [])
    )
    mobile = "mobsf-summary.json" in artifacts or bool({"kotlin", "swift"} & languages)
    thick_client = bool({"c", "cpp", "csharp", "rust"} & languages) and not mobile
    records: list[dict[str, Any]] = []

    def add(
        standard: str,
        version: str,
        requirement: str,
        applicable: bool,
        evidence: list[str],
        verification_scope: str,
    ) -> None:
        retained = sorted(set(evidence)) if applicable else []
        records.append(
            {
                "standard": standard,
                "version": version,
                "requirement": requirement,
                "applicable": applicable,
                "status": (
                    "evidence-collected"
                    if applicable and retained
                    else "gap"
                    if applicable
                    else "not-applicable"
                ),
                "verification_scope": verification_scope,
                "evidence": retained,
            }
        )

    sast = sorted({name for name in ("bandit", "semgrep") if name in successful_tools})
    add(
        "OWASP-ASVS",
        "5.0.0",
        "v5.0.0-1.2.5",
        web,
        [
            *sast,
            *(
                ["semantic-language-coverage.json"]
                if "semantic-language-coverage.json" in artifacts
                else []
            ),
        ],
        "OS command-injection static and semantic evidence; manual runtime verification remains required",
    )
    add(
        "OWASP-MASVS",
        "2.1.0",
        "MASVS-CODE-3",
        mobile,
        [
            name
            for name in (
                "sbom.cdx.json",
                "dependency-surface.json",
                "mobsf-summary.json",
            )
            if name in artifacts
        ],
        "known-vulnerable mobile component inventory",
    )
    add(
        "OWASP-MASVS",
        "2.1.0",
        "MASVS-CODE-4",
        mobile,
        [*sast, *(["mobsf-summary.json"] if "mobsf-summary.json" in artifacts else [])],
        "untrusted-input static and mobile analysis",
    )
    add(
        "OWASP-TCASVS",
        "5.0.0",
        "V4.6.3",
        thick_client,
        sast,
        "release-candidate SAST execution",
    )
    add(
        "OWASP-TCASVS",
        "5.0.0",
        "V4.6.5",
        thick_client,
        [
            name
            for name in ("reachability.json", "deptry-dependencies.json")
            if name in artifacts
        ],
        "dead-code, unreachable-code, and unused-dependency analysis",
    )
    add(
        "OWASP-TCASVS",
        "5.0.0",
        "V4.6.6",
        thick_client,
        [
            name
            for name in ("atheris-summary.json", "clusterfuzzlite-summary.json")
            if name in artifacts
        ],
        "mutation-based parser, protocol, and IPC fuzzing",
    )
    applicable = [record for record in records if record["applicable"]]
    gaps = [record["requirement"] for record in applicable if record["status"] == "gap"]
    catalogs: list[dict[str, Any]] = [
        {
            "standard": "OWASP-ASVS",
            "version": "5.0.0",
            "source": "https://github.com/OWASP/ASVS/tree/936f29673daa69fe90e6fa706011f89aef201988/5.0/en",
            "source_revision": "936f29673daa69fe90e6fa706011f89aef201988",
            "catalog_sha256": "5cbaa260b0f6386096a2ba5e066c1843efc32abb2c4e1f52609cacd7c6d219da",
            "requirements_in_catalog": 345,
            "requirements_mapped": 1,
        },
        {
            "standard": "OWASP-MASVS",
            "version": "2.1.0",
            "source": "https://github.com/OWASP/masvs/tree/8e133d09f4140518ed04cc254b18be9ff4990ffc/controls",
            "source_revision": "8e133d09f4140518ed04cc254b18be9ff4990ffc",
            "catalog_sha256": "f5b769e80fcdd0bdb431d907fd4787684f521efb7a488d4abd0751d8194bc4be",
            "requirements_in_catalog": None,
            "requirements_mapped": 2,
        },
        {
            "standard": "OWASP-TCASVS",
            "version": "5.0.0",
            "source": "https://github.com/OWASP/TCASVS/tree/66d534f223c992882f25ac192d10f16f0779cc4a/5.0/en",
            "source_revision": "66d534f223c992882f25ac192d10f16f0779cc4a",
            "catalog_sha256": None,
            "requirements_in_catalog": None,
            "requirements_mapped": 3,
        },
    ]
    organization_approved = False
    policy = _organization_requirements_policy()
    if policy is not None:
        applicability_flags = policy["applicability"]
        web = applicability_flags["web_or_api"]
        mobile = applicability_flags["mobile"]
        thick_client = applicability_flags["thick_client"]
        available_evidence = successful_tools | set(artifacts)
        records = []
        for item in policy["requirements"]:
            evidence = sorted(set(item["evidence"])) if item["applicable"] else []
            collected = (
                item["applicable"]
                and bool(evidence)
                and set(evidence).issubset(available_evidence)
            )
            records.append(
                {
                    **item,
                    "status": (
                        "evidence-collected"
                        if collected
                        else "gap"
                        if item["applicable"]
                        else "not-applicable"
                    ),
                    "evidence": evidence,
                }
            )
        mapped = {(item["standard"], item["version"]): 0 for item in policy["catalogs"]}
        for item in records:
            mapped[(item["standard"], item["version"])] += 1
        catalogs = [
            {
                **item,
                "requirements_mapped": mapped[(item["standard"], item["version"])],
            }
            for item in policy["catalogs"]
        ]
        organization_approved = True
    applicable = [record for record in records if record["applicable"]]
    gaps = [record["requirement"] for record in applicable if record["status"] == "gap"]
    automation_complete = not gaps
    full_catalog_coverage = all(
        isinstance(item["requirements_in_catalog"], int)
        and item["requirements_mapped"] == item["requirements_in_catalog"]
        for item in catalogs
    )
    subject = {
        "schema_version": "1.0",
        "analysis": "versioned-security-requirements-evidence-crosswalk",
        "applicability": {
            "web_or_api": web,
            "mobile": mobile,
            "thick_client": thick_client,
        },
        "requirements": records,
        "catalogs": catalogs,
        "applicability_decision": {
            "basis": (
                "threshold-signed-requirement-level-policy"
                if organization_approved
                else "bounded-source-heuristics"
            ),
            "organization_approved": organization_approved,
            "requires_owner_review": not organization_approved,
        },
        "applicable_requirements": len(applicable),
        "evidenced_requirements": sum(
            record["status"] == "evidence-collected" for record in applicable
        ),
        "gaps": sorted(gaps),
        "automation_complete": automation_complete,
        "full_catalog_coverage": full_catalog_coverage,
        "complete": automation_complete
        and full_catalog_coverage
        and organization_approved,
        "limitations": [
            "Evidence-collected is not a claim of standards conformance; each requirement still needs a requirement-specific pass/fail assessment.",
            "Full catalog coverage and organization-approved applicability are required before this artifact can become complete.",
        ],
    }
    return {
        **subject,
        "crosswalk_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
    }


def _organization_requirements_policy() -> dict[str, Any] | None:
    raw_path = os.environ.get("PYSEC_REQUIREMENTS_POLICY_PATH", "").strip()
    expected_digest = (
        os.environ.get("PYSEC_REQUIREMENTS_POLICY_SHA256", "").strip().casefold()
    )
    if not raw_path and not expected_digest:
        return None
    if (
        not raw_path
        or len(expected_digest) != 64
        or any(character not in "0123456789abcdef" for character in expected_digest)
    ):
        raise ValueError("organization requirements policy configuration is incomplete")
    path = Path(raw_path).expanduser().resolve()
    if sha256_file(path) != expected_digest:
        raise ValueError("organization requirements policy SHA-256 does not match")
    _, payload = read_regular_file(
        path, "organization requirements policy", maximum_bytes=16 * 1024 * 1024
    )
    value = strict_loads(payload)
    required = {
        "schema_version",
        "applicability",
        "catalogs",
        "requirements",
        "minimum_authority_signatures",
        "authorities",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
    ):
        raise ValueError("organization requirements policy fields do not match")
    applicability = value.get("applicability")
    if (
        not isinstance(applicability, dict)
        or set(applicability)
        != {
            "web_or_api",
            "mobile",
            "thick_client",
        }
        or any(not isinstance(item, bool) for item in applicability.values())
    ):
        raise ValueError("organization requirements applicability is invalid")
    catalogs = _policy_catalogs(value.get("catalogs"))
    requirements = _policy_requirements(value.get("requirements"), catalogs)
    threshold = value.get("minimum_authority_signatures")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, int)
        or not 2 <= threshold <= 16
    ):
        raise ValueError("organization requirements authority threshold is invalid")
    subject = {name: value[name] for name in required - {"authorities"}}
    verify_governance_quorum(
        path,
        value.get("authorities"),
        subject,
        threshold,
        datetime.now(UTC),
        purpose="security-requirements-applicability",
    )
    return {
        "applicability": applicability,
        "catalogs": catalogs,
        "requirements": requirements,
    }


def _policy_catalogs(value: object) -> list[dict[str, Any]]:
    required = {
        "standard",
        "version",
        "source",
        "source_revision",
        "catalog_sha256",
        "requirements_in_catalog",
    }
    if not isinstance(value, list) or len(value) != 3:
        raise ValueError("organization requirements catalogs are invalid")
    result: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("organization requirements catalog fields do not match")
        identity = (str(item["standard"]), str(item["version"]))
        count = item["requirements_in_catalog"]
        if (
            identity in identities
            or isinstance(count, bool)
            or not isinstance(count, int)
            or not 1 <= count <= 10_000
        ):
            raise ValueError("organization requirements catalog identity is invalid")
        if (
            not str(item["source"]).startswith("https://")
            or len(str(item["source_revision"])) != 40
            or len(str(item["catalog_sha256"])) != 64
        ):
            raise ValueError("organization requirements catalog provenance is invalid")
        identities.add(identity)
        result.append(dict(item))
    if {identity[0] for identity in identities} != {
        "OWASP-ASVS",
        "OWASP-MASVS",
        "OWASP-TCASVS",
    }:
        raise ValueError(
            "organization requirements policy must cover ASVS, MASVS, and TCASVS"
        )
    return result


def _policy_requirements(
    value: object, catalogs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    fields = {
        "standard",
        "version",
        "requirement",
        "applicable",
        "verification_scope",
        "evidence",
    }
    if not isinstance(value, list) or not 1 <= len(value) <= 10_000:
        raise ValueError("organization requirements decisions are invalid")
    catalog_counts = {
        (item["standard"], item["version"]): item["requirements_in_catalog"]
        for item in catalogs
    }
    result: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str]] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("organization requirement decision fields do not match")
        identity = (
            str(item["standard"]),
            str(item["version"]),
            str(item["requirement"]),
        )
        evidence = item["evidence"]
        if (
            identity in identities
            or identity[:2] not in catalog_counts
            or not isinstance(item["applicable"], bool)
            or not isinstance(evidence, list)
            or len(evidence) > 100
            or any(not isinstance(name, str) or not name for name in evidence)
        ):
            raise ValueError("organization requirement decision is invalid")
        identities.add(identity)
        result.append(dict(item))
    observed_counts: dict[tuple[str, str], int] = {key: 0 for key in catalog_counts}
    for standard, version, _requirement in identities:
        observed_counts[(standard, version)] += 1
    if observed_counts != catalog_counts:
        raise ValueError(
            "organization requirements policy does not cover every catalog requirement"
        )
    return result
