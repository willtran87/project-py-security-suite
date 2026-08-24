from __future__ import annotations

import hashlib
import base64
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import ToolRun, ToolStatus
from .operation_receipt import verify_operation_receipt
from .assurance_profile import verify_governance_quorum
from .deployment_receipt import verify_deployment_receipt
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
                "assessment": None,
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
    evidence_policy: dict[str, Any] | None = None
    evidence_policy_authority: dict[str, Any] | None = None
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
                    "assessment": None,
                }
            )
        assessments, evidence_policy, evidence_policy_authority = (
            _organization_requirement_assessments(policy, artifacts)
        )
        for record in records:
            identity = (
                str(record["standard"]),
                str(record["version"]),
                str(record["requirement"]),
            )
            assessment = assessments.get(identity)
            if assessment is not None:
                record["assessment"] = assessment
                record["status"] = str(assessment["status"])
                record["evidence"] = sorted(
                    {
                        str(name)
                        for assertion in assessment["assertions"]
                        for name in (
                            assertion["artifact"],
                            assertion["execution_artifact"],
                        )
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
    gaps = [
        record["requirement"]
        for record in applicable
        if record["status"] not in {"evidence-collected", "passed"}
    ]
    assessment_complete = bool(applicable) and all(
        record["status"] == "passed" for record in applicable
    )
    automation_complete = not gaps
    full_catalog_coverage = all(
        isinstance(item["requirements_in_catalog"], int)
        and item["requirements_mapped"] == item["requirements_in_catalog"]
        for item in catalogs
    )
    execution_names = sorted(
        {
            str(assertion["execution_artifact"])
            for record in records
            if isinstance(record.get("assessment"), dict)
            for assertion in record["assessment"].get("assertions", [])
            if isinstance(assertion, dict) and assertion.get("execution_artifact")
        }
    )
    procedure_executions = {
        name: artifacts[name] for name in execution_names if name in artifacts
    }
    if len(procedure_executions) != len(execution_names):
        raise ValueError("retained requirement procedure execution is missing")
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
            record["status"] in {"evidence-collected", "passed", "failed"}
            for record in applicable
        ),
        "gaps": sorted(gaps),
        "automation_complete": automation_complete,
        "full_catalog_coverage": full_catalog_coverage,
        "evidence_policy": evidence_policy,
        "evidence_policy_authority_receipt": evidence_policy_authority,
        "procedure_executions": procedure_executions,
        "complete": assessment_complete
        and full_catalog_coverage
        and organization_approved,
        "limitations": [
            "Artifact presence is not a claim of conformance; only deployment-pinned, requirement-specific assertions can establish assessed pass or fail.",
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
    from .trusted_observation import scan_observed_at

    verify_governance_quorum(
        path,
        value.get("authorities"),
        subject,
        threshold,
        scan_observed_at(),
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
            or not _hex_revision(str(item["source_revision"]))
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


def _organization_requirement_assessments(
    policy: dict[str, Any], artifacts: dict[str, Any]
) -> tuple[
    dict[tuple[str, str, str], dict[str, Any]],
    dict[str, Any] | None,
    dict[str, Any] | None,
]:
    raw_path = os.environ.get("PYSEC_REQUIREMENTS_ASSESSMENT_PATH", "").strip()
    expected = (
        os.environ.get("PYSEC_REQUIREMENTS_ASSESSMENT_SHA256", "").strip().casefold()
    )
    if not raw_path and not expected:
        return {}, None, None
    if not raw_path or not _digest(expected):
        raise ValueError(
            "organization requirements assessment configuration is incomplete"
        )
    path = Path(raw_path).expanduser().resolve()
    if sha256_file(path) != expected:
        raise ValueError("organization requirements assessment SHA-256 does not match")
    _, payload = read_regular_file(
        path, "organization requirements assessment", maximum_bytes=32 * 1024 * 1024
    )
    value = strict_loads(payload)
    required = {
        "schema_version",
        "catalogs",
        "assessments",
        "minimum_authority_signatures",
        "authorities",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
    ):
        raise ValueError("organization requirements assessment fields do not match")
    catalogs = _verified_catalog_snapshots(path, value["catalogs"])
    expected_identities = {
        (str(item["standard"]), str(item["version"]), str(item["requirement"]))
        for item in policy["requirements"]
    }
    if expected_identities != {
        (standard, version, requirement)
        for (standard, version), requirements in catalogs.items()
        for requirement in requirements
    }:
        raise ValueError("pinned requirements catalogs do not match the signed policy")
    from .trusted_observation import scan_observed_at

    observed_at = scan_observed_at()
    evidence_policy, raw_evidence_policy, evidence_policy_authority = (
        _assessment_evidence_policy(expected_identities)
    )
    threshold = value["minimum_authority_signatures"]
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, int)
        or not 2 <= threshold <= 16
    ):
        raise ValueError(
            "organization requirements assessment authority threshold is invalid"
        )
    subject = {name: value[name] for name in required - {"authorities"}}
    verify_governance_quorum(
        path,
        value["authorities"],
        subject,
        threshold,
        observed_at,
        purpose="security-requirements-assessment",
    )
    entries = value["assessments"]
    if not isinstance(entries, list) or len(entries) != len(expected_identities):
        raise ValueError("organization requirements assessments are incomplete")
    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    applicability = {
        (
            str(item["standard"]),
            str(item["version"]),
            str(item["requirement"]),
        ): bool(item["applicable"])
        for item in policy["requirements"]
    }
    for item in entries:
        assessment = _requirement_assessment(
            item, artifacts, observed_at, evidence_policy
        )
        identity = assessment.pop("identity")
        if identity not in expected_identities or identity in result:
            raise ValueError("organization requirement assessment identity is invalid")
        applicable = applicability[identity]
        status = str(assessment["result"])
        if applicable == (status == "not-applicable"):
            raise ValueError("requirement assessment applicability is inconsistent")
        assessment["status"] = (
            "passed"
            if status == "pass"
            else "failed"
            if status == "fail"
            else "not-tested"
            if status == "not-tested"
            else "not-applicable"
        )
        result[identity] = assessment
    return result, raw_evidence_policy, evidence_policy_authority


def _verified_catalog_snapshots(
    context: Path, value: object
) -> dict[tuple[str, str], set[str]]:
    if not isinstance(value, list) or len(value) != 3:
        raise ValueError("requirements assessment catalogs are invalid")
    raw_policy = os.environ.get("PYSEC_REQUIREMENTS_CATALOG_SHA256", "")
    try:
        trust_policy = json.loads(raw_policy)
    except json.JSONDecodeError as exc:
        raise ValueError("requirements catalog deployment policy is invalid") from exc
    if not isinstance(trust_policy, dict) or not trust_policy:
        raise ValueError("requirements catalog deployment policy is unavailable")
    result: dict[tuple[str, str], set[str]] = {}
    required = {
        "standard",
        "version",
        "source_revision",
        "requirements_file",
        "requirements_file_sha256",
    }
    for item in value:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("requirements assessment catalog fields do not match")
        identity = (str(item["standard"]), str(item["version"]))
        digest = str(item["requirements_file_sha256"]).casefold()
        key = f"{identity[0]}@{identity[1]}"
        if (
            identity in result
            or not _digest(digest)
            or trust_policy.get(key) != digest
            or not _hex_revision(str(item["source_revision"]))
        ):
            raise ValueError("requirements assessment catalog is not deployment-pinned")
        relative = Path(str(item["requirements_file"] or ""))
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError("requirements assessment catalog path is unsafe")
        catalog = (context.parent / relative).resolve()
        if catalog.parent != context.parent.resolve():
            raise ValueError("requirements assessment catalog must be adjacent")
        _, payload = read_regular_file(
            catalog,
            "requirements catalog snapshot",
            maximum_bytes=16 * 1024 * 1024,
            boundary=context.parent.resolve(),
        )
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError("requirements catalog snapshot SHA-256 does not match")
        identifiers = strict_loads(payload)
        if (
            not isinstance(identifiers, list)
            or not identifiers
            or identifiers != sorted(set(identifiers))
            or any(
                not isinstance(identifier, str) or not identifier
                for identifier in identifiers
            )
        ):
            raise ValueError("requirements catalog IDs are not canonical")
        result[identity] = set(identifiers)
    return result


def _requirement_assessment(
    value: object,
    artifacts: dict[str, Any],
    observed_at: datetime,
    evidence_policy: dict[tuple[str, str, str], dict[str, Any]],
) -> dict[str, Any]:
    fields = {
        "standard",
        "version",
        "requirement",
        "result",
        "method",
        "procedure_id",
        "assessor",
        "assessed_at",
        "assertions",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("requirement assessment fields do not match")
    identity = (
        _text(value["standard"], "assessment standard", 100),
        _text(value["version"], "assessment version", 30),
        _text(value["requirement"], "assessment requirement", 100),
    )
    declared = str(value["result"])
    if declared not in {"pass", "fail", "not-tested", "not-applicable"}:
        raise ValueError("requirement assessment result is invalid")
    assessed_at = _timestamp(value["assessed_at"], "assessment assessed_at")
    if assessed_at > observed_at:
        raise ValueError("requirement assessment is later than trusted scan time")
    assertions = value["assertions"]
    if not isinstance(assertions, list) or len(assertions) > 100:
        raise ValueError("requirement assessment assertions are invalid")
    normalized = [_assessment_assertion(item) for item in assertions]
    controls = evidence_policy[identity]
    if (
        str(value["method"]) not in controls["allowed_methods"]
        or str(value["procedure_id"]) != controls["procedure_id"]
        or len(normalized) < controls["minimum_assertions"]
        or sum(item["polarity"] == "negative-control" for item in normalized)
        < controls["minimum_negative_assertions"]
        or any(
            assertion["artifact"] not in controls["allowed_artifacts"]
            or assertion["execution_artifact"]
            not in controls["allowed_execution_artifacts"]
            or assertion["operator"] not in controls["allowed_operators"]
            or assertion["producer_sha256"] not in controls["allowed_producer_sha256"]
            for assertion in normalized
        )
    ):
        raise ValueError("requirement assessment violates its evidence policy")
    if declared in {"pass", "fail"} and not normalized:
        raise ValueError("assessed pass or fail requires replayable assertions")
    if declared == "pass" and any(item["operator"] == "exists" for item in normalized):
        raise ValueError("a passing assessment requires value-bearing assertions")
    if declared == "pass" and any(
        item["polarity"] == "negative-control" and item["operator"] != "not-equals"
        for item in normalized
    ):
        raise ValueError("negative controls must demonstrate a rejected value")
    if declared in {"not-tested", "not-applicable"} and normalized:
        raise ValueError("unassessed requirement cannot contain assertions")
    if normalized:
        maximum_age = timedelta(hours=controls["maximum_evidence_age_hours"])
        if any(
            item["observed_at"] > assessed_at
            or assessed_at - item["observed_at"] > maximum_age
            for item in normalized
        ):
            raise ValueError("requirement assertion evidence is stale or future-dated")
        for item in normalized:
            _verify_procedure_execution(
                item,
                artifacts,
                str(value["procedure_id"]),
                controls,
                observed_at,
            )
        if declared == "pass":
            positive_runs = {
                (item["fixture_sha256"], item["mutation_sha256"])
                for item in normalized
                if item["polarity"] == "positive"
            }
            negative_runs = {
                (item["fixture_sha256"], item["mutation_sha256"])
                for item in normalized
                if item["polarity"] == "negative-control"
            }
            if positive_runs & negative_runs:
                raise ValueError(
                    "negative controls require independently retained mutated executions"
                )
        outcomes = [_replay_assertion(item, artifacts) for item in normalized]
        observed_result = "pass" if all(outcomes) else "fail"
        if declared != observed_result:
            raise ValueError(
                "declared requirement result does not match replayed assertions"
            )
    retained_assertions = [
        {**item, "observed_at": item["observed_at"].isoformat()} for item in normalized
    ]
    return {
        "identity": identity,
        "result": declared,
        "method": _text(value["method"], "assessment method", 200),
        "procedure_id": _text(value["procedure_id"], "assessment procedure", 200),
        "assessor": _text(value["assessor"], "assessment assessor", 200),
        "assessed_at": assessed_at.isoformat(),
        "assertions": retained_assertions,
    }


def _assessment_evidence_policy(
    identities: set[tuple[str, str, str]],
) -> tuple[dict[tuple[str, str, str], dict[str, Any]], dict[str, Any], dict[str, Any]]:
    raw_path = os.environ.get("PYSEC_REQUIREMENTS_EVIDENCE_POLICY_PATH", "").strip()
    expected = (
        os.environ.get("PYSEC_REQUIREMENTS_EVIDENCE_POLICY_SHA256", "")
        .strip()
        .casefold()
    )
    if not raw_path or not _digest(expected):
        raise ValueError("requirements evidence policy configuration is incomplete")
    path = Path(raw_path).expanduser().resolve()
    _, payload = read_regular_file(
        path, "requirements evidence policy", maximum_bytes=16 * 1024 * 1024
    )
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError(
            "requirements evidence policy does not match its deployment pin"
        )
    value = strict_loads(payload)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "requirements"}
        or value.get("schema_version") != "1.0"
        or not isinstance(value.get("requirements"), list)
    ):
        raise ValueError("requirements evidence policy fields do not match")
    from .trusted_observation import scan_observed_at

    authority = verify_deployment_receipt(
        value,
        purpose="requirements-evidence-policy",
        environment_prefix="PYSEC_REQUIREMENTS_EVIDENCE_POLICY_AUTHORITY",
        observed_at=scan_observed_at(),
    )
    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    fields = {
        "standard",
        "version",
        "requirement",
        "allowed_artifacts",
        "allowed_execution_artifacts",
        "allowed_methods",
        "allowed_operators",
        "allowed_producer_sha256",
        "allowed_execution_authority_key_sha256",
        "minimum_assertions",
        "minimum_negative_assertions",
        "maximum_evidence_age_hours",
        "procedure_id",
    }
    for item in value["requirements"]:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("requirements evidence policy entry is invalid")
        identity = (
            str(item["standard"]),
            str(item["version"]),
            str(item["requirement"]),
        )
        lists = {
            name: item[name]
            for name in (
                "allowed_artifacts",
                "allowed_execution_artifacts",
                "allowed_methods",
                "allowed_operators",
                "allowed_producer_sha256",
                "allowed_execution_authority_key_sha256",
            )
        }
        minimum = item["minimum_assertions"]
        minimum_negative = item["minimum_negative_assertions"]
        maximum_age = item["maximum_evidence_age_hours"]
        if (
            identity not in identities
            or identity in result
            or any(
                not isinstance(items, list)
                or not items
                or items != sorted(set(items))
                or any(not isinstance(entry, str) or not entry for entry in items)
                for items in lists.values()
            )
            or not set(lists["allowed_operators"]).issubset(
                {"equals", "not-equals", "gte", "lte", "exists"}
            )
            or any(not _digest(digest) for digest in lists["allowed_producer_sha256"])
            or any(
                not _digest(digest)
                for digest in lists["allowed_execution_authority_key_sha256"]
            )
            or lists["allowed_methods"] != ["automated replay"]
            or item["procedure_id"] != "artifact-value-replay-v1"
            or isinstance(minimum, bool)
            or not isinstance(minimum, int)
            or not 0 <= minimum <= 100
            or isinstance(minimum_negative, bool)
            or not isinstance(minimum_negative, int)
            or not 0 <= minimum_negative <= minimum
            or isinstance(maximum_age, bool)
            or not isinstance(maximum_age, int)
            or not 1 <= maximum_age <= 24 * 365
        ):
            raise ValueError("requirements evidence policy entry is invalid")
        result[identity] = {
            **lists,
            "minimum_assertions": minimum,
            "minimum_negative_assertions": minimum_negative,
            "maximum_evidence_age_hours": maximum_age,
            "procedure_id": str(item["procedure_id"]),
        }
    if set(result) != identities:
        raise ValueError(
            "requirements evidence policy does not cover every requirement"
        )
    return result, value, authority


def _hex_revision(value: str) -> bool:
    return len(value) in {40, 64} and all(
        character in "0123456789abcdef" for character in value.casefold()
    )


def _assessment_assertion(value: object) -> dict[str, Any]:
    fields = {
        "artifact",
        "sha256",
        "pointer",
        "operator",
        "expected",
        "polarity",
        "observed_at",
        "producer_sha256",
        "execution_artifact",
        "execution_sha256",
        "fixture_sha256",
        "mutation_sha256",
        "command_sha256",
        "exit_code",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("requirement assertion fields do not match")
    artifact = _text(value["artifact"], "assessment artifact", 500)
    digest = str(value["sha256"])
    pointer = str(value["pointer"])
    operator = str(value["operator"])
    producer = str(value["producer_sha256"])
    execution_artifact = _text(
        value["execution_artifact"], "procedure execution artifact", 500
    )
    polarity = str(value["polarity"])
    observed_at = _timestamp(value["observed_at"], "assertion observed_at")
    if (
        not _digest(digest)
        or not _digest(producer)
        or not _digest(str(value["execution_sha256"]))
        or not _digest(str(value["fixture_sha256"]))
        or not _digest(str(value["mutation_sha256"]))
        or not _digest(str(value["command_sha256"]))
        or isinstance(value["exit_code"], bool)
        or not isinstance(value["exit_code"], int)
        or not -255 <= value["exit_code"] <= 255
        or polarity not in {"positive", "negative-control"}
        or not pointer.startswith("/")
        or len(pointer) > 1000
    ):
        raise ValueError("requirement assertion identity is invalid")
    if operator not in {"equals", "not-equals", "gte", "lte", "exists"}:
        raise ValueError("requirement assertion operator is unsupported")
    expected = value["expected"]
    if isinstance(expected, (dict, list)):
        raise ValueError("requirement assertion expected value must be scalar")
    return {
        "artifact": artifact,
        "sha256": digest,
        "pointer": pointer,
        "operator": operator,
        "expected": expected,
        "polarity": polarity,
        "observed_at": observed_at,
        "producer_sha256": producer,
        "execution_artifact": execution_artifact,
        "execution_sha256": str(value["execution_sha256"]),
        "fixture_sha256": str(value["fixture_sha256"]),
        "mutation_sha256": str(value["mutation_sha256"]),
        "command_sha256": str(value["command_sha256"]),
        "exit_code": value["exit_code"],
    }


def _verify_procedure_execution(
    assertion: dict[str, Any],
    artifacts: dict[str, Any],
    procedure_id: str,
    controls: dict[str, Any],
    observed_at: datetime,
) -> None:
    execution = artifacts.get(assertion["execution_artifact"])
    fields = {
        "schema_version",
        "procedure_id",
        "producer_sha256",
        "command_sha256",
        "fixture_sha256",
        "mutation_sha256",
        "exit_code",
        "stdout_sha256",
        "stderr_sha256",
        "result_artifact",
        "result_sha256",
        "started_at",
        "finished_at",
        "argv_sha256",
        "environment_sha256",
        "runtime_sha256",
        "assets_sha256",
        "sandbox_identity_sha256",
        "mutation_operator",
        "mutation_parent_sha256",
        "execution_authority_receipt",
        "argv",
        "environment",
        "runtime_manifest",
        "assets_manifest",
        "sandbox_policy",
        "fixture",
        "mutation_manifest",
    }
    if (
        not isinstance(execution, dict)
        or set(execution) != fields
        or hashlib.sha256(canonical_bytes(execution)).hexdigest()
        != assertion["execution_sha256"]
        or execution["schema_version"] != "1.0"
        or execution["procedure_id"] != procedure_id
        or execution["producer_sha256"] != assertion["producer_sha256"]
        or execution["command_sha256"] != assertion["command_sha256"]
        or execution["fixture_sha256"] != assertion["fixture_sha256"]
        or execution["mutation_sha256"] != assertion["mutation_sha256"]
        or execution["exit_code"] != assertion["exit_code"]
        or execution["result_artifact"] != assertion["artifact"]
        or execution["result_sha256"] != assertion["sha256"]
        or execution["stdout_sha256"] != execution["result_sha256"]
        or not _procedure_manifests_valid(execution)
        or execution["argv_sha256"]
        != hashlib.sha256(canonical_bytes(execution["argv"])).hexdigest()
        or execution["environment_sha256"]
        != hashlib.sha256(canonical_bytes(execution["environment"])).hexdigest()
        or execution["runtime_sha256"]
        != hashlib.sha256(canonical_bytes(execution["runtime_manifest"])).hexdigest()
        or execution["assets_sha256"]
        != hashlib.sha256(canonical_bytes(execution["assets_manifest"])).hexdigest()
        or execution["sandbox_identity_sha256"]
        != hashlib.sha256(canonical_bytes(execution["sandbox_policy"])).hexdigest()
        or execution["fixture_sha256"]
        != hashlib.sha256(canonical_bytes(execution["fixture"])).hexdigest()
        or execution["mutation_sha256"]
        != hashlib.sha256(canonical_bytes(execution["mutation_manifest"])).hexdigest()
        or any(
            not _digest(str(execution[name]))
            for name in (
                "stdout_sha256",
                "stderr_sha256",
                "argv_sha256",
                "environment_sha256",
                "runtime_sha256",
                "assets_sha256",
                "sandbox_identity_sha256",
                "mutation_parent_sha256",
            )
        )
        or execution["mutation_operator"]
        not in {"baseline", "negative-control-mutation"}
        or (
            assertion["polarity"] == "positive"
            and execution["mutation_operator"] != "baseline"
        )
        or (
            assertion["polarity"] == "negative-control"
            and execution["mutation_operator"] != "negative-control-mutation"
        )
    ):
        raise ValueError("requirement procedure execution is invalid or unbound")
    started = _timestamp(execution["started_at"], "procedure started_at")
    finished = _timestamp(execution["finished_at"], "procedure finished_at")
    if finished < started or finished - started > timedelta(hours=24):
        raise ValueError("requirement procedure execution duration is invalid")
    mutation = execution["mutation_manifest"]
    if (
        not isinstance(mutation, dict)
        or set(mutation) != {"operator", "parent_fixture_sha256", "mutated_fixture"}
        or mutation["operator"] != execution["mutation_operator"]
        or mutation["parent_fixture_sha256"] != execution["fixture_sha256"]
        or execution["mutation_parent_sha256"] != execution["fixture_sha256"]
        or (
            execution["mutation_operator"] == "baseline"
            and mutation["mutated_fixture"] != execution["fixture"]
        )
        or (
            execution["mutation_operator"] == "negative-control-mutation"
            and mutation["mutated_fixture"] == execution["fixture"]
        )
    ):
        raise ValueError("requirement mutation manifest is invalid or detached")
    subject = {
        name: value
        for name, value in execution.items()
        if name != "execution_authority_receipt"
    }
    receipt = execution["execution_authority_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    if not isinstance(statement, dict):
        raise ValueError("requirement execution authority statement is unavailable")
    signer = str((statement or {}).get("signer_key_sha256") or "")
    challenge = (
        os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    )
    if signer not in controls["allowed_execution_authority_key_sha256"]:
        raise ValueError("requirement execution authority is not policy-approved")
    verify_operation_receipt(
        subject,
        receipt,
        purpose="requirements-procedure-execution",
        observed_at=observed_at,
        challenge_sha256=challenge,
        expected_key_sha256=signer,
    )
    receipt_issued = _timestamp(statement["issued_at"], "execution receipt issued_at")
    if receipt_issued < finished or receipt_issued - finished > timedelta(minutes=5):
        raise ValueError("requirement execution receipt does not bracket execution")


def _procedure_manifests_valid(execution: dict[str, Any]) -> bool:
    environment = execution.get("environment")
    runtime = execution.get("runtime_manifest")
    assets = execution.get("assets_manifest")
    sandbox = execution.get("sandbox_policy")
    if (
        not isinstance(environment, list)
        or any(not isinstance(item, dict) for item in environment)
        or environment
        != sorted(environment, key=lambda item: str(item.get("name", "")))
        or not isinstance(runtime, dict)
        or set(runtime)
        != {
            "kind",
            "executable_sha256",
            "executable_base64",
            "closure_sha256",
            "closure_manifest",
            "image_digest",
            "image_manifest_base64",
            "sbom_sha256",
            "sbom_base64",
        }
        or runtime.get("kind") not in {"native", "container"}
        or execution.get("command_sha256") != runtime.get("executable_sha256")
        or any(
            not _digest(str(runtime.get(name) or ""))
            for name in ("executable_sha256", "closure_sha256", "sbom_sha256")
        )
        or not isinstance(runtime.get("image_digest"), str)
        or (
            runtime["kind"] == "container"
            and not (
                runtime["image_digest"].startswith("sha256:")
                and _digest(runtime["image_digest"].removeprefix("sha256:"))
            )
        )
        or (runtime["kind"] == "native" and runtime["image_digest"] != "")
        or not isinstance(assets, list)
        or any(not isinstance(item, dict) for item in assets)
        or assets != sorted(assets, key=lambda item: str(item.get("name", "")))
        or not isinstance(sandbox, dict)
        or sandbox
        != {
            "network": "deny",
            "filesystem": "read-only",
            "process": "confined",
            "credentials": "isolated",
        }
    ):
        return False
    try:
        executable = base64.b64decode(runtime["executable_base64"], validate=True)
        sbom = base64.b64decode(runtime["sbom_base64"], validate=True)
        image_manifest = base64.b64decode(
            runtime["image_manifest_base64"], validate=True
        )
    except (TypeError, ValueError):
        return False
    if (
        not executable
        or len(executable) > 16 * 1024 * 1024
        or hashlib.sha256(executable).hexdigest() != runtime["executable_sha256"]
        or not sbom
        or len(sbom) > 16 * 1024 * 1024
        or hashlib.sha256(sbom).hexdigest() != runtime["sbom_sha256"]
        or not isinstance(runtime["closure_manifest"], list)
        or runtime["closure_sha256"]
        != hashlib.sha256(canonical_bytes(runtime["closure_manifest"])).hexdigest()
        or (runtime["kind"] == "native" and image_manifest)
        or (
            runtime["kind"] == "container"
            and (
                not image_manifest
                or hashlib.sha256(image_manifest).hexdigest()
                != runtime["image_digest"].removeprefix("sha256:")
            )
        )
    ):
        return False
    closure_paths: set[str] = set()
    for item in runtime["closure_manifest"]:
        if not _material_record_valid(item, closure_paths, "path"):
            return False
    environment_names: set[str] = set()
    for item in environment:
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "name",
                "value_commitment",
                "classification",
                "commitment_algorithm",
                "commitment_key_sha256",
                "nonce_sha256",
            }
            or not str(item["name"])
            or str(item["name"]) in environment_names
            or not _digest(str(item["value_commitment"]))
            or item["classification"] not in {"public-commitment", "secret-commitment"}
        ):
            return False
        if item["classification"] == "public-commitment" and (
            item["commitment_algorithm"] != "sha256"
            or item["commitment_key_sha256"] != ""
            or item["nonce_sha256"] != ""
        ):
            return False
        if item["classification"] == "secret-commitment":
            expected_key = (
                os.environ.get("PYSEC_REQUIREMENTS_SECRET_COMMITMENT_KEY_SHA256", "")
                .strip()
                .casefold()
            )
            if (
                item["commitment_algorithm"] != "hmac-sha256"
                or not _digest(expected_key)
                or item["commitment_key_sha256"] != expected_key
                or not _digest(str(item["nonce_sha256"]))
            ):
                return False
        environment_names.add(str(item["name"]))
    asset_names: set[str] = set()
    for item in assets:
        if not isinstance(item, dict) or not _material_record_valid(
            item, asset_names, "name"
        ):
            return False
    return True


def _material_record_valid(
    item: object, identities: set[str], identity_field: str
) -> bool:
    if not isinstance(item, dict) or set(item) != {
        identity_field,
        "sha256",
        "content_base64",
    }:
        return False
    identity = str(item[identity_field])
    try:
        content = base64.b64decode(str(item["content_base64"]), validate=True)
    except (TypeError, ValueError):
        return False
    if (
        not identity
        or identity in identities
        or len(content) > 16 * 1024 * 1024
        or hashlib.sha256(content).hexdigest() != item["sha256"]
    ):
        return False
    identities.add(identity)
    return True


def _replay_assertion(assertion: dict[str, Any], artifacts: dict[str, Any]) -> bool:
    artifact = artifacts.get(assertion["artifact"])
    if (
        artifact is None
        or hashlib.sha256(canonical_bytes(artifact)).hexdigest() != assertion["sha256"]
    ):
        return False
    found, observed = _json_pointer(artifact, assertion["pointer"])
    operator = assertion["operator"]
    expected = assertion["expected"]
    if operator == "exists":
        return found is bool(expected)
    if not found:
        return False
    if operator == "equals":
        return observed == expected
    if operator == "not-equals":
        return observed != expected
    if (
        isinstance(observed, bool)
        or isinstance(expected, bool)
        or not isinstance(observed, (int, float))
        or not isinstance(expected, (int, float))
    ):
        return False
    return observed >= expected if operator == "gte" else observed <= expected


def _json_pointer(value: object, pointer: str) -> tuple[bool, object]:
    current = value
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif (
            isinstance(current, list) and token.isdigit() and int(token) < len(current)
        ):
            current = current[int(token)]
        else:
            return False, None
    return True, current


def _timestamp(value: object, label: str) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if result.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return result.astimezone(UTC)


def _text(value: object, label: str, maximum: int) -> str:
    result = str(value).strip()
    if (
        not result
        or len(result) > maximum
        or any(ord(character) < 32 for character in result)
    ):
        raise ValueError(f"{label} is invalid")
    return result


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
