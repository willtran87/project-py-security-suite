from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from companion.llm_adversarial import validate_proposal
from companion.semantic_assurance import (
    REQUIRED_CONTROLS,
    analyze,
    bind_case_observations,
)
from companion.strict_json import canonical_bytes
from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.llm_adversarial import build_llm_adversarial_plan
from py_security_suite.models import Confidence, Finding, Location, Severity
from py_security_suite.report_inspection import read_bundled_schema


_SOURCE_SHA256 = "a" * 64


def _finding() -> Finding:
    return Finding(
        finding_id="finding-authz",
        fingerprint="fingerprint-authz",
        title="Tenant authorization may fail open",
        description="A tenant-owned object is loaded before the tenant predicate is applied.",
        impact="A principal may observe another tenant's object.",
        remediation="Apply authenticated tenant context in the data query.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="authorization",
        locations=[Location(path="src/app.py", start_line=1, end_line=2)],
    )


def _artifacts() -> dict[str, object]:
    return {
        "source-inventory.json": {"source_sha256": _SOURCE_SHA256},
        "application-contract-analysis.json": {
            "generated_test_scenarios": [
                {
                    "id": "tenant-object-cross-tenant-deny",
                    "method": "GET",
                    "path": "/tenants/{tenant_id}/objects/{object_id}",
                    "kind": "cross-tenant-deny",
                    "priority": "P0",
                    "rationale": "Prove a valid principal cannot cross the tenant boundary.",
                    "execution": {"oracle": "deny"},
                }
            ]
        },
        "domain-assurance.json": {
            "domains": [
                {
                    "name": "tenant-isolation",
                    "applicable": True,
                    "status": "partial",
                    "recommendation": "Exercise cross-tenant denial at every store.",
                }
            ]
        },
    }


def _write_policy(root: Path) -> None:
    security = root / "security"
    security.mkdir(exist_ok=True)
    policy = json.loads(
        Path(__file__)
        .parents[1]
        .joinpath("examples/llm-adversarial-policy.example.json")
        .read_text(encoding="utf-8")
    )
    security.joinpath("llm-adversarial-policy.json").write_text(
        json.dumps(policy), encoding="utf-8"
    )


def test_builds_bounded_source_referenced_campaigns(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    source.joinpath("app.py").write_text(
        "def load():\n    return None\n", encoding="utf-8"
    )

    plan, errors = build_llm_adversarial_plan(tmp_path, [_finding()], _artifacts())

    assert errors == []
    assert plan["complete"] is True
    assert plan["execution_ready"] is False
    assert plan["campaigns_retained"] == 3
    assert plan["execution_plan"]["tasks_detected"] == 3
    assert all(item["content_included"] is False for item in plan["context"])
    source_context = next(
        item for item in plan["context"] if item["path"] == "src/app.py"
    )
    assert source_context["sha256"] is not None
    assert source_context["content_trust"] == "untrusted-repository-data"
    validate_governed_artifacts({"llm-adversarial-plan.json": plan})


def test_safe_policy_marks_handoff_ready_without_authorizing_execution(
    tmp_path: Path,
) -> None:
    (tmp_path / "src").mkdir()
    tmp_path.joinpath("src/app.py").write_text("value = 1\n", encoding="utf-8")
    _write_policy(tmp_path)

    plan, errors = build_llm_adversarial_plan(tmp_path, [_finding()], _artifacts())

    assert errors == []
    assert plan["policy_present"] is True
    assert plan["execution_ready"] is True
    assert plan["execution_plan"]["destructive_testing_allowed"] is False
    assert plan["execution_plan"]["human_approval_required"] is True
    validate_governed_artifacts({"llm-adversarial-plan.json": plan})


def test_policy_rejects_runtime_network_and_missing_controls(tmp_path: Path) -> None:
    _write_policy(tmp_path)
    path = tmp_path / "security" / "llm-adversarial-policy.json"
    policy = json.loads(path.read_text(encoding="utf-8"))
    policy["network_policy"] = "approved-targets-only"
    policy["allow_runtime_testing"] = True
    policy["require_negative_control"] = False
    policy["allowed_test_roots"] = ["somewhere-else"]
    path.write_text(json.dumps(policy), encoding="utf-8")

    plan, errors = build_llm_adversarial_plan(tmp_path, [], _artifacts())

    assert plan["complete"] is False
    assert plan["execution_ready"] is False
    assert errors == ["security/llm-adversarial-policy.json: ValueError"]
    validate_governed_artifacts({"llm-adversarial-plan.json": plan})


def test_authenticated_control_proof_updates_campaign_accounting(
    tmp_path: Path,
) -> None:
    (tmp_path / "src").mkdir()
    tmp_path.joinpath("src/app.py").write_text("value = 1\n", encoding="utf-8")
    initial, _ = build_llm_adversarial_plan(tmp_path, [_finding()], _artifacts())
    campaign_id = initial["campaigns"][0]["id"]
    artifacts = _artifacts()
    controls = sorted(REQUIRED_CONTROLS["llm-adversarial"])
    ledger = [
        {
            "id": f"case-{index}",
            "target_id": campaign_id,
            "control": control,
            "expected": "pass",
            "observed": "block" if index == 0 else "pass",
        }
        for index, control in enumerate(controls)
    ]
    artifacts["llm-adversarial-summary.json"] = {
        "kind": "llm-adversarial",
        "source_sha256": _SOURCE_SHA256,
        "evidence_binding": {"verified": True, "authenticated": True},
        "execution": {
            "status": "completed",
            "features": controls,
            "control_proof": {"case_ledger": ledger},
        },
        "findings": [
            {"evidence": {"campaign_id": campaign_id, "case_id": "case-0"}},
        ],
    }

    plan, _ = build_llm_adversarial_plan(tmp_path, [_finding()], artifacts)

    assert plan["campaigns"][0]["evidence_status"] == "confirmed-defect"
    assert plan["evidence"]["confirmed_defects"] == 1
    validate_governed_artifacts({"llm-adversarial-plan.json": plan})


def test_companion_validates_confined_schema_bound_proposal(tmp_path: Path) -> None:
    source = tmp_path / "source"
    workspace = tmp_path / "workspace"
    source.joinpath("src").mkdir(parents=True)
    workspace.mkdir()
    source.joinpath("src/app.py").write_text("value = 1\n", encoding="utf-8")
    _write_policy(source)
    plan, _ = build_llm_adversarial_plan(source, [_finding()], _artifacts())
    campaign = next(
        item for item in plan["campaigns"] if "hypothesis" in item["allowed_tools"]
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    proposal = {
        "schema_version": "1.0",
        "plan_sha256": hashlib.sha256(canonical_bytes(plan)).hexdigest(),
        "source_sha256": _SOURCE_SHA256,
        "campaign_id": campaign["id"],
        "model_sha256": "1" * 64,
        "provider_sha256": "2" * 64,
        "prompt_template_sha256": "3" * 64,
        "hypothesis": "The tenant predicate may fail open.",
        "proposed_tests": [
            {
                "id": "tenant-boundary",
                "path": "generated-tests/test_tenant.py",
                "framework": "pytest-hypothesis",
                "tool": "hypothesis",
                "command": ["pytest", "generated-tests/test_tenant.py", "-q"],
                "objective": "Exercise foreign tenant identifiers.",
                "oracle": {
                    "kind": "cross-tenant-deny",
                    "expected": "Foreign tenant identifiers are denied.",
                    "deterministic": True,
                    "llm_judge_sufficient": False,
                },
                "negative_control": {
                    "present": True,
                    "description": "An owned object remains accessible.",
                },
                "mutation_validation": {
                    "present": True,
                    "description": "Removing the tenant predicate fails the test.",
                },
            }
        ],
    }
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_text(json.dumps(proposal), encoding="utf-8")

    validated = validate_proposal(
        plan_path=plan_path,
        proposal_path=proposal_path,
        campaign_id=campaign["id"],
        source_root=source,
        workspace=workspace,
    )

    assert validated["validated"] is True
    assert validated["execution_authorized"] is False
    proposal["proposed_tests"][0]["command"] = ["pytest", "x; whoami"]
    proposal_path.write_text(json.dumps(proposal), encoding="utf-8")
    with pytest.raises(ValueError, match="shell control"):
        validate_proposal(
            plan_path=plan_path,
            proposal_path=proposal_path,
            campaign_id=campaign["id"],
            source_root=source,
            workspace=workspace,
        )

    plan["campaigns"][0]["generated_test_root"] = "."
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(ValueError, match="campaign authority"):
        validate_proposal(
            plan_path=plan_path,
            proposal_path=proposal_path,
            campaign_id=plan["campaigns"][0]["id"],
            source_root=source,
            workspace=workspace,
        )


def test_llm_adversarial_schemas_and_examples_are_bundled() -> None:
    for name, example_name in (
        ("llm-adversarial-policy-1.0", "llm-adversarial-policy.example.json"),
        ("llm-adversarial-proposal-1.0", "llm-adversarial-proposal.example.json"),
    ):
        schema = json.loads(read_bundled_schema(name))
        example = json.loads(
            Path(__file__).parents[1].joinpath("examples", example_name).read_text()
        )
        Draft202012Validator(schema).validate(example)
    plan_schema = json.loads(read_bundled_schema("llm-adversarial-plan-1.0"))
    assert plan_schema["$id"].endswith("llm-adversarial-plan:1.0")


def test_semantic_companion_requires_every_llm_adversarial_control() -> None:
    cases = [
        {
            "id": f"case-{index}",
            "target_id": "llm-campaign-33333333333333333333",
            "role": "adversarial",
            "control": control,
            "expected": "pass",
            "observed": "pass",
            "severity": "high",
            "classification": "CWE-693",
        }
        for index, control in enumerate(sorted(REQUIRED_CONTROLS["llm-adversarial"]))
    ]
    bound = bind_case_observations(cases, artifact={}, transcript={})

    result = analyze(
        {
            "schema_version": "2.0",
            "kind": "llm-adversarial",
            "cases": bound,
            "canary_id": "case-0",
        },
        "llm-adversarial",
    )

    assert set(result["execution"]["features"]) == REQUIRED_CONTROLS["llm-adversarial"]
    assert result["execution"]["control_proof"]["case_ledger"] == bound
