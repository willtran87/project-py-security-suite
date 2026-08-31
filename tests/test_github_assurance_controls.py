from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType


_ROOT = Path(__file__).parent.parent


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "audit_github_assurance_controls",
        _ROOT / "scripts/audit_github_assurance_controls.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _policy() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "minimum_distinct_maintainers": 3,
        "deployment_branches": ["main"],
        "environments": [
            {
                "name": "release",
                "minimum_reviewer_principals": 2,
                "prevent_self_review": True,
                "require_branch_policy": True,
                "runner_labels": ["self-hosted", "pysec-release"],
            }
        ],
    }


def _snapshot() -> dict[str, object]:
    return {
        "repository": "owner/repository",
        "collaborators": [
            {"login": name, "permissions": {"maintain": True}}
            for name in ("one", "two", "three")
        ],
        "environments": [
            {
                "name": "release",
                "deployment_branch_policy": {
                    "custom_branch_policies": True,
                    "protected_branches": False,
                },
                "deployment_branch_policies": [{"name": "main", "type": "branch"}],
                "protection_rules": [
                    {"type": "branch_policy"},
                    {
                        "type": "required_reviewers",
                        "prevent_self_review": True,
                        "reviewers": [
                            {"type": "User", "reviewer": {"login": "two"}},
                            {"type": "Team", "reviewer": {"slug": "security"}},
                        ],
                    },
                ],
            }
        ],
        "runners": [
            {
                "name": "release-runner",
                "status": "online",
                "busy": False,
                "labels": [{"name": "self-hosted"}, {"name": "pysec-release"}],
            }
        ],
    }


def test_control_plane_readiness_passes_only_with_independent_live_controls() -> None:
    report = _script().audit_controls(_policy(), _snapshot())

    assert report["status"] == "PASS"
    assert report["summary"]["failed"] == 0


def test_control_plane_readiness_reports_every_missing_authority() -> None:
    snapshot = _snapshot()
    snapshot["collaborators"] = snapshot["collaborators"][:1]
    snapshot["runners"] = []
    snapshot["environments"][0]["protection_rules"] = []

    report = _script().audit_controls(_policy(), snapshot)

    assert report["status"] == "INCOMPLETE"
    assert set(report["failures"]) == {
        "distinct-maintainers",
        "environment:release:reviewer-principals",
        "environment:release:prevent-self-review",
        "environment:release:branch-policy",
        "environment:release:available-runner",
    }


def test_repository_control_policy_is_valid_and_complete() -> None:
    policy = json.loads(
        (_ROOT / "security/github-assurance-controls.json").read_text(encoding="utf-8")
    )
    names = {item["name"] for item in policy["environments"]}

    assert policy["minimum_distinct_maintainers"] >= 3
    assert policy["deployment_branches"] == ["main"]
    assert names == {
        "release-admission",
        "release-evidence-source",
        "production-security-isolation",
        "authorized-dynamic-security",
        "independent-release-verification",
        "production-signing-conformance",
        "pypi-production",
    }
    assert all(
        item["minimum_reviewer_principals"] >= 2 for item in policy["environments"]
    )
