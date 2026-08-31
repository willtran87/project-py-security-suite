from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import quote


_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ReadinessError(ValueError):
    """Raised when control-plane evidence cannot be acquired or interpreted."""


def _gh_json(endpoint: str) -> Any:
    executable = shutil.which("gh")
    if executable is None:
        raise ReadinessError("GitHub CLI is unavailable")
    completed = subprocess.run(  # noqa: S603 - resolved CLI and validated API path
        [executable, "api", endpoint],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ReadinessError(f"GitHub API request failed for {endpoint}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ReadinessError(
            f"GitHub API returned invalid JSON for {endpoint}"
        ) from exc


def acquire_snapshot(repository: str) -> dict[str, Any]:
    if not _REPOSITORY.fullmatch(repository):
        raise ReadinessError("repository must use the OWNER/NAME form")
    environment_listing = _gh_json(f"repos/{repository}/environments")
    environments = []
    for item in environment_listing.get("environments", []):
        name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(name, str):
            raise ReadinessError("GitHub environment response is invalid")
        encoded_name = quote(name, safe="")
        detail = _gh_json(f"repos/{repository}/environments/{encoded_name}")
        deployment = detail.get("deployment_branch_policy")
        if isinstance(deployment, dict) and deployment.get("custom_branch_policies"):
            policies = _gh_json(
                f"repos/{repository}/environments/{encoded_name}/deployment-branch-policies"
            )
            detail["deployment_branch_policies"] = policies.get("branch_policies", [])
        environments.append(detail)
    runners = _gh_json(f"repos/{repository}/actions/runners")
    collaborators = _gh_json(f"repos/{repository}/collaborators?per_page=100")
    return {
        "repository": repository,
        "environments": environments,
        "runners": runners.get("runners", []),
        "collaborators": collaborators,
    }


def _reviewer_rule(environment: dict[str, Any]) -> dict[str, Any] | None:
    return next(
        (
            rule
            for rule in environment.get("protection_rules", [])
            if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
        ),
        None,
    )


def audit_controls(policy: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    environments = {
        item.get("name"): item
        for item in snapshot.get("environments", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    runners = [item for item in snapshot.get("runners", []) if isinstance(item, dict)]
    maintainers = {
        item.get("login")
        for item in snapshot.get("collaborators", [])
        if isinstance(item, dict)
        and isinstance(item.get("login"), str)
        and isinstance(item.get("permissions"), dict)
        and (item["permissions"].get("admin") or item["permissions"].get("maintain"))
    }
    checks: list[dict[str, Any]] = []

    minimum_maintainers = policy.get("minimum_distinct_maintainers")
    if not isinstance(minimum_maintainers, int) or minimum_maintainers < 1:
        raise ReadinessError("minimum_distinct_maintainers is invalid")
    checks.append(
        {
            "control": "distinct-maintainers",
            "passed": len(maintainers) >= minimum_maintainers,
            "observed": len(maintainers),
            "required": minimum_maintainers,
        }
    )

    specifications = policy.get("environments")
    if not isinstance(specifications, list) or not specifications:
        raise ReadinessError("environment policy must be a non-empty array")
    deployment_branches = policy.get("deployment_branches")
    if (
        not isinstance(deployment_branches, list)
        or not deployment_branches
        or any(not isinstance(item, str) or not item for item in deployment_branches)
    ):
        raise ReadinessError("deployment_branches must be a non-empty string array")
    expected_deployment_branches = set(deployment_branches)
    for specification in specifications:
        if not isinstance(specification, dict) or not isinstance(
            specification.get("name"), str
        ):
            raise ReadinessError("environment policy entry is invalid")
        name = specification["name"]
        environment = environments.get(name)
        exists = isinstance(environment, dict)
        checks.append({"control": f"environment:{name}:exists", "passed": exists})
        if not isinstance(environment, dict):
            continue
        rules = environment.get("protection_rules", [])
        reviewer_rule = _reviewer_rule(environment)
        reviewer_principals = {
            (
                reviewer.get("type"),
                reviewer.get("reviewer", {}).get("login")
                or reviewer.get("reviewer", {}).get("slug"),
            )
            for reviewer in (reviewer_rule or {}).get("reviewers", [])
            if isinstance(reviewer, dict)
        }
        required_reviewers = specification.get("minimum_reviewer_principals", 0)
        checks.append(
            {
                "control": f"environment:{name}:reviewer-principals",
                "passed": len(reviewer_principals) >= required_reviewers,
                "observed": len(reviewer_principals),
                "required": required_reviewers,
            }
        )
        if specification.get("prevent_self_review"):
            checks.append(
                {
                    "control": f"environment:{name}:prevent-self-review",
                    "passed": bool((reviewer_rule or {}).get("prevent_self_review")),
                }
            )
        if specification.get("require_branch_policy"):
            deployment = environment.get("deployment_branch_policy")
            custom_policies = environment.get("deployment_branch_policies", [])
            observed_branches: set[str] = set()
            for item in custom_policies:
                if not isinstance(item, dict) or item.get("type") != "branch":
                    continue
                branch_name = item.get("name")
                if isinstance(branch_name, str) and branch_name:
                    observed_branches.add(branch_name)
            branch_policy_passed = bool(
                isinstance(deployment, dict)
                and (
                    deployment.get("protected_branches") is True
                    or (
                        deployment.get("custom_branch_policies") is True
                        and observed_branches == expected_deployment_branches
                    )
                )
                and any(
                    isinstance(rule, dict) and rule.get("type") == "branch_policy"
                    for rule in rules
                )
            )
            checks.append(
                {
                    "control": f"environment:{name}:branch-policy",
                    "passed": branch_policy_passed,
                    "expected_branches": deployment_branches,
                    "observed_branches": sorted(observed_branches),
                }
            )
        labels = specification.get("runner_labels", [])
        if labels:
            matched = [
                runner
                for runner in runners
                if runner.get("status") == "online"
                and not runner.get("busy")
                and set(labels)
                <= {
                    label.get("name")
                    for label in runner.get("labels", [])
                    if isinstance(label, dict)
                }
            ]
            checks.append(
                {
                    "control": f"environment:{name}:available-runner",
                    "passed": bool(matched),
                    "required_labels": labels,
                    "observed": len(matched),
                }
            )

    failures = [check["control"] for check in checks if not check["passed"]]
    return {
        "schema_version": "1.0",
        "repository": snapshot.get("repository", "offline-snapshot"),
        "status": "PASS" if not failures else "INCOMPLETE",
        "summary": {
            "checks": len(checks),
            "passed": len(checks) - len(failures),
            "failed": len(failures),
        },
        "failures": failures,
        "checks": checks,
    }


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReadinessError(f"cannot read {label}") from exc
    if not isinstance(value, dict):
        raise ReadinessError(f"{label} must be a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit protected GitHub assurance controls."
    )
    parser.add_argument("--repository")
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("security/github-assurance-controls.json"),
    )
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if bool(arguments.repository) == bool(arguments.snapshot):
        parser.error("provide exactly one of --repository or --snapshot")
    policy = _read_object(arguments.policy, "control policy")
    snapshot = (
        acquire_snapshot(arguments.repository)
        if arguments.repository
        else _read_object(arguments.snapshot, "control snapshot")
    )
    report = audit_controls(policy, snapshot)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
