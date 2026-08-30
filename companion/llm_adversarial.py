from __future__ import annotations

import argparse
import hashlib
import os
import re
from pathlib import Path
from typing import Any

try:
    from companion.strict_json import canonical_bytes
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
except ModuleNotFoundError:  # Direct script execution.
    from strict_json import canonical_bytes  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]


_MAX_INPUT_BYTES = 16 * 1024 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EXECUTABLES = {
    "atheris": {"python"},
    "authorization-security": {"python"},
    "codeql": {"codeql"},
    "crosshair": {"crosshair"},
    "hypothesis": {"pytest"},
    "mutmut": {"mutmut"},
    "playwright": {"npx", "playwright", "pytest"},
    "pysa": {"pyre"},
    "restler": {"restler", "dotnet"},
    "schemathesis": {"st", "schemathesis"},
    "semgrep": {"semgrep"},
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate an LLM adversarial proposal without executing it."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--plan", type=Path, required=True)
    validate.add_argument("--proposal", type=Path, required=True)
    validate.add_argument("--campaign", required=True)
    validate.add_argument("--source-root", type=Path, required=True)
    validate.add_argument("--workspace", type=Path, required=True)
    validate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if os.environ.get("PYSEC_LLM_EXECUTION_APPROVAL") != "approved-plan-validation":
            raise ValueError("explicit LLM plan-validation approval is required")
        result = validate_proposal(
            plan_path=args.plan,
            proposal_path=args.proposal,
            campaign_id=args.campaign,
            source_root=args.source_root,
            workspace=args.workspace,
        )
        _write_output(args.output, args.workspace, result)
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    return 0


def validate_proposal(
    *,
    plan_path: Path,
    proposal_path: Path,
    campaign_id: str,
    source_root: Path,
    workspace: Path,
) -> dict[str, Any]:
    plan = _document(plan_path, "adversarial plan")
    proposal = _document(proposal_path, "LLM proposal")
    _validate_plan(plan)
    campaign = _campaign(plan, campaign_id)
    source = _regular_directory(source_root, "source root")
    disposable = _regular_directory(workspace, "disposable workspace")
    if (
        source == disposable
        or source in disposable.parents
        or disposable in source.parents
    ):
        raise ValueError("source root and disposable workspace must be disjoint")
    plan_digest = hashlib.sha256(canonical_bytes(plan)).hexdigest()
    _validate_proposal_shape(proposal, plan_digest, plan, campaign)
    context = {
        str(item["id"]): item
        for item in plan["context"]
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    verified_context = 0
    for context_id in campaign["context_ids"]:
        item = context.get(context_id)
        if item is None:
            raise ValueError("campaign references missing context")
        expected = item.get("sha256")
        path = item.get("path")
        if expected is None or path == "<repository>":
            continue
        candidate = _confined(source, str(path).partition("#")[0].partition(":")[0])
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("context source is not a regular file")
        if _sha256(candidate) != expected:
            raise ValueError("context source digest does not match the plan")
        verified_context += 1
    tests = proposal["proposed_tests"]
    allowed_tools = set(campaign["allowed_tools"])
    for test in tests:
        test_path = _confined(disposable, str(test["path"]))
        relative = test_path.relative_to(disposable).as_posix()
        if not relative.startswith(f"{campaign['generated_test_root']}/"):
            raise ValueError("generated test escapes the campaign write root")
        tool = str(test["tool"])
        if tool not in allowed_tools:
            raise ValueError("proposal requests a tool outside the campaign allowlist")
        command = test["command"]
        if command[0].casefold() not in _EXECUTABLES[tool]:
            raise ValueError("proposal command does not match its allowed tool")
        if any(_shell_control(str(argument)) for argument in command):
            raise ValueError("proposal command contains shell control syntax")
        if test["negative_control"]["present"] is not True:
            raise ValueError("proposal omits a negative control")
        if test["mutation_validation"]["present"] is not True:
            raise ValueError("proposal omits mutation validation")
        if test["oracle"]["deterministic"] is not True:
            raise ValueError("proposal oracle is not deterministic")
        if test["oracle"]["llm_judge_sufficient"] is not False:
            raise ValueError("an LLM judge cannot be the sole oracle")
    return {
        "schema_version": "1.0",
        "validated": True,
        "plan_sha256": plan_digest,
        "source_sha256": plan["source_sha256"],
        "campaign_id": campaign_id,
        "proposal_sha256": hashlib.sha256(canonical_bytes(proposal)).hexdigest(),
        "model_sha256": proposal["model_sha256"],
        "provider_sha256": proposal["provider_sha256"],
        "prompt_template_sha256": proposal["prompt_template_sha256"],
        "context_entries_verified": verified_context,
        "proposed_tests": tests,
        "execution_authorized": False,
        "network_policy": "deny",
        "write_scope": "generated-tests-only",
        "claim_boundary": (
            "Validation proves proposal shape, source references, path confinement, "
            "tool allowlisting, and required oracles. It does not execute tests, grant "
            "shell authority, or establish a finding."
        ),
    }


def _validate_plan(value: dict[str, Any]) -> None:
    execution = value.get("execution_plan")
    if (
        value.get("schema_version") != "1.0"
        or value.get("analysis") != "provider-neutral-llm-adversarial-test-planning"
        or value.get("complete") is not True
        or value.get("planning_enabled") is not True
        or value.get("execution_ready") is not True
        or value.get("truncated") is not False
        or value.get("policy_present") is not True
        or not isinstance(value.get("context"), list)
        or not isinstance(value.get("campaigns"), list)
        or not isinstance(execution, dict)
        or execution.get("network_policy") != "deny"
        or execution.get("write_scope") != "generated-tests-only"
        or execution.get("human_approval_required") is not True
        or execution.get("destructive_testing_allowed") is not False
        or _DIGEST.fullmatch(str(value.get("source_sha256") or "")) is None
    ):
        raise ValueError("LLM adversarial plan is incomplete or invalid")
    context_ids = [
        item.get("id") for item in value["context"] if isinstance(item, dict)
    ]
    campaign_ids = [
        item.get("id") for item in value["campaigns"] if isinstance(item, dict)
    ]
    if (
        len(context_ids) != len(value["context"])
        or len(context_ids) != len(set(context_ids))
        or len(campaign_ids) != len(value["campaigns"])
        or len(campaign_ids) != len(set(campaign_ids))
    ):
        raise ValueError("LLM adversarial plan identities are invalid")
    for campaign in value["campaigns"]:
        tools = campaign.get("allowed_tools")
        references = campaign.get("context_ids")
        oracle = campaign.get("oracle")
        iterations = campaign.get("maximum_iterations")
        if (
            not _text(campaign.get("id"), 200)
            or not isinstance(tools, list)
            or not tools
            or len(tools) != len(set(tools))
            or not set(tools).issubset(_EXECUTABLES)
            or not isinstance(references, list)
            or not references
            or not set(references).issubset(context_ids)
            or not _safe_root(campaign.get("generated_test_root"))
            or not isinstance(iterations, int)
            or isinstance(iterations, bool)
            or not 1 <= iterations <= 10
            or campaign.get("negative_control_required") is not True
            or campaign.get("mutation_validation_required") is not True
            or not isinstance(oracle, dict)
            or oracle.get("deterministic") is not True
            or oracle.get("llm_judge_sufficient") is not False
        ):
            raise ValueError("LLM adversarial campaign authority is invalid")


def _campaign(plan: dict[str, Any], campaign_id: str) -> dict[str, Any]:
    matches = [
        item
        for item in plan["campaigns"]
        if isinstance(item, dict) and item.get("id") == campaign_id
    ]
    if len(matches) != 1:
        raise ValueError("campaign is missing or ambiguous")
    return matches[0]


def _validate_proposal_shape(
    value: dict[str, Any],
    plan_digest: str,
    plan: dict[str, Any],
    campaign: dict[str, Any],
) -> None:
    required = {
        "schema_version",
        "plan_sha256",
        "source_sha256",
        "campaign_id",
        "model_sha256",
        "provider_sha256",
        "prompt_template_sha256",
        "hypothesis",
        "proposed_tests",
    }
    if set(value) != required or value.get("schema_version") != "1.0":
        raise ValueError("LLM proposal fields do not match the v1 contract")
    if value.get("plan_sha256") != plan_digest:
        raise ValueError("LLM proposal is not bound to this plan")
    if value.get("source_sha256") != plan["source_sha256"]:
        raise ValueError("LLM proposal is not bound to this source")
    if value.get("campaign_id") != campaign["id"]:
        raise ValueError("LLM proposal is not bound to this campaign")
    for field in ("model_sha256", "provider_sha256", "prompt_template_sha256"):
        if _DIGEST.fullmatch(str(value.get(field) or "")) is None:
            raise ValueError(f"LLM proposal requires a valid {field}")
    if not _text(value.get("hypothesis"), 2000):
        raise ValueError("LLM proposal hypothesis is invalid")
    tests = value.get("proposed_tests")
    if not isinstance(tests, list) or not 1 <= len(tests) <= 20:
        raise ValueError("LLM proposal must contain 1 to 20 tests")
    seen: set[str] = set()
    for test in tests:
        _validate_test(test)
        if test["id"] in seen:
            raise ValueError("LLM proposal contains duplicate test identities")
        seen.add(test["id"])


def _validate_test(value: object) -> None:
    required = {
        "id",
        "path",
        "framework",
        "tool",
        "command",
        "objective",
        "oracle",
        "negative_control",
        "mutation_validation",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("proposed test fields do not match the v1 contract")
    if not _text(value.get("id"), 160) or not _safe_relative(value.get("path")):
        raise ValueError("proposed test identity or path is invalid")
    if not _text(value.get("framework"), 100) or value.get("tool") not in _EXECUTABLES:
        raise ValueError("proposed test framework or tool is invalid")
    command = value.get("command")
    if (
        not isinstance(command, list)
        or not 1 <= len(command) <= 30
        or not all(_text(item, 1000) for item in command)
    ):
        raise ValueError("proposed test command is invalid")
    if not _text(value.get("objective"), 1000):
        raise ValueError("proposed test objective is invalid")
    oracle = value.get("oracle")
    if (
        not isinstance(oracle, dict)
        or set(oracle) != {"kind", "expected", "deterministic", "llm_judge_sufficient"}
        or not _text(oracle.get("kind"), 100)
        or not _text(oracle.get("expected"), 1000)
    ):
        raise ValueError("proposed test oracle is invalid")
    for field in ("negative_control", "mutation_validation"):
        control = value.get(field)
        if (
            not isinstance(control, dict)
            or set(control) != {"present", "description"}
            or not isinstance(control.get("present"), bool)
            or not _text(control.get("description"), 1000)
        ):
            raise ValueError(f"proposed test {field} is invalid")


def _document(path: Path, label: str) -> dict[str, Any]:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > _MAX_INPUT_BYTES
    ):
        raise ValueError(f"{label} is not a bounded regular file")
    value = strict_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    return value


def _regular_directory(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} is not a regular directory")
    return path.resolve()


def _confined(root: Path, relative: str) -> Path:
    candidate_path = Path(relative)
    if candidate_path.is_absolute() or ".." in candidate_path.parts:
        raise ValueError("path is not repository-relative")
    candidate = (root / candidate_path).resolve(strict=False)
    if candidate != root and root not in candidate.parents:
        raise ValueError("path escapes its allowed root")
    return candidate


def _safe_relative(value: object) -> bool:
    if not _text(value, 500):
        return False
    path = Path(str(value))
    return not path.is_absolute() and ".." not in path.parts


def _safe_root(value: object) -> bool:
    return _safe_relative(value) and str(value) not in {"", "."}


def _shell_control(value: str) -> bool:
    return any(token in value for token in (";", "&&", "||", "`", "$(", "\n", "\r"))


def _text(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_output(path: Path, workspace: Path, value: dict[str, Any]) -> None:
    root = _regular_directory(workspace, "disposable workspace")
    if path.is_absolute():
        resolved = path.resolve(strict=False)
        if resolved != root and root not in resolved.parents:
            raise ValueError("output escapes the disposable workspace")
    else:
        resolved = _confined(root, str(path))
    resolved.parent.mkdir(parents=True, exist_ok=True)
    if resolved.is_symlink():
        raise ValueError("output cannot be a symbolic link")
    temporary = resolved.with_name(f".{resolved.name}.tmp")
    temporary.write_text(strict_dumps(value) + "\n", encoding="utf-8")
    temporary.replace(resolved)


if __name__ == "__main__":
    raise SystemExit(main())
