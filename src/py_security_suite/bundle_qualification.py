from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path
from typing import Any

from .adapter_conformance import assess_adapter_conformance
from .config import SuiteConfig
from .doctor import assess_readiness
from .execution import sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_directory, resolve_regular_file


_SCHEMA_ID = "urn:project-py-security-suite:schema:bundle-qualification:1.1"
_MAX_EFFECTIVENESS_BYTES = 64 * 1024 * 1024


def qualify_bundle(
    *,
    target: Path,
    config: SuiteConfig,
    effectiveness_evaluation: Path | None = None,
    effectiveness_report: Path | None = None,
    effectiveness_sha256: str = "",
    minimum_effectiveness_labels: int = 0,
    minimum_effectiveness_tools: int = 0,
    required_effectiveness_tools: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Join static adapter contracts and activation-free scanner readiness."""
    adapters = assess_adapter_conformance()
    readiness = assess_readiness(target=target, config=config)
    adapter_failures = [
        {
            "adapter": row["adapter"],
            "failed_checks": [
                check["check"] for check in row["checks"] if not check["passed"]
            ],
        }
        for row in adapters["adapters"]
        if row["status"] != "pass"
    ]
    identities = [_tool_identity(item) for item in readiness["tools"]]
    readiness_actions = [
        {
            "priority": group["priority"],
            "blocking": group["blocking"],
            "category": group["category"],
            "subjects": group["subjects"],
            "required_action": group["required_action"],
        }
        for group in readiness["action_groups"]
    ]
    conformance_actions = [
        {
            "priority": "P0",
            "blocking": True,
            "category": "adapter_contract",
            "subjects": [item["adapter"]],
            "required_action": (
                "Repair the failed adapter SDK checks and rerun bundle qualification."
            ),
        }
        for item in adapter_failures
    ]
    effectiveness = _effectiveness_evidence(
        effectiveness_evaluation,
        report_path=effectiveness_report,
        sha256=effectiveness_sha256,
        minimum_labels=minimum_effectiveness_labels,
        minimum_tools=minimum_effectiveness_tools,
        required_tools=required_effectiveness_tools,
        current_identities={str(item["tool"]): item["sha256"] for item in identities},
    )
    effectiveness_actions = (
        []
        if effectiveness["qualified"]
        else [
            {
                "priority": "P0",
                "blocking": True,
                "category": "behavioral_qualification",
                "subjects": effectiveness["missing_required_tools"]
                or ["scanner-effectiveness"],
                "required_action": effectiveness["required_action"],
            }
        ]
    )
    qualified = (
        adapters["status"] == "pass"
        and readiness["ready"]
        and effectiveness["qualified"]
    )
    payload: dict[str, Any] = {
        "schema_version": "1.1",
        "schema_id": _SCHEMA_ID,
        "authoritative": False,
        "qualification_scope": (
            "static-readiness+behavioral-evidence"
            if effectiveness["status"] != "not_provided"
            else "static-readiness"
        ),
        "target": readiness["target"],
        "profile": readiness["profile"],
        "platform": {
            "system": platform.system().casefold() or "unknown",
            "machine": platform.machine().casefold() or "unknown",
            "python": platform.python_version(),
        },
        "decision": {
            "disposition": "qualify" if qualified else "block",
            "adapter_contracts": adapters["status"],
            "profile_readiness": "ready" if readiness["ready"] else "not_ready",
            "behavioral_evidence": effectiveness["decision"],
            "scanner_execution_performed": False,
            "release_approval": False,
        },
        "summary": {
            "registered_adapters": adapters["summary"]["adapters"],
            "conformant_adapters": adapters["summary"]["passed"],
            "adapter_checks": adapters["summary"]["checks"],
            "selected_controls": readiness["summary"]["selected"],
            "applicable_controls": readiness["summary"]["applicable"],
            "ready_controls": readiness["summary"]["ready"],
            "required_applicable": readiness["summary"]["required_applicable"],
            "required_ready": readiness["summary"]["required_ready"],
            "not_applicable": readiness["summary"]["not_applicable"],
            "attention": readiness["summary"]["attention"],
            "observed_digests": len(
                {item["sha256"] for item in identities if item["sha256"]}
            ),
            "organization_approved": sum(
                item["organization_approved"] is True for item in identities
            ),
            "effectiveness_labels": effectiveness["labels"],
            "effectiveness_tools": effectiveness["tools"],
        },
        "behavioral_evidence": {
            key: value for key, value in effectiveness.items() if key != "qualified"
        },
        "adapter_failures": adapter_failures,
        "context_errors": readiness["context_errors"],
        "actions": sorted(
            [*conformance_actions, *readiness_actions, *effectiveness_actions],
            key=lambda item: (
                item["priority"],
                not item["blocking"],
                item["category"],
                item["subjects"],
            ),
        ),
        "tools": identities,
        "scope": (
            "Activation-free bundle qualification: validates adapter contracts, "
            "applicability, configured assets, executable identity, and profile "
            "readiness without running scanners. When supplied, it also binds and "
            "evaluates an independently generated labeled-corpus receipt; it does not "
            "rerun scanners, prove external isolation, signer identity, or release "
            "approval."
        ),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["qualification_id"] = (
        "qualification-" + hashlib.sha256(canonical.encode()).hexdigest()[:24]
    )
    return payload


def render_bundle_qualification(document: dict[str, Any]) -> str:
    summary = document["summary"]
    disposition = str(document["decision"]["disposition"]).upper()
    lines = [
        f"{disposition}: bundle {document['qualification_id']}",
        f"Profile: {document['profile']} | Target: {document['target']}",
        (
            f"Adapters: {summary['conformant_adapters']}/"
            f"{summary['registered_adapters']} conformant; "
            f"{summary['adapter_checks']} static checks"
        ),
        (
            f"Controls: {summary['ready_controls']}/"
            f"{summary['applicable_controls']} applicable ready; "
            f"{summary['not_applicable']} not applicable; "
            f"{summary['attention']} need attention"
        ),
        (
            f"Identity: {summary['observed_digests']} unique digest(s); "
            f"{summary['organization_approved']} approved control entry point(s)"
        ),
        (
            "Behavior: "
            f"{str(document['decision']['behavioral_evidence']).upper()}; "
            f"{summary['effectiveness_labels']} label(s), "
            f"{summary['effectiveness_tools']} named tool(s)"
        ),
    ]
    if document["actions"]:
        lines.append("Actions:")
        lines.extend(
            f"- {item['priority']} {'BLOCK' if item['blocking'] else 'PREPARE'} "
            f"[{item['category'].replace('_', ' ')}] "
            f"{', '.join(item['subjects'])}: {item['required_action']}"
            for item in document["actions"]
        )
    else:
        lines.append("Actions: none; proceed to the externally isolated scan lane.")
    lines.append(f"Scope: {document['scope']}")
    return "\n".join(lines)


def render_bundle_qualification_markdown(document: dict[str, Any]) -> str:
    summary = document["summary"]
    disposition = str(document["decision"]["disposition"]).upper()
    lines = [
        "# Scanner bundle qualification",
        "",
        f"**Decision:** {disposition}  ",
        f"**Qualification:** `{document['qualification_id']}`  ",
        f"**Profile:** `{document['profile']}`  ",
        f"**Scope:** `{document['qualification_scope']}`",
        "",
        "## Evidence summary",
        "",
        "| Measure | Result |",
        "|---|---:|",
        (
            f"| Adapter contracts | {summary['conformant_adapters']} / "
            f"{summary['registered_adapters']} |"
        ),
        f"| Static adapter checks | {summary['adapter_checks']} |",
        (
            f"| Applicable controls ready | {summary['ready_controls']} / "
            f"{summary['applicable_controls']} |"
        ),
        (
            f"| Required controls ready | {summary['required_ready']} / "
            f"{summary['required_applicable']} |"
        ),
        f"| Conditional controls not applicable | {summary['not_applicable']} |",
        f"| Controls needing attention | {summary['attention']} |",
        f"| Unique executable digests | {summary['observed_digests']} |",
        f"| Organization-approved entry points | {summary['organization_approved']} |",
        f"| Effectiveness labels | {summary['effectiveness_labels']} |",
        f"| Effectiveness tools | {summary['effectiveness_tools']} |",
        "",
        "## Required actions",
        "",
        "| Priority | Disposition | Category | Subjects | Action |",
        "|---|---|---|---|---|",
    ]
    if document["actions"]:
        lines.extend(
            f"| {item['priority']} | {'BLOCK' if item['blocking'] else 'PREPARE'} | "
            f"{item['category'].replace('_', ' ')} | "
            f"{', '.join(item['subjects'])} | {item['required_action']} |"
            for item in document["actions"]
        )
    else:
        lines.append(
            "| - | PROCEED | - | All selected controls | Run the isolated scan. |"
        )
    lines.extend(
        [
            "",
            "<details>",
            f"<summary>Per-control identity and readiness ({len(document['tools'])})</summary>",
            "",
            "| Control | Status | Required | Entry point | SHA-256 | Integrity | Approved |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    lines.extend(
        f"| `{item['tool']}` | {item['status']} | "
        f"{'yes' if item['required'] else 'no'} | `{item['entrypoint'] or '-'}` | "
        f"`{item['sha256'] or '-'}` | {_state(item['integrity_verified'])} | "
        f"{_state(item['organization_approved'])} |"
        for item in document["tools"]
    )
    lines.extend(
        [
            "",
            "</details>",
            "",
            f"> {document['scope']}",
        ]
    )
    return "\n".join(lines) + "\n"


def _tool_identity(item: dict[str, Any]) -> dict[str, Any]:
    executable = str(item.get("executable") or "")
    return {
        "tool": item["tool"],
        "status": item["status"],
        "category": item["category"],
        "required": item["required"],
        "entrypoint": _entrypoint_name(executable),
        "sha256": item.get("executable_sha256"),
        "integrity_verified": item.get("executable_integrity_verified"),
        "organization_approved": item.get("executable_organization_approved", False),
    }


def _state(value: object) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def _entrypoint_name(value: str) -> str | None:
    """Return a portable basename without retaining a configured host path."""
    normalized = value.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1] if normalized else None


def _effectiveness_evidence(
    source: Path | None,
    *,
    report_path: Path | None,
    sha256: str,
    minimum_labels: int,
    minimum_tools: int,
    required_tools: tuple[str, ...],
    current_identities: dict[str, object],
) -> dict[str, Any]:
    required = _effectiveness_limits(minimum_labels, minimum_tools, required_tools)
    evidence_required = bool(minimum_labels or minimum_tools or required)
    if source is None:
        return _missing_effectiveness_evidence(
            report_path=report_path,
            sha256=sha256,
            minimum_labels=minimum_labels,
            minimum_tools=minimum_tools,
            required=required,
        )
    if report_path is None:
        raise ValueError(
            "behavioral qualification requires the verified report that produced "
            "the effectiveness evaluation"
        )
    document, observed = _read_effectiveness_evaluation(source, sha256)
    labels = _effectiveness_labels(document)
    corpus = _object(document.get("corpus"), "effectiveness corpus")
    _validate_effectiveness_label_count(corpus, labels)
    report_verification, manifest, evaluation_report_digest = (
        _verified_effectiveness_report(document, report_path)
    )
    tools = _named_effectiveness_tools(labels)
    tool_bindings = _behavioral_tool_bindings(
        tools,
        manifest=manifest,
        current_identities=current_identities,
    )
    identity_mismatches = [
        str(item["tool"]) for item in tool_bindings if item["matched"] is not True
    ]
    missing = sorted(set(required) - set(tools))
    positive = sum(item.get("expected") == "finding" for item in labels)
    negative = sum(item.get("expected") == "clean" for item in labels)
    verdict = str(document.get("verdict") or "")
    failures = document.get("failures")
    if verdict not in {"pass", "fail"} or not isinstance(failures, list):
        raise ValueError("effectiveness evaluation verdict or failures are invalid")
    threshold_failures = _effectiveness_threshold_failures(
        labels=len(labels),
        tools=len(tools),
        minimum_labels=minimum_labels,
        minimum_tools=minimum_tools,
        missing=missing,
        identity_mismatches=identity_mismatches,
    )
    qualified = verdict == "pass" and not failures and not threshold_failures
    return {
        "status": "verified",
        "decision": "pass" if qualified else "fail",
        "required": evidence_required,
        "sha256": observed,
        "verdict": verdict,
        "corpus_id": _bounded(corpus.get("id"), 200),
        "report_checksums_sha256": evaluation_report_digest,
        "report_scan_id": _bounded(report_verification.get("scan_id"), 200),
        "labels": len(labels),
        "positive_labels": positive,
        "negative_labels": negative,
        "tools": len(tools),
        "tool_names": tools,
        "required_tools": required,
        "missing_required_tools": missing,
        "identity_mismatches": identity_mismatches,
        "tool_bindings": tool_bindings,
        "minimum_labels": minimum_labels,
        "minimum_tools": minimum_tools,
        "required_action": (
            "No action; retain this receipt with the scanner bundle qualification."
            if qualified
            else "Repair the labeled-corpus failures or configured effectiveness "
            "minimums, regenerate the sealed scan and evaluation, then requalify. "
            + "; ".join(threshold_failures)
        ),
        "qualified": qualified,
    }


def _effectiveness_limits(
    minimum_labels: int,
    minimum_tools: int,
    required_tools: tuple[str, ...],
) -> list[str]:
    if minimum_labels < 0 or minimum_labels > 10_000:
        raise ValueError("minimum effectiveness labels must be between 0 and 10000")
    if minimum_tools < 0 or minimum_tools > 1000:
        raise ValueError("minimum effectiveness tools must be between 0 and 1000")
    return sorted({_tool_name(item) for item in required_tools})


def _missing_effectiveness_evidence(
    *,
    report_path: Path | None,
    sha256: str,
    minimum_labels: int,
    minimum_tools: int,
    required: list[str],
) -> dict[str, Any]:
    if report_path is not None:
        raise ValueError("effectiveness report requires an evaluation file")
    if sha256:
        raise ValueError("effectiveness SHA-256 requires an evaluation file")
    evidence_required = bool(minimum_labels or minimum_tools or required)
    return {
        "status": "not_provided",
        "decision": "required_missing" if evidence_required else "not_required",
        "required": evidence_required,
        "sha256": None,
        "verdict": None,
        "corpus_id": None,
        "report_checksums_sha256": None,
        "report_scan_id": None,
        "labels": 0,
        "positive_labels": 0,
        "negative_labels": 0,
        "tools": 0,
        "tool_names": [],
        "required_tools": required,
        "missing_required_tools": required,
        "identity_mismatches": [],
        "tool_bindings": [],
        "minimum_labels": minimum_labels,
        "minimum_tools": minimum_tools,
        "required_action": (
            "Generate a passing digest-bound labeled-corpus evaluation that "
            "satisfies the configured minimums."
            if evidence_required
            else "No behavioral evidence was required for this static assessment."
        ),
        "qualified": not evidence_required,
    }


def _read_effectiveness_evaluation(
    source: Path, expected_sha256: str
) -> tuple[dict[str, Any], str]:
    expected = expected_sha256.strip().casefold()
    if _digest_or_none(expected) is None:
        raise ValueError(
            "effectiveness evaluation SHA-256 must be exactly 64 hexadecimal characters"
        )
    path = resolve_regular_file(source, "effectiveness evaluation")
    if path.stat().st_size > _MAX_EFFECTIVENESS_BYTES:
        raise ValueError("effectiveness evaluation exceeds the bounded size limit")
    observed = sha256_file(path)
    if observed != expected:
        raise ValueError(
            "effectiveness evaluation digest does not match the approved SHA-256"
        )
    try:
        document = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("effectiveness evaluation is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or document.get("schema_version") != "1.0":
        raise ValueError("effectiveness evaluation schema_version must be '1.0'")
    return document, observed


def _validate_effectiveness_label_count(
    corpus: dict[str, Any], labels: list[dict[str, Any]]
) -> None:
    declared = corpus.get("labels")
    if (
        not isinstance(declared, int)
        or isinstance(declared, bool)
        or declared != len(labels)
    ):
        raise ValueError(
            "effectiveness label count does not match the corpus declaration"
        )


def _verified_effectiveness_report(
    evaluation: dict[str, Any], report_path: Path
) -> tuple[dict[str, Any], dict[str, Any], str]:
    evaluation_report = _object(evaluation.get("report"), "effectiveness report")
    root = resolve_regular_directory(report_path, "effectiveness report")
    verification = verify_report(root)
    digest = _digest_or_none(evaluation_report.get("checksums_sha256"))
    if digest is None or digest != str(verification["checksums_sha256"]):
        raise ValueError(
            "effectiveness evaluation is not bound to the supplied verified report"
        )
    return verification, _read_report_manifest(root), digest


def _named_effectiveness_tools(labels: list[dict[str, Any]]) -> list[str]:
    names: set[str] = set()
    for item in labels:
        match = _object(item.get("match"), "effectiveness label match")
        if str(match.get("tool") or "").strip():
            names.add(_tool_name(match.get("tool")))
    return sorted(names)


def _effectiveness_threshold_failures(
    *,
    labels: int,
    tools: int,
    minimum_labels: int,
    minimum_tools: int,
    missing: list[str],
    identity_mismatches: list[str],
) -> list[str]:
    failures: list[str] = []
    if labels < minimum_labels:
        failures.append(f"labels {labels} are below the required {minimum_labels}")
    if tools < minimum_tools:
        failures.append(f"named tools {tools} are below the required {minimum_tools}")
    if missing:
        failures.append("required tool evidence is missing: " + ", ".join(missing))
    if identity_mismatches:
        failures.append(
            "scanner identity does not match the current unchanged bundle: "
            + ", ".join(identity_mismatches)
        )
    return failures


def _effectiveness_labels(document: dict[str, Any]) -> list[dict[str, Any]]:
    labels = document.get("label_outcomes")
    if (
        not isinstance(labels, list)
        or not labels
        or len(labels) > 10_000
        or any(not isinstance(item, dict) for item in labels)
    ):
        raise ValueError(
            "effectiveness label outcomes must be a bounded non-empty array"
        )
    return labels


def _read_report_manifest(root: Path) -> dict[str, Any]:
    source = resolve_regular_file(root / "scan-manifest.json", "scan manifest")
    if source.stat().st_size > _MAX_EFFECTIVENESS_BYTES:
        raise ValueError("scan manifest exceeds the bounded size limit")
    try:
        value = json.loads(source.read_bytes(), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("scan manifest is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("scan manifest root must be an object")
    return value


def _behavioral_tool_bindings(
    tools: list[str],
    *,
    manifest: dict[str, Any],
    current_identities: dict[str, object],
) -> list[dict[str, Any]]:
    values = manifest.get("tools")
    if not isinstance(values, list) or any(
        not isinstance(item, dict) for item in values
    ):
        raise ValueError("scan manifest tools must be an array of objects")
    indexed = {str(item.get("tool") or "").casefold(): item for item in values}
    bindings: list[dict[str, Any]] = []
    for tool in tools:
        row = indexed.get(tool, {})
        report_digest = _digest_or_none(row.get("executable_sha256"))
        current_digest = _digest_or_none(current_identities.get(tool))
        completed = (
            row.get("applicable", True) is not False
            and str(row.get("status") or "") == "completed"
        )
        unchanged = row.get("executable_unchanged") is True
        matched = (
            report_digest is not None
            and current_digest is not None
            and report_digest == current_digest
            and completed
            and unchanged
        )
        bindings.append(
            {
                "tool": tool,
                "version": _bounded(row.get("version"), 500),
                "report_sha256": report_digest,
                "current_sha256": current_digest,
                "completed": completed,
                "unchanged": unchanged,
                "matched": matched,
            }
        )
    return bindings


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _tool_name(value: object) -> str:
    name = str(value or "").strip().casefold()
    if (
        not name
        or len(name) > 200
        or any(character in name for character in "\r\n\x00")
    ):
        raise ValueError("effectiveness tool names must be bounded non-empty strings")
    return name


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("effectiveness evaluation contains a duplicate object key")
        result[key] = value
    return result


def _bounded(value: object, maximum: int) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ")[:maximum]


def _digest_or_none(value: object) -> str | None:
    digest = str(value or "").casefold()
    return (
        digest
        if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
        else None
    )
