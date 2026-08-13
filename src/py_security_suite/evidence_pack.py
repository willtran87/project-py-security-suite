from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .audience_report import AUDIENCES, build_audience_report, render_audience_markdown
from .audit_package import create_audit_package, verify_audit_package
from .baseline_candidate import build_baseline_candidate
from .config_provenance import build_config_provenance
from .evidence_draft import build_governance_evidence_draft
from .execution import sha256_file
from .finding_register import build_finding_register
from .github_annotations import build_github_annotations, render_github_commands
from .passport import verify_report
from .path_safety import is_link_like, resolve_regular_file, resolve_unlinked_path
from .policy_simulation import simulate_policy
from .portfolio_dashboard import build_portfolio_dashboard
from .promotion import (
    build_promotion_plan,
    render_promotion_html,
    render_promotion_markdown,
)
from .reachability_delta import compare_reachability
from .release_manifest import (
    build_release_evidence_manifest,
    verify_release_evidence_manifest,
)
from .release_readiness import assess_release_readiness
from .release_payload import prepare_signing_request, verify_signing_request
from .operational_trend import (
    build_operational_trend,
    render_operational_trend_markdown,
)
from .report_inspection import (
    inspect_report,
    report_verification_receipt,
    verify_inspection,
)

_CONTROL_FILES = {"COMPLETE", "checksums.sha256", "pack-manifest.json"}
_MAX_FILES = 1_000
_MAX_FILE_BYTES = 128 * 1024 * 1024
_PACK_SCHEMA = "1.0"
_RELEASE_EVIDENCE = (
    "release-readiness",
    "governance-evidence-draft",
    "promotion-plan",
    "finding-register",
    "github-annotations",
    "audience-executive",
)
_OPTIONAL_RELEASE_INPUTS = (
    "effectiveness-evaluation",
    "passport-verification",
)


def create_evidence_pack(
    report: Path,
    output: Path,
    *,
    previous_register: Path | None = None,
    previous_register_sha256: str = "",
    previous_report: Path | None = None,
    artifacts: Path | None = None,
    organization_policy: Path | None = None,
    repository_config: Path | None = None,
    profile_override: str | None = None,
    effectiveness_evaluation: Path | None = None,
    effectiveness_sha256: str = "",
    minimum_effectiveness_labels: int = 0,
    minimum_effectiveness_positive_labels: int = 0,
    minimum_effectiveness_negative_labels: int = 0,
    minimum_effectiveness_tools: int = 0,
    minimum_effectiveness_labels_per_tool: int = 0,
    required_effectiveness_tools: tuple[str, ...] = (),
    passport_verification: Path | None = None,
    passport_verification_sha256: str = "",
    require_passport: bool = False,
    block_severities: tuple[str, ...] = ("critical", "high"),
    required_tools: tuple[str, ...] = (),
    minimum_confidence: str = "unknown",
    maximum_blocking_findings: int = 0,
    performance_regression_percent: float = 50.0,
    maximum_total_seconds: float | None = None,
    tool_budgets: dict[str, float] | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Atomically publish a portable, closed set of release decision evidence."""
    verification = verify_report(report)
    report_root = report.expanduser().resolve()
    destination = _destination(output, report_root)
    _validate_replacement(destination, overwrite=overwrite)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=destination.parent)
    )
    backup: Path | None = None
    try:
        _build_payload(
            report_root,
            staging,
            previous_register=previous_register,
            previous_register_sha256=previous_register_sha256,
            previous_report=previous_report,
            artifacts=artifacts,
            organization_policy=organization_policy,
            repository_config=repository_config,
            profile_override=profile_override,
            effectiveness_evaluation=effectiveness_evaluation,
            effectiveness_sha256=effectiveness_sha256,
            minimum_effectiveness_labels=minimum_effectiveness_labels,
            minimum_effectiveness_positive_labels=minimum_effectiveness_positive_labels,
            minimum_effectiveness_negative_labels=minimum_effectiveness_negative_labels,
            minimum_effectiveness_tools=minimum_effectiveness_tools,
            minimum_effectiveness_labels_per_tool=minimum_effectiveness_labels_per_tool,
            required_effectiveness_tools=required_effectiveness_tools,
            passport_verification=passport_verification,
            passport_verification_sha256=passport_verification_sha256,
            require_passport=require_passport,
            block_severities=block_severities,
            required_tools=required_tools,
            minimum_confidence=minimum_confidence,
            maximum_blocking_findings=maximum_blocking_findings,
            performance_regression_percent=performance_regression_percent,
            maximum_total_seconds=maximum_total_seconds,
            tool_budgets=tool_budgets,
        )
        manifest = _publish_controls(staging, verification)
        _verify_directory(staging, report=report_root)
        if destination.exists():
            backup = destination.with_name(f".{destination.name}.backup-{os.getpid()}")
            if backup.exists():
                raise ValueError(f"evidence pack backup path already exists: {backup}")
            os.replace(destination, backup)
        try:
            os.replace(staging, destination)
        except BaseException:
            if backup is not None:
                os.replace(backup, destination)
                backup = None
            raise
        if backup is not None:
            shutil.rmtree(backup)
            backup = None
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if backup is not None and not destination.exists():
            os.replace(backup, destination)
    return _creation_receipt(destination, manifest)


def verify_evidence_pack(
    pack: Path,
    *,
    report: Path | None = None,
    pack_sha256: str = "",
) -> dict[str, Any]:
    """Verify a closed evidence pack, its audit archive, and optional source report."""
    root = resolve_unlinked_path(pack, "evidence pack")
    if not root.is_dir():
        raise ValueError(f"evidence pack is not a regular directory: {root}")
    return _verify_directory(root, report=report, pack_sha256=pack_sha256)


def _build_payload(
    report: Path,
    root: Path,
    *,
    previous_register: Path | None,
    previous_register_sha256: str,
    previous_report: Path | None,
    artifacts: Path | None,
    organization_policy: Path | None,
    repository_config: Path | None,
    profile_override: str | None,
    effectiveness_evaluation: Path | None,
    effectiveness_sha256: str,
    minimum_effectiveness_labels: int,
    minimum_effectiveness_positive_labels: int,
    minimum_effectiveness_negative_labels: int,
    minimum_effectiveness_tools: int,
    minimum_effectiveness_labels_per_tool: int,
    required_effectiveness_tools: tuple[str, ...],
    passport_verification: Path | None,
    passport_verification_sha256: str,
    require_passport: bool,
    block_severities: tuple[str, ...],
    required_tools: tuple[str, ...],
    minimum_confidence: str,
    maximum_blocking_findings: int,
    performance_regression_percent: float,
    maximum_total_seconds: float | None,
    tool_budgets: dict[str, float] | None,
) -> None:
    verification = verify_report(report)
    _copy_sealed_report(report, root / "report")
    retained_inputs = _retain_approved_release_inputs(
        root,
        effectiveness_evaluation=effectiveness_evaluation,
        effectiveness_sha256=effectiveness_sha256,
        passport_verification=passport_verification,
        passport_verification_sha256=passport_verification_sha256,
    )
    _write_json(
        root / "report-verification.json", report_verification_receipt(verification)
    )
    inspection_path = root / "inspection.json"
    _write_json(inspection_path, inspect_report(report))
    _write_json(
        root / "inspection-verification.json",
        verify_inspection(inspection_path, report=report),
    )
    readiness_path = root / "release-readiness.json"
    readiness = assess_release_readiness(
        report,
        effectiveness_evaluation=effectiveness_evaluation,
        effectiveness_sha256=effectiveness_sha256,
        minimum_effectiveness_labels=minimum_effectiveness_labels,
        minimum_effectiveness_positive_labels=minimum_effectiveness_positive_labels,
        minimum_effectiveness_negative_labels=minimum_effectiveness_negative_labels,
        minimum_effectiveness_tools=minimum_effectiveness_tools,
        minimum_effectiveness_labels_per_tool=minimum_effectiveness_labels_per_tool,
        required_effectiveness_tools=required_effectiveness_tools,
        passport_verification=passport_verification,
        passport_verification_sha256=passport_verification_sha256,
        require_passport=require_passport,
    )
    _make_readiness_portable(readiness, retained_inputs)
    _write_json(
        readiness_path,
        readiness,
    )
    readiness_digest = sha256_file(readiness_path)
    _write_json(
        root / "governance-evidence-draft.json",
        build_governance_evidence_draft(report),
    )
    reports = [report]
    trend_path: Path | None = None
    trend_digest = ""
    if previous_report is not None:
        reports.insert(0, previous_report)
        trend_path = root / "operational-trend.json"
        trend = build_operational_trend(
            reports,
            performance_regression_percent=performance_regression_percent,
            maximum_total_seconds=maximum_total_seconds,
            tool_budgets=tool_budgets,
        )
        _write_json(trend_path, trend)
        (root / "operational-trend.md").write_text(
            render_operational_trend_markdown(trend),
            encoding="utf-8",
            newline="\n",
        )
        trend_digest = sha256_file(trend_path)
    plan = build_promotion_plan(
        report,
        release_readiness=readiness_path,
        release_readiness_sha256=readiness_digest,
        operational_trend=trend_path,
        operational_trend_sha256=trend_digest,
    )
    plan_path = root / "promotion-plan.json"
    _write_json(plan_path, plan)
    (root / "promotion-plan.md").write_text(
        render_promotion_markdown(plan), encoding="utf-8", newline="\n"
    )
    (root / "promotion-plan.html").write_text(
        render_promotion_html(plan), encoding="utf-8", newline="\n"
    )
    plan_digest = sha256_file(plan_path)
    if previous_report is not None and previous_register is None:
        previous_register_path = root / "previous-finding-register.json"
        _write_json(
            previous_register_path,
            build_finding_register(previous_report),
        )
        previous_register = previous_register_path
        previous_register_sha256 = sha256_file(previous_register_path)
    register = build_finding_register(
        report,
        previous=previous_register,
        previous_sha256=previous_register_sha256,
    )
    _write_json(root / "finding-register.json", register)
    annotations = build_github_annotations(
        plan_path, plan_sha256=plan_digest, report=report
    )
    _write_json(root / "github-annotations.json", annotations)
    (root / "github-annotations.txt").write_text(
        render_github_commands(annotations), encoding="utf-8", newline="\n"
    )
    for audience in AUDIENCES:
        view = build_audience_report(
            plan_path,
            plan_sha256=plan_digest,
            report=report,
            audience=audience,
        )
        _write_json(root / f"audience-{audience}.json", view)
        (root / f"audience-{audience}.md").write_text(
            render_audience_markdown(view), encoding="utf-8", newline="\n"
        )
    _write_json(root / "baseline-candidate.json", build_baseline_candidate(report))
    if previous_report is not None:
        _write_reachability_delta(previous_report, report, root)
    _write_json(root / "portfolio.json", build_portfolio_dashboard(reports))
    _write_json(
        root / "policy-simulation.json",
        simulate_policy(
            report,
            block_severities=block_severities,
            required_tools=required_tools,
            minimum_confidence=minimum_confidence,
            maximum_blocking_findings=maximum_blocking_findings,
        ),
    )
    if any(
        value is not None
        for value in (organization_policy, repository_config, profile_override)
    ):
        provenance = build_config_provenance(
            organization_policy=organization_policy,
            repository_config=repository_config,
            profile_override=profile_override,
        )
        _validate_config_profile(provenance, report)
        _make_provenance_portable(provenance)
        _write_json(root / "config-provenance.json", provenance)
    if artifacts is not None:
        signing_path = root / "signing-request.json"
        _write_json(signing_path, prepare_signing_request(report, artifacts))
        _write_json(
            root / "signing-request-verification.json",
            verify_signing_request(
                signing_path,
                artifacts,
                request_sha256=sha256_file(signing_path),
            ),
        )
    evidence_names = (*_RELEASE_EVIDENCE, *retained_inputs)
    evidence = _named_evidence(root, evidence_names)
    release_manifest_path = root / "release-evidence-manifest.json"
    _write_json(
        release_manifest_path,
        build_release_evidence_manifest(report, evidence=evidence, path_base=root),
    )
    manifest_digest = sha256_file(release_manifest_path)
    _write_json(
        root / "release-evidence-manifest-verification.json",
        verify_release_evidence_manifest(
            release_manifest_path,
            manifest_sha256=manifest_digest,
            report=report,
            required_evidence=evidence_names,
        ),
    )
    audit_evidence = _named_evidence(
        root,
        (
            *evidence_names,
            "release-evidence-manifest",
            "release-evidence-manifest-verification",
        ),
    )
    audit_path = root / "audit-package.zip"
    audit_creation = create_audit_package(report, audit_path, evidence=audit_evidence)
    audit_digest = str(audit_creation["package"]["sha256"])
    audit_creation["package"]["path"] = "audit-package.zip"
    _write_json(root / "audit-package-creation.json", audit_creation)
    audit_verification = verify_audit_package(audit_path, package_sha256=audit_digest)
    audit_verification["package"]["path"] = "audit-package.zip"
    _write_json(root / "audit-package-verification.json", audit_verification)
    (root / "README.md").write_text(
        _pack_readme(root, plan, register, audit_digest),
        encoding="utf-8",
        newline="\n",
    )


def _publish_controls(root: Path, verification: dict[str, Any]) -> dict[str, Any]:
    files = [_file_record(path, root) for path in _payload_files(root)]
    manifest = {
        "schema_version": _PACK_SCHEMA,
        "closed_set": True,
        "authoritative": False,
        "scope": "Portable decision-support evidence; external admission, approval, and signing remain required.",
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
            "outcome": verification["outcome"],
        },
        "files": files,
        "required_authorities": [
            "controlled-signing",
            "organization-security",
            "release-approver",
        ],
    }
    _write_json(root / "pack-manifest.json", manifest)
    manifest_digest = sha256_file(root / "pack-manifest.json")
    lines = [f"{record['sha256']}  {record['path']}" for record in files] + [
        f"{manifest_digest}  pack-manifest.json"
    ]
    (root / "checksums.sha256").write_text(
        "\n".join(lines) + "\n", encoding="ascii", newline="\n"
    )
    (root / "COMPLETE").write_text(
        f"evidence-pack-v{_PACK_SCHEMA}\npack-manifest-sha256={manifest_digest}\n",
        encoding="ascii",
        newline="\n",
    )
    return manifest


def _verify_directory(
    root: Path,
    *,
    report: Path | None,
    pack_sha256: str = "",
) -> dict[str, Any]:
    _reject_links(root)
    manifest_path = root / "pack-manifest.json"
    manifest = _read_object(manifest_path, "evidence pack manifest")
    _validate_manifest(manifest)
    manifest_digest = sha256_file(manifest_path)
    if pack_sha256 and _digest(pack_sha256, "evidence pack SHA-256") != manifest_digest:
        raise ValueError("evidence pack does not match its approved SHA-256")
    expected = {str(item["path"]): item for item in manifest["files"]}
    actual = {
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
    }
    if actual != set(expected) | _CONTROL_FILES:
        raise ValueError("evidence pack file set does not match its closed manifest")
    for name, record in expected.items():
        source = root.joinpath(*PurePosixPath(name).parts)
        if (
            source.stat().st_size != record["size_bytes"]
            or sha256_file(source) != record["sha256"]
        ):
            raise ValueError(f"evidence pack file identity mismatch: {name}")
    _verify_control_files(root, expected, manifest_digest)
    audit = _read_object(root / "audit-package-creation.json", "audit creation receipt")
    audit_digest = _digest(
        str(audit.get("package", {}).get("sha256") or ""), "audit package SHA-256"
    )
    audit_verification = verify_audit_package(
        root / "audit-package.zip", package_sha256=audit_digest
    )
    report_identity = audit_verification["report"]
    if report_identity["checksums_sha256"] != manifest["report"]["checksums_sha256"]:
        raise ValueError(
            "evidence pack report identity does not match its audit archive"
        )
    if report is not None:
        source_verification = verify_report(report)
        if (
            source_verification["checksums_sha256"]
            != manifest["report"]["checksums_sha256"]
        ):
            raise ValueError("evidence pack is not bound to the supplied report")
        release_manifest = root / "release-evidence-manifest.json"
        required_evidence = (
            *_RELEASE_EVIDENCE,
            *(
                name
                for name in _OPTIONAL_RELEASE_INPUTS
                if (root / f"{name}.json").is_file()
            ),
        )
        verify_release_evidence_manifest(
            release_manifest,
            manifest_sha256=sha256_file(release_manifest),
            report=report,
            required_evidence=required_evidence,
        )
    return {
        "schema_version": _PACK_SCHEMA,
        "verified": True,
        "authoritative": False,
        "admission": "requires_external_approval",
        "pack": {
            "path": str(root),
            "sha256": manifest_digest,
            "files_verified": len(actual),
        },
        "report": dict(manifest["report"]),
        "audit_package": {
            "sha256": audit_digest,
            "files_verified": audit_verification["package"]["files_verified"],
        },
        "required_authorities": list(manifest["required_authorities"]),
    }


def _validate_manifest(manifest: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "closed_set",
        "authoritative",
        "scope",
        "report",
        "files",
        "required_authorities",
    }
    if set(manifest) != required or manifest.get("schema_version") != _PACK_SCHEMA:
        raise ValueError("evidence pack manifest contract is invalid")
    _validate_manifest_header(manifest)
    _validate_report_identity(manifest.get("report"))
    _validate_file_records(manifest.get("files"))
    _validate_authorities(manifest.get("required_authorities"))


def _validate_manifest_header(manifest: dict[str, Any]) -> None:
    if (
        manifest.get("closed_set") is not True
        or manifest.get("authoritative") is not False
    ):
        raise ValueError("evidence pack must be closed and non-authoritative")
    if not isinstance(manifest.get("scope"), str) or not manifest["scope"]:
        raise ValueError("evidence pack scope must be non-empty")


def _validate_report_identity(value: object) -> None:
    report = value
    if not isinstance(report, dict) or set(report) != {
        "scan_id",
        "checksums_sha256",
        "outcome",
    }:
        raise ValueError("evidence pack report identity is invalid")
    _digest(str(report.get("checksums_sha256") or ""), "report checksum seal")
    if not isinstance(report.get("scan_id"), str) or not report["scan_id"]:
        raise ValueError("evidence pack scan ID is invalid")
    if report.get("outcome") not in {"pass", "warn", "fail", "incomplete"}:
        raise ValueError("evidence pack outcome is invalid")


def _validate_file_records(value: object) -> None:
    files = value
    if not isinstance(files, list) or not files or len(files) > _MAX_FILES:
        raise ValueError(
            "evidence pack manifest files must be a bounded non-empty array"
        )
    names: set[str] = set()
    for record in files:
        name = _validate_file_record(record, names)
        names.add(name)


def _validate_file_record(value: object, names: set[str]) -> str:
    if not isinstance(value, dict) or set(value) != {
        "path",
        "sha256",
        "size_bytes",
    }:
        raise ValueError("evidence pack file record is invalid")
    name = str(value["path"])
    _validate_pack_path(name, names)
    _digest(str(value["sha256"]), f"evidence pack file {name} SHA-256")
    if type(value["size_bytes"]) is not int or not (
        0 <= value["size_bytes"] <= _MAX_FILE_BYTES
    ):
        raise ValueError(f"evidence pack file size is invalid: {name}")
    return name


def _validate_pack_path(name: str, names: set[str]) -> None:
    path = PurePosixPath(name)
    unsafe = (
        not name
        or name == "."
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or name.endswith("/")
        or any(ord(character) < 32 for character in name)
        or name in _CONTROL_FILES
        or name in names
    )
    if unsafe:
        raise ValueError(f"evidence pack file path is unsafe or duplicated: {name}")


def _validate_authorities(value: object) -> None:
    authorities = value
    if (
        not isinstance(authorities, list)
        or not authorities
        or not all(isinstance(item, str) and item for item in authorities)
        or len(authorities) != len(set(authorities))
    ):
        raise ValueError("evidence pack required authorities are invalid")


def _verify_control_files(
    root: Path, expected: dict[str, dict[str, Any]], manifest_digest: str
) -> None:
    complete = (root / "COMPLETE").read_text(encoding="ascii")
    expected_complete = (
        f"evidence-pack-v{_PACK_SCHEMA}\npack-manifest-sha256={manifest_digest}\n"
    )
    if complete != expected_complete:
        raise ValueError("evidence pack completion marker is invalid")
    lines = [f"{record['sha256']}  {name}" for name, record in expected.items()] + [
        f"{manifest_digest}  pack-manifest.json"
    ]
    if (root / "checksums.sha256").read_text(encoding="ascii") != "\n".join(
        lines
    ) + "\n":
        raise ValueError("evidence pack checksum index is invalid")


def _named_evidence(
    root: Path, names: tuple[str, ...]
) -> tuple[tuple[str, Path, str], ...]:
    return tuple(
        (name, root / f"{name}.json", sha256_file(root / f"{name}.json"))
        for name in names
    )


def _retain_approved_release_inputs(
    root: Path,
    *,
    effectiveness_evaluation: Path | None,
    effectiveness_sha256: str,
    passport_verification: Path | None,
    passport_verification_sha256: str,
) -> tuple[str, ...]:
    retained: list[str] = []
    inputs = (
        (
            "effectiveness-evaluation",
            effectiveness_evaluation,
            effectiveness_sha256,
        ),
        (
            "passport-verification",
            passport_verification,
            passport_verification_sha256,
        ),
    )
    for name, requested, approved_digest in inputs:
        if requested is None:
            if approved_digest:
                raise ValueError(f"{name} SHA-256 requires its input file")
            continue
        source = resolve_regular_file(requested, name.replace("-", " "))
        expected = _digest(approved_digest, f"{name} SHA-256")
        if sha256_file(source) != expected:
            raise ValueError(f"{name} does not match its approved SHA-256")
        _read_object(source, name.replace("-", " "))
        shutil.copyfile(source, root / f"{name}.json")
        retained.append(name)
    return tuple(retained)


def _make_readiness_portable(
    readiness: dict[str, Any], retained_inputs: tuple[str, ...]
) -> None:
    controls = readiness.get("controls")
    if not isinstance(controls, list):
        return
    replacements = {
        "detection-effectiveness": "effectiveness-evaluation.json",
        "signed-release-passport": "passport-verification.json",
    }
    retained = set(retained_inputs)
    for control in controls:
        if not isinstance(control, dict):
            continue
        name = replacements.get(str(control.get("id") or ""))
        if name and name.removesuffix(".json") in retained:
            control["evidence"] = [name]


def _copy_sealed_report(report: Path, destination: Path) -> None:
    for source in sorted(
        report.rglob("*"), key=lambda path: path.relative_to(report).as_posix()
    ):
        if is_link_like(source):
            raise ValueError(
                f"sealed report cannot contain links or junctions: {source}"
            )
        if source.is_dir():
            continue
        if not source.is_file():
            raise ValueError(f"sealed report contains an unsupported entry: {source}")
        relative = source.relative_to(report)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def _write_reachability_delta(previous: Path, report: Path, root: Path) -> None:
    baseline = previous.expanduser().resolve() / "reachability.json"
    current = report.expanduser().resolve() / "reachability.json"
    if baseline.is_file() and current.is_file():
        _write_json(
            root / "reachability-delta.json",
            compare_reachability(
                baseline,
                current,
                baseline_sha256=sha256_file(baseline),
                current_sha256=sha256_file(current),
            ),
        )


def _validate_config_profile(provenance: dict[str, Any], report: Path) -> None:
    manifest = _read_object(report / "scan-manifest.json", "scan manifest")
    effective = provenance.get("effective")
    profile = effective.get("profile") if isinstance(effective, dict) else None
    if profile != manifest.get("profile"):
        raise ValueError(
            "configuration provenance profile does not match the sealed report"
        )


def _make_provenance_portable(provenance: dict[str, Any]) -> None:
    sources = provenance.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("configuration provenance sources are invalid")
    for name in ("organization", "repository"):
        source = sources.get(name)
        if not isinstance(source, dict):
            raise ValueError("configuration provenance source is invalid")
        path = source.get("path")
        if isinstance(path, str) and path:
            source["path"] = Path(path).name


def _payload_files(root: Path) -> list[Path]:
    return sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file()
            and path.relative_to(root).as_posix() not in _CONTROL_FILES
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def _file_record(path: Path, root: Path) -> dict[str, Any]:
    size = path.stat().st_size
    if size > _MAX_FILE_BYTES:
        raise ValueError(f"evidence pack file exceeds 128 MiB: {path.name}")
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
        "size_bytes": size,
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _read_object(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError(f"{label} is missing or too large: {path}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise TypeError(f"{label} root must be an object")
    return value


def _destination(output: Path, report: Path) -> Path:
    requested = output.expanduser().absolute()
    destination = resolve_unlinked_path(
        requested, "evidence pack output", boundary=Path(requested.anchor)
    )
    if destination == report or destination.is_relative_to(report):
        raise ValueError("evidence pack output must be outside the sealed report")
    return destination


def _validate_replacement(destination: Path, *, overwrite: bool) -> None:
    if not destination.exists():
        return
    if not destination.is_dir():
        raise ValueError(
            f"evidence pack output exists and is not a directory: {destination}"
        )
    if not overwrite:
        raise ValueError(
            "evidence pack output already exists; choose a new path or use --overwrite"
        )
    verify_evidence_pack(destination)


def _reject_links(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        if is_link_like(path):
            raise ValueError(f"evidence pack cannot contain links or junctions: {path}")
        if path.is_dir() or path.is_file():
            continue
        raise ValueError(
            f"evidence pack contains an unsupported filesystem entry: {path}"
        )


def _digest(value: str, label: str) -> str:
    normalized = value.strip().casefold()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return normalized


def _creation_receipt(destination: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    digest = sha256_file(destination / "pack-manifest.json")
    return {
        "schema_version": _PACK_SCHEMA,
        "status": "candidate",
        "authoritative": False,
        "pack": {
            "path": str(destination),
            "sha256": digest,
            "files": len(manifest["files"]) + len(_CONTROL_FILES),
        },
        "report": dict(manifest["report"]),
        "entrypoint": "README.md",
        "verification_command": f"pysec verify-evidence-pack {destination} --pack-sha256 {digest}",
    }


def _pack_readme(
    root: Path,
    plan: dict[str, Any],
    register: dict[str, Any],
    audit_digest: str,
) -> str:
    summary = plan["summary"]
    lifecycle = register["summary"]
    return "\n".join(
        [
            "# Security evidence pack",
            "",
            f"**Promotion status:** {str(plan['status']).upper()}  ",
            f"**Scan:** `{plan['report']['scan_id']}`  ",
            f"**Report seal:** `{plan['report']['checksums_sha256']}`",
            "",
            "## Decision summary",
            "",
            "| Measure | Value |",
            "|---|---:|",
            f"| Active findings | {summary['active_findings']} |",
            f"| Blocking findings | {summary['blocking_findings']} |",
            f"| Release blockers | {summary['release_blockers']} |",
            f"| Open lifecycle records | {lifecycle['open']} |",
            f"| Overdue lifecycle records | {lifecycle['overdue']} |",
            f"| Evidence quality | {summary['evidence_quality_average']}% |",
            "",
            "## Start here",
            "",
            "- [Full cited findings](report/summary.md) - tool, rule, classification, file, line, context, references, and remediation",
            "- [Interactive offline report](report/index.html) - self-contained searchable report",
            "- [Action plan](report/action-plan.md) - prioritized owner and trust work",
            "- [Promotion plan](promotion-plan.md) - prioritized release blockers and actions",
            "- [Developer view](audience-developer.md) - code-focused next actions",
            "- [Security view](audience-security.md) - assurance and evidence gaps",
            "- [Executive view](audience-executive.md) - concise risk decision",
            "- [Auditor view](audience-auditor.md) - integrity and governance context",
            "- `github-annotations.txt` - escaped workflow annotations",
            "- `finding-register.json` - lifecycle, ownership, and SLA state",
            *_optional_input_links(root),
            "",
            "## Integrity and authority",
            "",
            f"Audit package SHA-256: `{audit_digest}`",
            "",
            "Verify `pack-manifest.json`, `checksums.sha256`, the completion marker, the embedded sealed report, and the audit archive with `pysec verify-evidence-pack`.",
            "",
            "> This pack is non-authoritative decision support. Controlled signing, organization security approval, and release admission remain external responsibilities.",
            "",
        ]
    )


def _optional_input_links(root: Path) -> list[str]:
    links: list[str] = []
    if (root / "operational-trend.json").is_file():
        links.append(
            "- [Operational trend](operational-trend.md) - validation debt, CODEOWNER queues, scanner reliability, and anomalies"
        )
        links.append(
            "- `operational-trend.json` - machine-readable digest-bound trend evidence"
        )
    if (root / "effectiveness-evaluation.json").is_file():
        links.append(
            "- `effectiveness-evaluation.json` - approved labeled-corpus evaluation"
        )
    if (root / "passport-verification.json").is_file():
        links.append(
            "- `passport-verification.json` - approved signed-Passport verification"
        )
    return links
