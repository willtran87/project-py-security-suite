from __future__ import annotations

import json
import re
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from . import __version__
from .execution import CommandEnvironment, resolve_executable, run_command, sha256_file
from .models import ScanManifest, json_ready
from .path_safety import is_link_like as _is_link_like
from .path_safety import resolve_regular_file as _regular_file
from .path_safety import resolve_unlinked_path as _resolve_evidence_root

_MAX_FILE_BYTES = 128 * 1024 * 1024
_MAX_RELEASE_ARTIFACT_BYTES = 512 * 1024 * 1024
_MAX_CHECKSUM_ENTRIES = 10_000
_MAX_TREE_ENTRIES = 20_000
_STATEMENT_NAME = "security-passport.json"
_SIGNATURE_NAME = "security-passport.sig"
_BUNDLE_NAME = "security-passport.sigstore.json"
_COSIGN_VERSION = re.compile(r"(?:gitVersion[^v]*|\bcosign version\s+)?v?(\d+)\.")

REQUIRED_REPORT_ARTIFACTS = {
    "summary": "summary.md",
    "action_plan": "action-plan.md",
    "assurance_case": "assurance-case.md",
    "html": "index.html",
    "sarif": "results.sarif",
    "sonarqube_external_issues": "sonarqube-external-issues.json",
    "findings": "findings.json",
    "manifest": "scan-manifest.json",
    "checksums": "checksums.sha256",
    "security_passport": "security-passport.json",
}


@dataclass(frozen=True, slots=True)
class _SigningContext:
    key: Path
    executable: Path
    executable_sha256: str
    integrity_verified: bool
    major_version: int
    config: Path | None
    config_sha256: str
    password: str


def build_security_passport_statement(
    report: Path, manifest: ScanManifest
) -> dict[str, Any]:
    inputs = _report_inputs(report, exclude={_STATEMENT_NAME, "checksums.sha256"})
    subjects = _statement_subjects(
        report,
        target=manifest.target,
        source_sha256=manifest.inventory.source_sha256,
    )
    verification_result = "PASSED" if manifest.outcome.value == "pass" else "FAILED"
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/verification_summary/v1",
        "predicate": {
            "verifier": {
                "id": "https://github.com/william-zk/project-py-security-suite",
                "version": {"py-security-suite": manifest.suite_version},
            },
            "timeVerified": manifest.finished_at,
            "resourceUri": f"urn:pysec:scan:{manifest.scan_id}",
            "policy": {
                "uri": f"urn:pysec:profile:{manifest.profile}",
                "digest": {"sha256": manifest.configuration_sha256},
            },
            "inputAttestations": inputs,
            "verificationResult": verification_result,
            "verifiedLevels": [
                f"PYSEC_PROFILE_{manifest.profile.upper().replace('-', '_')}"
            ]
            if verification_result == "PASSED"
            else ["FAILED"],
            "slsaVersion": "1.2",
            "pysec": {
                "schema_version": "1.0",
                "outcome": manifest.outcome.value,
                "profile": manifest.profile,
                "network_isolation_attested": manifest.network_isolation_attested,
                "source_integrity_verified": manifest.inventory.source_integrity_verified,
                "finding_counts": manifest.finding_counts,
                "tool_statuses": {
                    status: sum(run.status.value == status for run in manifest.tools)
                    for status in (
                        "completed",
                        "skipped",
                        "unavailable",
                        "failed",
                        "timed_out",
                        "parse_error",
                    )
                },
                "risk_acceptance_sha256": manifest.risk_acceptance_sha256,
                "intelligence": manifest.intelligence,
                "baseline": manifest.baseline,
            },
        },
    }


def create_attestation(
    *,
    report: Path,
    output: Path,
    signing_key: Path | None,
    signing_password_file: Path | None = None,
    cosign_executable: str = "cosign",
    cosign_sha256: str = "",
    allow_signing_network: bool = False,
    signing_config: Path | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    report = _resolve_evidence_root(report, "report")
    output = _resolve_evidence_root(output, "attestation output")
    verification = verify_report(report)
    statement_source = report / _STATEMENT_NAME
    if not statement_source.is_file() or statement_source.is_symlink():
        raise ValueError(f"report does not contain {_STATEMENT_NAME}")
    signing = _preflight_signing(
        signing_key=signing_key,
        signing_password_file=signing_password_file,
        cosign_executable=cosign_executable,
        cosign_sha256=cosign_sha256,
        allow_signing_network=allow_signing_network,
        signing_config=signing_config,
        cwd=report,
    )
    _prepare_directory(output, overwrite)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent)
    )
    try:
        statement = staging / _STATEMENT_NAME
        shutil.copyfile(statement_source, statement)
        signer = (
            _sign_statement(signing, statement, staging)
            if signing is not None
            else {"signed": False}
        )
        material = {
            "schema_version": "1.0",
            "created_at": datetime.now(UTC)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "suite_version": __version__,
            "report": str(report),
            "report_checksums_sha256": verification["checksums_sha256"],
            **signer,
        }
        _write_json(staging / "verification-material.json", material)
        _write_checksums(staging)
        _verify_checksums(staging)
        _publish_staging(staging, output, overwrite=overwrite)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return material


def _preflight_signing(
    *,
    signing_key: Path | None,
    signing_password_file: Path | None,
    cosign_executable: str,
    cosign_sha256: str,
    allow_signing_network: bool,
    signing_config: Path | None,
    cwd: Path,
) -> _SigningContext | None:
    signing_options = (
        signing_password_file is not None
        or signing_config is not None
        or allow_signing_network
    )
    if signing_key is None:
        if signing_options:
            raise ValueError("signing options require a signing key")
        return None
    key = _regular_file(signing_key, "signing key")
    executable = resolve_executable(cosign_executable)
    if executable is None:
        raise ValueError(f"Cosign executable is unavailable: {cosign_executable}")
    executable_path = Path(executable).resolve()
    executable_sha256 = sha256_file(executable_path)
    if cosign_sha256 and executable_sha256 != cosign_sha256.lower():
        raise ValueError("Cosign executable does not match the approved SHA-256")
    major = _cosign_major_version(executable_path, cwd)
    if major >= 3 and not allow_signing_network:
        raise ValueError(
            "Cosign v3 bundle signing may contact configured signing services; "
            "use --allow-signing-network in an approved signing lane, or create "
            "an unsigned integrity-only passport"
        )
    config = (
        _regular_file(signing_config, "signing config")
        if signing_config is not None
        else None
    )
    if config is not None and major < 3:
        raise ValueError("a signing config requires Cosign v3 or newer")
    password = _read_signing_password(signing_password_file)
    return _SigningContext(
        key=key,
        executable=executable_path,
        executable_sha256=executable_sha256,
        integrity_verified=bool(cosign_sha256),
        major_version=major,
        config=config,
        config_sha256=sha256_file(config) if config is not None else "",
        password=password,
    )


def _sign_statement(
    signing: _SigningContext, statement: Path, output: Path
) -> dict[str, Any]:
    if sha256_file(signing.executable) != signing.executable_sha256:
        raise ValueError("Cosign executable changed after signing preflight")
    if (
        signing.config is not None
        and sha256_file(signing.config) != signing.config_sha256
    ):
        raise ValueError("Cosign signing configuration changed after preflight")
    command, signature_material, signature_format = _signing_command(
        signing, statement, output
    )
    environment = (
        CommandEnvironment(extra={"COSIGN_PASSWORD": signing.password})
        if signing.password
        else None
    )
    result = run_command(
        command,
        cwd=output,
        timeout_seconds=120,
        max_output_bytes=1024 * 1024,
        environment=environment,
    )
    if result.timed_out or result.exit_code != 0:
        raise ValueError("Cosign could not sign the Security Passport")
    if sha256_file(signing.executable) != signing.executable_sha256:
        raise ValueError("Cosign executable changed while signing")
    if (
        signing.config is not None
        and sha256_file(signing.config) != signing.config_sha256
    ):
        raise ValueError("Cosign signing configuration changed while signing")
    if (
        not signature_material.is_file()
        or signature_material.is_symlink()
        or signature_material.stat().st_size == 0
    ):
        raise ValueError("Cosign did not create regular signature material")
    return {
        "signed": True,
        "algorithm": "sigstore-cosign-blob",
        "signature_format": signature_format,
        "signature": signature_material.name,
        "cosign_major_version": signing.major_version,
        "signing_network_approved": signing.major_version >= 3,
        "signing_service_configuration": (
            "explicit" if signing.config is not None else "cosign-default"
        ),
        "signing_config_sha256": signing.config_sha256,
        "cosign_sha256": signing.executable_sha256,
        "cosign_integrity_verified": signing.integrity_verified,
        "cosign_unchanged": True,
    }


def _signing_command(
    signing: _SigningContext, statement: Path, output: Path
) -> tuple[list[str], Path, str]:
    command = [str(signing.executable), "sign-blob", "--key", str(signing.key)]
    if signing.major_version >= 3:
        material = output / _BUNDLE_NAME
        command.extend(["--bundle", str(material), "--yes"])
        if signing.config is not None:
            command.extend(["--signing-config", str(signing.config)])
        command.append(str(statement))
        return command, material, "sigstore-bundle-v0.3"
    material = output / _SIGNATURE_NAME
    command.extend(
        [
            "--tlog-upload=false",
            "--yes",
            "--output-signature",
            str(material),
            str(statement),
        ]
    )
    return command, material, "cosign-detached"


def _read_signing_password(path: Path | None) -> str:
    if path is None:
        return ""
    resolved = _regular_file(path, "signing password file")
    if resolved.stat().st_size > 4096:
        raise ValueError("signing password file is not a bounded regular file")
    password = resolved.read_text(encoding="utf-8").rstrip("\r\n")
    if not password:
        raise ValueError("signing password file is empty")
    return password


def _publish_staging(staging: Path, output: Path, *, overwrite: bool) -> None:
    if not output.exists() and not _is_link_like(output):
        staging.replace(output)
        return
    _prepare_directory(output, overwrite)
    backup = Path(tempfile.mkdtemp(prefix=f".{output.name}.backup-", dir=output.parent))
    backup.rmdir()
    output.replace(backup)
    try:
        staging.replace(output)
    except Exception:
        if backup.exists() and not output.exists():
            backup.replace(output)
        raise
    shutil.rmtree(backup)


def verify_attestation(
    *,
    passport: Path,
    report: Path | None,
    public_key: Path | None,
    artifact_root: Path | None = None,
    cosign_executable: str = "cosign",
    cosign_sha256: str = "",
    allow_unsigned: bool = False,
) -> dict[str, Any]:
    passport = _resolve_evidence_root(passport, "passport")
    verified_files = _verify_checksums(passport)
    material = _read_json(passport / "verification-material.json")
    statement = _read_json(passport / _STATEMENT_NAME)
    _validate_statement(statement)
    artifact_subjects = _release_artifact_subjects(statement)
    authentic = _verify_passport_authenticity(
        passport=passport,
        material=material,
        public_key=public_key,
        cosign_executable=cosign_executable,
        cosign_sha256=cosign_sha256,
        allow_unsigned=allow_unsigned,
    )
    report_verification = _verify_bound_report(report, material, statement)
    release_artifacts_verified, release_artifacts_verified_count = (
        _verify_presented_release_artifacts(artifact_root, artifact_subjects)
    )
    policy_verification_result = str(statement["predicate"]["verificationResult"])
    policy_passed = policy_verification_result == "PASSED"
    release_blockers = _release_blockers(
        authentic=authentic,
        report_verified=report_verification is not None,
        artifacts_verified=release_artifacts_verified,
        policy_passed=policy_passed,
    )
    return {
        "schema_version": "1.0",
        "verified": True,
        "verification_status": "verified",
        "verification_scope": (
            "authenticity-and-integrity" if authentic else "integrity-only"
        ),
        "passport_integrity_verified": True,
        "report_integrity_verified": (
            None if report_verification is None else report_verification["verified"]
        ),
        "authentic": authentic,
        "authenticity_status": "verified" if authentic else "not_verified",
        "integrity_only": not authentic,
        "passport_files_verified": verified_files,
        "report": report_verification,
        "release_artifacts_required": bool(artifact_subjects),
        "release_artifacts_verified": release_artifacts_verified,
        "release_artifacts_verified_count": release_artifacts_verified_count,
        # Retain the original name for API compatibility. This is the SLSA
        # policy result, not the outcome of checksum or signature verification.
        "verification_result": policy_verification_result,
        "policy_verification_result": policy_verification_result,
        "policy_passed": policy_passed,
        "outcome": statement["predicate"]["pysec"]["outcome"],
        "release_decision": "approved" if not release_blockers else "not_approved",
        "release_blockers": release_blockers,
    }


def _verify_passport_authenticity(
    *,
    passport: Path,
    material: dict[str, Any],
    public_key: Path | None,
    cosign_executable: str,
    cosign_sha256: str,
    allow_unsigned: bool,
) -> bool:
    if material.get("signed") is not True:
        if not allow_unsigned:
            raise ValueError(
                "passport is unsigned; pass --allow-unsigned for integrity-only "
                "verification"
            )
        return False
    if public_key is None:
        raise ValueError("a public key is required to verify the signed passport")
    key = _regular_file(public_key, "public key")
    signature_name = str(material.get("signature") or _SIGNATURE_NAME)
    signature = passport / signature_name
    if signature.parent != passport or not signature.is_file():
        raise ValueError("passport signature material is missing or invalid")
    executable = resolve_executable(cosign_executable)
    if executable is None:
        raise ValueError(f"Cosign executable is unavailable: {cosign_executable}")
    executable_path = Path(executable).resolve()
    before = sha256_file(executable_path)
    if cosign_sha256 and before != cosign_sha256.lower():
        raise ValueError("Cosign executable does not match the approved SHA-256")
    command = [str(executable_path), "verify-blob", "--key", str(key)]
    option = (
        "--bundle"
        if material.get("signature_format") == "sigstore-bundle-v0.3"
        else "--signature"
    )
    command.extend([option, str(signature), str(passport / _STATEMENT_NAME)])
    result = run_command(
        command,
        cwd=passport,
        timeout_seconds=120,
        max_output_bytes=1024 * 1024,
    )
    if result.timed_out or result.exit_code != 0:
        raise ValueError("Security Passport signature verification failed")
    if sha256_file(executable_path) != before:
        raise ValueError("Cosign executable changed while verifying")
    return True


def _verify_bound_report(
    report: Path | None,
    material: dict[str, Any],
    statement: dict[str, Any],
) -> dict[str, Any] | None:
    if report is None:
        return None
    report_root = _resolve_evidence_root(report, "report")
    verification = verify_report(report_root)
    expected = str(material.get("report_checksums_sha256") or "")
    if verification["checksums_sha256"] != expected:
        raise ValueError("report checksum manifest does not match the passport")
    _verify_statement_inputs(statement, report_root)
    return verification


def _verify_presented_release_artifacts(
    artifact_root: Path | None, artifact_subjects: dict[str, str]
) -> tuple[bool | None, int]:
    if not artifact_subjects:
        if artifact_root is not None:
            raise ValueError("passport does not declare release artifact subjects")
        return None, 0
    if artifact_root is None:
        return False, 0
    return True, _verify_release_artifacts(artifact_root, artifact_subjects)


def _release_blockers(
    *,
    authentic: bool,
    report_verified: bool,
    artifacts_verified: bool | None,
    policy_passed: bool,
) -> list[str]:
    candidates = (
        (not authentic, "signer_authenticity_not_verified"),
        (not report_verified, "source_report_not_verified"),
        (artifacts_verified is False, "release_artifacts_not_verified"),
        (not policy_passed, "scan_policy_not_satisfied"),
    )
    return [blocker for blocked, blocker in candidates if blocked]


def _release_artifact_subjects(statement: dict[str, Any]) -> dict[str, str]:
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        raise ValueError("Security Passport subject set is invalid")
    digests = _subject_digest_map(subjects)
    source_names = [
        name for name in digests if name.startswith("source:") and name != "source:"
    ]
    if len(source_names) != 1:
        raise ValueError("Security Passport requires exactly one source subject")
    artifacts = {
        name: digest for name, digest in digests.items() if name not in source_names
    }
    for name in artifacts:
        _safe_relative(name)
    return artifacts


def _verify_release_artifacts(
    artifact_root: Path, artifact_subjects: dict[str, str]
) -> int:
    root = _resolve_evidence_root(artifact_root, "release artifact root")
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"release artifact root is not a regular directory: {root}")
    for name, expected in artifact_subjects.items():
        relative = _safe_relative(name)
        path = _resolve_evidence_root(
            root / relative,
            f"release artifact {name}",
            boundary=root,
        )
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"release artifact is unavailable: {name}")
        if path.stat().st_size > _MAX_RELEASE_ARTIFACT_BYTES:
            raise ValueError(f"release artifact is too large: {name}")
        if sha256_file(path) != expected:
            raise ValueError(f"release artifact digest mismatch: {name}")
    return len(artifact_subjects)


def _cosign_major_version(executable: Path, cwd: Path) -> int:
    result = run_command(
        [str(executable), "version", "--json"],
        cwd=cwd,
        timeout_seconds=30,
        max_output_bytes=64 * 1024,
    )
    output = f"{result.stdout}\n{result.stderr}"
    match = _COSIGN_VERSION.search(output)
    if result.timed_out or result.exit_code != 0 or match is None:
        raise ValueError("could not establish the Cosign major version")
    return int(match.group(1))


def verify_report(report: Path) -> dict[str, Any]:
    report = _resolve_evidence_root(report, "report")
    count = _verify_checksums(report)
    manifest = _read_json(report / "scan-manifest.json")
    if (
        manifest.get("schema_version") != "1.0"
        or not manifest.get("scan_id")
        or not manifest.get("suite_version")
    ):
        raise ValueError("report scan manifest is invalid")
    _verify_report_artifact_contract(report, manifest)
    _verify_embedded_statement(report, manifest)
    checksums = report / "checksums.sha256"
    return {
        "verified": True,
        "file_count": count,
        "checksums_sha256": sha256_file(checksums),
        "scan_id": manifest["scan_id"],
        "outcome": manifest.get("outcome"),
    }


def _verify_embedded_statement(report: Path, manifest: dict[str, Any]) -> None:
    statement = _read_json(report / _STATEMENT_NAME)
    _validate_statement(statement)
    bound_inputs = _verify_statement_inputs(statement, report)
    expected_inputs = {
        path.relative_to(report).as_posix()
        for path in report.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path.relative_to(report).as_posix()
        not in {_STATEMENT_NAME, "checksums.sha256"}
    }
    if bound_inputs != expected_inputs:
        raise ValueError("embedded Security Passport input set is incomplete")
    _verify_statement_manifest_binding(statement, manifest)
    _verify_statement_subjects(statement, report, manifest)


def _verify_statement_manifest_binding(
    statement: dict[str, Any], manifest: dict[str, Any]
) -> None:
    outcome = manifest.get("outcome")
    if outcome not in {"pass", "warn", "fail", "incomplete"}:
        raise ValueError("report scan manifest outcome is invalid")
    predicate = statement["predicate"]
    if not isinstance(predicate, dict):
        raise ValueError("embedded Security Passport manifest binding is invalid")
    inventory = manifest.get("inventory")
    tools = manifest.get("tools")
    if not isinstance(inventory, dict) or not isinstance(tools, list):
        raise ValueError("embedded Security Passport manifest binding is invalid")
    _validate_statement_manifest_evidence(manifest, inventory)
    expected_result = "PASSED" if outcome == "pass" else "FAILED"
    profile = str(manifest["profile"])
    expected_claims = {
        "verificationResult": expected_result,
        "verifiedLevels": (
            [f"PYSEC_PROFILE_{profile.upper().replace('-', '_')}"]
            if outcome == "pass"
            else ["FAILED"]
        ),
        "slsaVersion": "1.2",
        "timeVerified": manifest["finished_at"],
        "resourceUri": f"urn:pysec:scan:{manifest['scan_id']}",
        "verifier": {
            "id": "https://github.com/william-zk/project-py-security-suite",
            "version": {"py-security-suite": manifest["suite_version"]},
        },
        "policy": {
            "uri": f"urn:pysec:profile:{profile}",
            "digest": {"sha256": manifest["configuration_sha256"]},
        },
        "pysec": {
            "schema_version": "1.0",
            "outcome": outcome,
            "profile": profile,
            "network_isolation_attested": manifest["network_isolation_attested"],
            "source_integrity_verified": inventory["source_integrity_verified"],
            "finding_counts": manifest["finding_counts"],
            "tool_statuses": _tool_status_counts(tools),
            "risk_acceptance_sha256": manifest.get("risk_acceptance_sha256", ""),
            "intelligence": manifest.get("intelligence", {}),
            "baseline": manifest.get("baseline", {}),
        },
    }
    if any(predicate.get(key) != value for key, value in expected_claims.items()):
        raise ValueError("embedded Security Passport does not match scan manifest")


def _verify_statement_subjects(
    statement: dict[str, Any], report: Path, manifest: dict[str, Any]
) -> None:
    inventory = manifest.get("inventory")
    if not isinstance(inventory, dict):
        raise ValueError("embedded Security Passport subject binding is invalid")
    expected = _subject_digest_map(
        _statement_subjects(
            report,
            target=str(manifest.get("target") or ""),
            source_sha256=str(inventory.get("source_sha256") or ""),
        )
    )
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or _subject_digest_map(subjects) != expected:
        raise ValueError("embedded Security Passport subjects do not match report")


def _statement_subjects(
    report: Path, *, target: str, source_sha256: str
) -> list[dict[str, Any]]:
    if not target or not _is_digest(source_sha256):
        raise ValueError("embedded Security Passport source subject is invalid")
    subjects: list[dict[str, Any]] = [
        {"name": f"source:{target}", "digest": {"sha256": source_sha256}}
    ]
    artifact_manifest = report / "artifact-manifest.json"
    if not artifact_manifest.exists():
        return subjects
    document = _read_json(artifact_manifest)
    artifacts = document.get("artifacts")
    if (
        document.get("schema_version") != "1.0"
        or document.get("algorithm") != "sha256"
        or not isinstance(artifacts, list)
        or len(artifacts) > 1000
    ):
        raise ValueError("report artifact subject manifest is invalid")
    seen: set[str] = set()
    for value in artifacts:
        subject = _artifact_subject(value)
        name = str(subject["name"])
        if name in seen:
            raise ValueError(f"report artifact subject is duplicated: {name}")
        seen.add(name)
        subjects.append(subject)
    return subjects


def _artifact_subject(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("report artifact subject is malformed")
    name = value.get("path")
    digest = value.get("sha256")
    size = value.get("size_bytes")
    if (
        not isinstance(name, str)
        or not name
        or len(name) > 4096
        or _safe_relative(name).as_posix() != name
        or not isinstance(digest, str)
        or not _is_digest(digest)
        or type(size) is not int
        or size < 0
    ):
        raise ValueError("report artifact subject is malformed")
    return {"name": name, "digest": {"sha256": digest}}


def _subject_digest_map(subjects: Sequence[object]) -> dict[str, str]:
    values: dict[str, str] = {}
    for subject in subjects:
        name, digest = _statement_subject(subject)
        if name in values:
            raise ValueError(
                f"embedded Security Passport subject is duplicated: {name}"
            )
        values[name] = digest
    return values


def _statement_subject(subject: object) -> tuple[str, str]:
    if not isinstance(subject, dict) or set(subject) != {"name", "digest"}:
        raise ValueError("embedded Security Passport subject is malformed")
    name = subject.get("name")
    digest_value = subject.get("digest")
    digest = (
        str(digest_value.get("sha256") or "") if isinstance(digest_value, dict) else ""
    )
    if (
        not isinstance(name, str)
        or not name
        or not isinstance(digest_value, dict)
        or set(digest_value) != {"sha256"}
        or not _is_digest(digest)
    ):
        raise ValueError("embedded Security Passport subject is malformed")
    return name, digest


def _validate_statement_manifest_evidence(
    manifest: dict[str, Any], inventory: dict[str, Any]
) -> None:
    identity_values = (
        manifest.get("scan_id"),
        manifest.get("suite_version"),
        manifest.get("target"),
        manifest.get("profile"),
        manifest.get("finished_at"),
    )
    if (
        not all(isinstance(value, str) and value for value in identity_values)
        or not _is_digest(str(manifest.get("configuration_sha256") or ""))
        or not _is_digest(str(inventory.get("source_sha256") or ""))
        or not isinstance(manifest.get("network_isolation_attested"), bool)
        or not isinstance(inventory.get("source_integrity_verified"), bool)
        or not isinstance(manifest.get("finding_counts"), dict)
    ):
        raise ValueError("embedded Security Passport manifest evidence is invalid")


def _tool_status_counts(tools: list[Any]) -> dict[str, int]:
    return {
        status: sum(
            isinstance(run, dict) and run.get("status") == status for run in tools
        )
        for status in (
            "completed",
            "skipped",
            "unavailable",
            "failed",
            "timed_out",
            "parse_error",
        )
    }


def _verify_report_artifact_contract(report: Path, manifest: dict[str, Any]) -> None:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("report artifact manifest is missing or invalid")
    if not artifacts or len(artifacts) > _MAX_CHECKSUM_ENTRIES:
        raise ValueError("report artifact binding count is invalid")
    for key, required_relative in REQUIRED_REPORT_ARTIFACTS.items():
        if artifacts.get(key) != required_relative:
            raise ValueError(f"report artifact binding is invalid: {key}")
        path = report / required_relative
        if not path.is_file() or path.is_symlink():
            raise ValueError(
                f"required report artifact is missing: {required_relative}"
            )
    seen: set[str] = set()
    for key, raw_binding in artifacts.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > 256
            or not isinstance(raw_binding, str)
            or len(raw_binding) > 4096
        ):
            raise ValueError("report artifact binding is malformed")
        directory_binding = raw_binding.endswith("/")
        raw_relative = raw_binding[:-1] if directory_binding else raw_binding
        artifact_relative = _safe_relative(raw_relative)
        normalized = artifact_relative.as_posix()
        if normalized in seen:
            raise ValueError(f"report artifact binding is duplicated: {raw_binding}")
        seen.add(normalized)
        path = report / artifact_relative
        available = (
            path.is_dir() if directory_binding else path.is_file()
        ) and not _is_link_like(path)
        if not available:
            raise ValueError(f"declared report artifact is unavailable: {raw_binding}")


def _report_inputs(report: Path, *, exclude: set[str]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for path in sorted(report.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(report).as_posix()
        if relative in exclude:
            continue
        values.append(
            {
                "uri": relative,
                "digest": {"sha256": sha256_file(path)},
            }
        )
        if len(values) > _MAX_CHECKSUM_ENTRIES:
            raise ValueError("report contains too many evidence files")
    return values


def _verify_statement_inputs(statement: dict[str, Any], report: Path) -> set[str]:
    predicate = statement.get("predicate", {})
    inputs = (
        predicate.get("inputAttestations", []) if isinstance(predicate, dict) else []
    )
    if not isinstance(inputs, list):
        raise ValueError("passport inputAttestations must be a list")
    seen: set[str] = set()
    for value in inputs:
        if not isinstance(value, dict):
            raise ValueError("passport input attestation must be an object")
        relative = _safe_relative(str(value.get("uri") or ""))
        relative_name = relative.as_posix()
        if relative_name in seen:
            raise ValueError(f"passport input is duplicated: {relative_name}")
        seen.add(relative_name)
        digest = value.get("digest", {})
        expected = str(digest.get("sha256") or "") if isinstance(digest, dict) else ""
        path = (report / relative).resolve()
        if not path.is_relative_to(report) or not path.is_file() or path.is_symlink():
            raise ValueError(f"passport input is unavailable: {relative}")
        if sha256_file(path) != expected:
            raise ValueError(f"passport input digest mismatch: {relative}")
    return seen


def _validate_statement(document: dict[str, Any]) -> None:
    if document.get("_type") != "https://in-toto.io/Statement/v1":
        raise ValueError("passport is not an in-toto Statement v1")
    if document.get("predicateType") != "https://slsa.dev/verification_summary/v1":
        raise ValueError("passport is not a SLSA Verification Summary Attestation")
    subjects = document.get("subject")
    predicate = document.get("predicate")
    if (
        not isinstance(subjects, list)
        or not subjects
        or not isinstance(predicate, dict)
    ):
        raise ValueError("passport requires subjects and a predicate")
    if predicate.get("verificationResult") not in {"PASSED", "FAILED"}:
        raise ValueError("passport verificationResult is invalid")
    policy = predicate.get("policy")
    if not isinstance(policy, dict) or not isinstance(policy.get("digest"), dict):
        raise ValueError("passport policy digest is missing")


def _verify_checksums(root: Path) -> int:
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"evidence root is not a regular directory: {root}")
    checksum_file = root / "checksums.sha256"
    if not checksum_file.is_file() or checksum_file.is_symlink():
        raise ValueError(f"checksum manifest is missing: {checksum_file}")
    if checksum_file.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError("checksum manifest is too large")
    lines = checksum_file.read_text(encoding="utf-8").splitlines()
    if not lines or len(lines) > _MAX_CHECKSUM_ENTRIES:
        raise ValueError("checksum manifest entry count is invalid")
    seen: set[str] = set()
    for line in lines:
        try:
            expected, raw_relative = line.split("  ", 1)
        except ValueError as exc:
            raise ValueError("checksum manifest line is invalid") from exc
        if not _is_digest(expected) or raw_relative in seen:
            raise ValueError("checksum manifest digest or path is invalid")
        seen.add(raw_relative)
        relative = _safe_relative(raw_relative)
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
            raise ValueError(f"checksummed file is unavailable: {raw_relative}")
        if path.stat().st_size > _MAX_FILE_BYTES:
            raise ValueError(f"checksummed file is too large: {raw_relative}")
        if sha256_file(path) != expected:
            raise ValueError(f"checksum mismatch: {raw_relative}")
    actual: set[str] = set()
    entry_count = 0
    for path in root.rglob("*"):
        entry_count += 1
        if entry_count > _MAX_TREE_ENTRIES:
            raise ValueError("evidence tree entry count is invalid")
        relative_name = path.relative_to(root).as_posix()
        if relative_name == "checksums.sha256":
            continue
        if _is_link_like(path):
            raise ValueError(f"evidence tree contains a link: {relative_name}")
        if path.is_file():
            actual.add(relative_name)
        elif not path.is_dir():
            raise ValueError(f"evidence tree contains a special file: {relative_name}")
    if actual != seen:
        raise ValueError("checksum manifest does not cover the exact evidence file set")
    return len(lines)


def _safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if (
        not value
        or not pure.parts
        or value != pure.as_posix()
        or pure.is_absolute()
        or ".." in pure.parts
        or "\\" in value
        or ":" in pure.parts[0]
    ):
        raise ValueError(f"unsafe evidence path: {value!r}")
    return Path(*pure.parts)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError(f"JSON evidence is not a bounded regular file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"JSON evidence root must be an object: {path}")
    return value


def _prepare_directory(path: Path, overwrite: bool) -> None:
    if _is_link_like(path):
        raise ValueError(f"attestation output is not a regular directory: {path}")
    if path.exists():
        if not overwrite:
            raise ValueError(f"attestation output already exists: {path}")
        if not path.is_dir():
            raise ValueError(f"attestation output is not a regular directory: {path}")
        marker = path / "verification-material.json"
        try:
            _verify_checksums(path)
            material = _read_json(marker)
            statement = _read_json(path / _STATEMENT_NAME)
            _validate_statement(statement)
            valid_material = (
                material.get("schema_version") == "1.0"
                and isinstance(material.get("signed"), bool)
                and _is_digest(str(material.get("report_checksums_sha256") or ""))
            )
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError(
                "refusing to overwrite a directory that is not a valid "
                "Security Passport"
            ) from exc
        if not valid_material:
            raise ValueError(
                "refusing to overwrite a directory that is not a valid "
                "Security Passport"
            )


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(json_ready(value), indent=2, sort_keys=True, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_checksums(output: Path) -> None:
    values = [
        f"{sha256_file(path)}  {path.relative_to(output).as_posix()}"
        for path in sorted(output.iterdir())
        if path.is_file() and path.name != "checksums.sha256" and not path.is_symlink()
    ]
    (output / "checksums.sha256").write_text(
        "\n".join(values) + "\n", encoding="utf-8", newline="\n"
    )


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
