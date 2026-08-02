from __future__ import annotations

import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from . import __version__
from .execution import CommandEnvironment, resolve_executable, run_command, sha256_file
from .models import ScanManifest, json_ready

_MAX_FILE_BYTES = 128 * 1024 * 1024
_MAX_CHECKSUM_ENTRIES = 10_000
_STATEMENT_NAME = "security-passport.json"
_SIGNATURE_NAME = "security-passport.sig"
_BUNDLE_NAME = "security-passport.sigstore.json"
_COSIGN_VERSION = re.compile(r"(?:gitVersion[^v]*|\bcosign version\s+)?v?(\d+)\.")


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
    subjects = [
        {
            "name": f"source:{manifest.target}",
            "digest": {"sha256": manifest.inventory.source_sha256},
        }
    ]
    artifact_manifest = report / "artifact-manifest.json"
    if artifact_manifest.is_file() and not artifact_manifest.is_symlink():
        document = _read_json(artifact_manifest)
        artifacts = document.get("artifacts", []) if isinstance(document, dict) else []
        if isinstance(artifacts, list):
            for value in artifacts[:1000]:
                if not isinstance(value, dict):
                    continue
                digest = str(value.get("sha256") or "")
                name = str(value.get("path") or "")
                if _is_digest(digest) and name:
                    subjects.append({"name": name, "digest": {"sha256": digest}})
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
    report = report.expanduser().resolve()
    output = output.expanduser().resolve()
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
        _publish_staging(staging, output)
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


def _regular_file(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"{label} is not a regular file: {resolved}")
    return resolved


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


def _publish_staging(staging: Path, output: Path) -> None:
    if output.exists():
        _prepare_directory(output, overwrite=True)
        shutil.rmtree(output)
    staging.replace(output)


def verify_attestation(
    *,
    passport: Path,
    report: Path | None,
    public_key: Path | None,
    cosign_executable: str = "cosign",
    cosign_sha256: str = "",
    allow_unsigned: bool = False,
) -> dict[str, Any]:
    passport = passport.expanduser().resolve()
    verified_files = _verify_checksums(passport)
    material = _read_json(passport / "verification-material.json")
    statement = _read_json(passport / _STATEMENT_NAME)
    _validate_statement(statement)
    signed = material.get("signed") is True
    authentic = False
    if signed:
        if public_key is None:
            raise ValueError("a public key is required to verify the signed passport")
        key = public_key.expanduser().resolve()
        signature_name = str(material.get("signature") or _SIGNATURE_NAME)
        signature = passport / signature_name
        if signature.parent != passport or not signature.is_file():
            raise ValueError("passport signature material is missing or invalid")
        if not key.is_file() or key.is_symlink():
            raise ValueError(f"public key is not a regular file: {key}")
        executable = resolve_executable(cosign_executable)
        if executable is None:
            raise ValueError(f"Cosign executable is unavailable: {cosign_executable}")
        executable_path = Path(executable).resolve()
        before = sha256_file(executable_path)
        if cosign_sha256 and before != cosign_sha256.lower():
            raise ValueError("Cosign executable does not match the approved SHA-256")
        command = [str(executable_path), "verify-blob", "--key", str(key)]
        if material.get("signature_format") == "sigstore-bundle-v0.3":
            command.extend(["--bundle", str(signature)])
        else:
            command.extend(["--signature", str(signature)])
        command.append(str(passport / _STATEMENT_NAME))
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
        authentic = True
    elif not allow_unsigned:
        raise ValueError(
            "passport is unsigned; pass --allow-unsigned for integrity-only verification"
        )

    report_verification: dict[str, Any] | None = None
    if report is not None:
        report_verification = verify_report(report.expanduser().resolve())
        expected = str(material.get("report_checksums_sha256") or "")
        if report_verification["checksums_sha256"] != expected:
            raise ValueError("report checksum manifest does not match the passport")
        _verify_statement_inputs(statement, report.expanduser().resolve())
    policy_verification_result = str(statement["predicate"]["verificationResult"])
    policy_passed = policy_verification_result == "PASSED"
    release_blockers: list[str] = []
    if not authentic:
        release_blockers.append("signer_authenticity_not_verified")
    if report_verification is None:
        release_blockers.append("source_report_not_verified")
    if not policy_passed:
        release_blockers.append("scan_policy_not_satisfied")
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
        # Retain the original name for API compatibility. This is the SLSA
        # policy result, not the outcome of checksum or signature verification.
        "verification_result": policy_verification_result,
        "policy_verification_result": policy_verification_result,
        "policy_passed": policy_passed,
        "outcome": statement["predicate"]["pysec"]["outcome"],
        "release_decision": "approved" if not release_blockers else "not_approved",
        "release_blockers": release_blockers,
    }


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
    report = report.expanduser().resolve()
    count = _verify_checksums(report)
    manifest = _read_json(report / "scan-manifest.json")
    if (
        manifest.get("schema_version") != "1.0"
        or not manifest.get("scan_id")
        or not manifest.get("suite_version")
    ):
        raise ValueError("report scan manifest is invalid")
    checksums = report / "checksums.sha256"
    return {
        "verified": True,
        "file_count": count,
        "checksums_sha256": sha256_file(checksums),
        "scan_id": manifest["scan_id"],
        "outcome": manifest.get("outcome"),
    }


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


def _verify_statement_inputs(statement: dict[str, Any], report: Path) -> None:
    predicate = statement.get("predicate", {})
    inputs = (
        predicate.get("inputAttestations", []) if isinstance(predicate, dict) else []
    )
    if not isinstance(inputs, list):
        raise ValueError("passport inputAttestations must be a list")
    for value in inputs:
        if not isinstance(value, dict):
            raise ValueError("passport input attestation must be an object")
        relative = _safe_relative(str(value.get("uri") or ""))
        digest = value.get("digest", {})
        expected = str(digest.get("sha256") or "") if isinstance(digest, dict) else ""
        path = (report / relative).resolve()
        if not path.is_relative_to(report) or not path.is_file() or path.is_symlink():
            raise ValueError(f"passport input is unavailable: {relative}")
        if sha256_file(path) != expected:
            raise ValueError(f"passport input digest mismatch: {relative}")


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
    return len(lines)


def _safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if not value or pure.is_absolute() or ".." in pure.parts or "\\" in value:
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
    if path.exists():
        if not overwrite:
            raise ValueError(f"attestation output already exists: {path}")
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"attestation output is not a regular directory: {path}")
        marker = path / "verification-material.json"
        if not marker.is_file() or marker.is_symlink():
            raise ValueError(
                "refusing to overwrite a directory that is not a Security Passport"
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
