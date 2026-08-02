from __future__ import annotations

import time
from pathlib import Path

from ..execution import run_command, sanitize_diagnostic
from ..models import Citation, Confidence, Finding, Location, Severity, Source
from ..models import ToolRun, ToolStatus, finding_identity, normalize_repo_path
from .artifacts import configured_path, distribution_files
from .base import AdapterResult, ScannerAdapter


class CosignAdapter(ScannerAdapter):
    name = "cosign"

    def not_applicable_reason(self, target: Path) -> str | None:
        return (
            None
            if distribution_files(target, self.config)
            else "no built wheel or source distribution was found"
        )

    def prerequisite_error(self) -> str | None:
        if self.config.public_key_path:
            if not self.config.public_key_path.expanduser().resolve().is_file():
                return "the configured Cosign public key does not exist"
            return None
        if (
            not self.config.certificate_identity
            or not self.config.certificate_oidc_issuer
        ):
            return "Cosign keyless verification requires certificate_identity and certificate_oidc_issuer"
        if (
            self.config.database_path is None
            or not self.config.database_path.expanduser().resolve().is_file()
        ):
            return "Cosign keyless verification requires a staged trusted-root JSON file in database_path"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        raise NotImplementedError("Cosign verifies one distribution at a time")

    def parse(self, payload: str, target: Path) -> list[Finding]:
        return []

    def run(self, target: Path) -> AdapterResult:
        reason = self.not_applicable_reason(target)
        if reason:
            run = ToolRun(
                tool=self.name,
                status=ToolStatus.SKIPPED,
                command=[self.config.executable],
                duration_seconds=0.0,
                error=reason,
                applicable=False,
            )
            return AdapterResult([], run, self._diagnostic(run, None))
        prerequisite = self.prerequisite_error()
        executable, integrity_error = self._prepare_executable()
        if prerequisite or integrity_error or executable is None:
            run = ToolRun(
                tool=self.name,
                status=ToolStatus.UNAVAILABLE,
                command=[self.config.executable],
                duration_seconds=0.0,
                error=prerequisite
                or integrity_error
                or "Cosign executable unavailable",
            )
            return AdapterResult([], run, self._diagnostic(run, None))

        version = self._detect_version(executable, target)
        provenance_root = configured_path(target, self.config.provenance_path, "dist")
        findings: list[Finding] = []
        diagnostics: list[dict[str, object]] = []
        last_command = [executable, "verify-blob"]
        last_execution = None
        started = time.monotonic()
        for artifact in distribution_files(target, self.config):
            bundle = _bundle_for(provenance_root, artifact)
            if bundle is None:
                findings.append(
                    _finding(
                        target,
                        artifact,
                        "COSIGN-BUNDLE-MISSING",
                        "Sigstore verification bundle is missing",
                    )
                )
                continue
            command = [executable, "verify-blob", "--bundle", str(bundle)]
            if self.config.public_key_path:
                command.extend(
                    ["--key", str(self.config.public_key_path.expanduser().resolve())]
                )
            else:
                trusted_root = self.config.database_path
                if trusted_root is None:
                    raise RuntimeError("validated Cosign trusted root is unavailable")
                command.extend(
                    [
                        "--trusted-root",
                        str(trusted_root.expanduser().resolve()),
                        "--certificate-identity",
                        self.config.certificate_identity,
                        "--certificate-oidc-issuer",
                        self.config.certificate_oidc_issuer,
                    ]
                )
            command.append(str(artifact))
            last_command = command
            execution = run_command(
                command,
                cwd=target,
                timeout_seconds=self.config.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
                environment=self.environment(),
            )
            last_execution = execution
            diagnostics.append(
                {
                    "artifact": normalize_repo_path(target, artifact),
                    "bundle": normalize_repo_path(target, bundle),
                    "exit_code": execution.exit_code,
                    "timed_out": execution.timed_out,
                    "detail": sanitize_diagnostic(
                        execution.stderr or execution.stdout, maximum=300
                    ),
                }
            )
            changed_error = self._executable_changed_error()
            if changed_error or execution.timed_out:
                status = (
                    ToolStatus.TIMED_OUT if execution.timed_out else ToolStatus.FAILED
                )
                error = (
                    f"Cosign verification timed out for {artifact.name}"
                    if execution.timed_out
                    else changed_error
                )
                run = ToolRun(
                    tool=self.name,
                    status=status,
                    command=command,
                    duration_seconds=round(time.monotonic() - started, 3),
                    version=version,
                    exit_code=execution.exit_code,
                    error=error,
                )
                return AdapterResult(
                    findings,
                    run,
                    {**self._diagnostic(run, execution), "verifications": diagnostics},
                )
            if execution.exit_code != 0:
                findings.append(
                    _finding(
                        target,
                        artifact,
                        "COSIGN-VERIFICATION-FAILED",
                        "Artifact signature or identity verification failed",
                        sanitize_diagnostic(
                            execution.stderr or execution.stdout, maximum=300
                        ),
                    )
                )

        run = ToolRun(
            tool=self.name,
            status=ToolStatus.COMPLETED,
            command=last_command,
            duration_seconds=round(time.monotonic() - started, 3),
            version=version,
            exit_code=0,
            finding_count=len(findings),
            **self._integrity_fields(),
        )
        diagnostic = {
            **self._diagnostic(run, last_execution),
            "verifications": diagnostics,
            "raw_output_retained": False,
        }
        return AdapterResult(findings, run, diagnostic)


def _bundle_for(root: Path, artifact: Path) -> Path | None:
    candidates = (
        root / f"{artifact.name}.sigstore.json",
        root / f"{artifact.name}.bundle.json",
    )
    return next(
        (
            path.resolve()
            for path in candidates
            if path.is_file() and not path.is_symlink()
        ),
        None,
    )


def _finding(
    target: Path, artifact: Path, rule_id: str, title: str, detail: str = ""
) -> Finding:
    path = normalize_repo_path(target, artifact)
    finding_id, fingerprint = finding_identity(
        tool="cosign", rule_id=rule_id, path=path
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=title,
        description=f"{title} for {artifact.name}."
        + (f" Sanitized verifier detail: {detail}" if detail else ""),
        impact="The release artifact cannot be cryptographically bound to an approved signer identity and exact artifact digest.",
        remediation="Reject the artifact, stage the approved Sigstore bundle and trust material, then rebuild or re-sign through the controlled release workflow.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="artifact-provenance",
        domain="supply-chain",
        classifications=[rule_id, "SLSA-PROVENANCE"],
        locations=[Location(path=path)],
        sources=[
            Source(
                tool="cosign", rule_id=rule_id, message=title, native_severity="error"
            )
        ],
        citations=[
            Citation(
                kind="standard",
                identifier="sigstore-bundle",
                title="Cosign blob verification",
                uri="https://github.com/sigstore/cosign/blob/main/doc/cosign_verify-blob.md",
            )
        ],
        evidence={"artifact": artifact.name, "raw_material_retained": False},
    )
