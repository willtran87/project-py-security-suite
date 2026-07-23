from __future__ import annotations

import json
import time
from pathlib import Path

from ..execution import (
    CommandEnvironment,
    resolve_executable,
    run_command,
    sanitize_diagnostic,
)
from ..models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    ToolRun,
    ToolStatus,
    finding_identity,
    normalize_repo_path,
)
from .artifacts import configured_path, distribution_files
from .base import AdapterResult, ScannerAdapter


class PyPiAttestationsAdapter(ScannerAdapter):
    name = "pypi-attestations"

    def not_applicable_reason(self, target: Path) -> str | None:
        if not distribution_files(target, self.config):
            return "no built wheel or source distribution was found"
        return None

    def prerequisite_error(self) -> str | None:
        if not self.config.repository_url:
            return "the expected Trusted Publisher repository_url is required"
        if not self.config.repository_url.startswith(
            ("https://github.com/", "https://gitlab.com/")
        ):
            return "repository_url must identify an HTTPS GitHub or GitLab repository"
        trust_home = self.config.database_path
        if trust_home is None:
            return "a staged offline Sigstore trust cache is required in database_path"
        if not trust_home.expanduser().resolve().is_dir():
            return f"offline Sigstore trust cache does not exist: {trust_home}"
        return None

    def environment(self) -> CommandEnvironment:
        trust_home = self.config.database_path
        if trust_home is None:
            return CommandEnvironment()
        resolved = str(trust_home.expanduser().resolve())
        return CommandEnvironment(
            extra={
                "HOME": resolved,
                "USERPROFILE": resolved,
                "APPDATA": str(Path(resolved) / "AppData" / "Roaming"),
                "LOCALAPPDATA": str(Path(resolved) / "AppData" / "Local"),
                "XDG_CACHE_HOME": str(Path(resolved) / "cache"),
            }
        )

    def build_command(self, executable: str, target: Path) -> list[str]:
        raise NotImplementedError("attestations are verified one distribution at a time")

    def parse(self, payload: str, target: Path) -> list[Finding]:
        if payload.strip():
            json.loads(payload)
        return []

    def run(self, target: Path) -> AdapterResult:
        not_applicable = self.not_applicable_reason(target)
        if not_applicable:
            tool_run = ToolRun(
                tool=self.name,
                status=ToolStatus.SKIPPED,
                command=[self.config.executable],
                duration_seconds=0.0,
                error=not_applicable,
                applicable=False,
            )
            return AdapterResult([], tool_run, self._diagnostic(tool_run, None))
        prerequisite = self.prerequisite_error()
        executable = resolve_executable(self.config.executable)
        if prerequisite or executable is None:
            tool_run = ToolRun(
                tool=self.name,
                status=ToolStatus.UNAVAILABLE,
                command=[self.config.executable],
                duration_seconds=0.0,
                error=prerequisite or f"executable not found: {self.config.executable}",
            )
            return AdapterResult([], tool_run, self._diagnostic(tool_run, None))

        version = self._detect_version(executable, target)
        provenance_root = configured_path(
            target, self.config.provenance_path, "dist"
        )
        findings: list[Finding] = []
        commands: list[list[str]] = []
        diagnostics: list[dict[str, object]] = []
        started = time.monotonic()
        for distribution in distribution_files(target, self.config):
            provenance = _provenance_file(provenance_root, distribution)
            if provenance is None:
                findings.append(
                    _attestation_finding(
                        target,
                        distribution,
                        "PYPI-ATTESTATION-MISSING",
                        "Distribution provenance is missing",
                        (
                            "Acquire the PyPI Integrity API provenance object in the "
                            "connected preparation lane and stage it beside the artifact."
                        ),
                    )
                )
                continue
            command = [
                executable,
                "verify",
                "pypi",
                str(distribution),
                "--repository",
                self.config.repository_url,
                "--offline",
                "--provenance-file",
                str(provenance),
            ]
            commands.append(command)
            execution = run_command(
                command,
                cwd=target,
                timeout_seconds=self.config.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
                environment=self.environment(),
            )
            diagnostics.append(
                {
                    "distribution": normalize_repo_path(target, distribution),
                    "provenance": normalize_repo_path(target, provenance),
                    "exit_code": execution.exit_code,
                    "timed_out": execution.timed_out,
                    "stderr": sanitize_diagnostic(execution.stderr, maximum=512),
                }
            )
            if execution.timed_out:
                status = ToolStatus.TIMED_OUT
                error = (
                    f"attestation verification timed out for {distribution.name}"
                )
                tool_run = ToolRun(
                    tool=self.name,
                    status=status,
                    command=command,
                    duration_seconds=round(time.monotonic() - started, 3),
                    version=version,
                    error=error,
                )
                return AdapterResult(
                    findings,
                    tool_run,
                    {
                        **self._diagnostic(tool_run, execution),
                        "verifications": diagnostics,
                    },
                )
            if execution.exit_code != 0:
                message = sanitize_diagnostic(
                    execution.stderr or execution.stdout, maximum=300
                )
                findings.append(
                    _attestation_finding(
                        target,
                        distribution,
                        "PYPI-ATTESTATION-INVALID",
                        "Distribution provenance verification failed",
                        (
                            "Reject the artifact, verify its digest and expected publisher "
                            "identity, then rebuild and publish through the approved workflow."
                        ),
                        detail=message,
                    )
                )

        tool_run = ToolRun(
            tool=self.name,
            status=ToolStatus.COMPLETED,
            command=commands[-1] if commands else [executable, "verify", "pypi"],
            duration_seconds=round(time.monotonic() - started, 3),
            version=version,
            exit_code=0,
            finding_count=len(findings),
        )
        diagnostic = self._diagnostic(tool_run, None)
        diagnostic["verifications"] = diagnostics
        diagnostic["repository"] = self.config.repository_url
        return AdapterResult(findings, tool_run, diagnostic)


def _provenance_file(root: Path, distribution: Path) -> Path | None:
    candidates = (
        root / f"{distribution.name}.provenance.json",
        root / f"{distribution.name}.provenance",
    )
    return next((path.resolve() for path in candidates if path.is_file()), None)


def _attestation_finding(
    target: Path,
    distribution: Path,
    rule_id: str,
    title: str,
    remediation: str,
    *,
    detail: str = "",
) -> Finding:
    path = normalize_repo_path(target, distribution)
    finding_id, fingerprint = finding_identity(
        tool="pypi-attestations", rule_id=rule_id, path=path
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=title,
        description=(
            f"{title} for {distribution.name}."
            + (f" Sanitized verifier detail: {detail}" if detail else "")
        ),
        impact=(
            "The release artifact cannot be cryptographically bound to the expected "
            "Trusted Publisher identity and exact distribution digest."
        ),
        remediation=remediation,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="artifact-provenance",
        classifications=["SLSA-PROVENANCE", rule_id],
        locations=[Location(path=path)],
        sources=[
            Source(
                tool="pypi-attestations",
                rule_id=rule_id,
                message=title,
                native_severity="error",
            )
        ],
        citations=[
            Citation(
                kind="standard",
                identifier="PEP-740",
                title="PyPI digital attestations",
                uri="https://docs.pypi.org/attestations/",
            )
        ],
        evidence={"artifact": distribution.name, "raw_material_retained": False},
    )
