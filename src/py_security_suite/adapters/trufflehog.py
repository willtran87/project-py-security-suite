from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    finding_identity,
    normalize_repo_path,
)
from ..strict_json import loads as strict_json_loads
from .base import ScannerAdapter
from .common import (
    contains_regular_file,
    native_suppression_finding,
    native_suppression_markers,
)

# TruffleHog 3.x has no switch to disable its in-source ignore comment, so the
# suite counts each occurrence as an unaccepted finding instead.
NATIVE_IGNORE_MARKER = b"trufflehog:ignore"


class TruffleHogAdapter(ScannerAdapter):
    name = "trufflehog"

    def not_applicable_reason(self, target: Path) -> str | None:
        if not contains_regular_file(target):
            return "the target contains no files to inspect for secrets"
        return None

    def prerequisite_error(self) -> str | None:
        excludes = self.config.rules_path
        if excludes is None:
            return "a local TruffleHog exclude-path file is required"
        if not excludes.expanduser().resolve().is_file():
            return f"TruffleHog exclude-path file does not exist: {excludes}"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        excludes = self.config.rules_path
        if excludes is None:
            raise ValueError("TruffleHog exclude paths were not configured")
        return [
            executable,
            "filesystem",
            f"--directory={target.resolve()}",
            "--json",
            "--no-verification",
            "--no-update",
            f"--exclude-paths={excludes.expanduser().resolve()}",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        findings: list[Finding] = self._native_suppressions(target)
        for line in payload.splitlines():
            if not line.strip():
                continue
            result = strict_json_loads(line)
            if not isinstance(result, dict):
                raise TypeError("TruffleHog result must be an object")
            detector = str(
                result.get("DetectorName")
                or result.get("detector_name")
                or "unknown-detector"
            )
            metadata = (
                result.get("SourceMetadata") or result.get("source_metadata") or {}
            )
            path, line_number = _location(metadata)
            normalized = normalize_repo_path(target, path)
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=detector,
                path=normalized,
                start_line=line_number,
            )
            verified = bool(result.get("Verified") or result.get("verified"))
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Credential candidate detected by {detector}",
                    description=(
                        "TruffleHog independently identified a credential-shaped value. "
                        "Verification was disabled and secret material was discarded."
                    ),
                    impact=(
                        "A credential in a release tree may permit unauthorized access "
                        "even when another secret scanner did not recognize its format."
                    ),
                    remediation=(
                        "Validate without copying the value into reports, revoke and "
                        "rotate real credentials, remove them from source and history, "
                        "then add a narrowly governed test-data exclusion if necessary."
                    ),
                    severity=Severity.HIGH,
                    confidence=(Confidence.HIGH if verified else Confidence.MEDIUM),
                    area="secrets",
                    classifications=["CWE-798"],
                    locations=[
                        Location(
                            path=normalized,
                            start_line=line_number,
                            end_line=line_number,
                        )
                    ],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=detector,
                            message=f"{detector} credential candidate",
                            native_severity="verified" if verified else "unverified",
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=detector,
                            title=f"TruffleHog detector: {detector}",
                            uri=(
                                "https://github.com/trufflesecurity/trufflehog/"
                                "blob/main/proto/detectors.proto"
                            ),
                        )
                    ],
                    evidence={
                        "redacted": True,
                        "verification_enabled": False,
                        "decoder": str(
                            result.get("DecoderName")
                            or result.get("decoder_name")
                            or "unknown"
                        ),
                    },
                )
            )
        return findings

    def _native_suppressions(self, target: Path) -> list[Finding]:
        excludes = self.config.rules_path
        patterns: list[re.Pattern[str]] = []
        if excludes is not None:
            for line in (
                excludes.expanduser().resolve().read_text(encoding="utf-8").splitlines()
            ):
                if line.strip():
                    patterns.append(re.compile(line.strip()))
        root = target.resolve()
        return [
            native_suppression_finding(
                self.name,
                rule_id="trufflehog.native-suppression",
                path=normalize_repo_path(target, str(path)),
                line=line,
                mechanism="trufflehog:ignore comment",
                area="secrets",
            )
            for path, line in native_suppression_markers(
                root, NATIVE_IGNORE_MARKER, excluded=patterns
            )
        ]


def _location(value: Any) -> tuple[str, int | None]:
    if not isinstance(value, dict):
        return "<repository>", None
    data = value.get("Data") or value.get("data") or value
    if not isinstance(data, dict):
        return "<repository>", None
    filesystem = data.get("Filesystem") or data.get("filesystem") or data
    if not isinstance(filesystem, dict):
        return "<repository>", None
    path = str(
        filesystem.get("file")
        or filesystem.get("File")
        or filesystem.get("path")
        or filesystem.get("Path")
        or "<repository>"
    )
    raw_line = filesystem.get("line") or filesystem.get("Line")
    try:
        line = int(raw_line) if raw_line is not None else None
    except (TypeError, ValueError):
        line = None
    return path, line
