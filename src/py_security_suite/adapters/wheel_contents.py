from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path

from ..execution import sha256_file
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
from .artifacts import artifact_identity_evidence, wheel_files
from .base import ScannerAdapter

_ISSUE = re.compile(r"^(?P<path>.+?):\s+(?P<rule>W\d{3}):\s+(?P<message>.+)$")


class CheckWheelContentsAdapter(ScannerAdapter):
    name = "check-wheel-contents"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        if not wheel_files(target, self.config):
            return "no built wheel was found"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "--no-config",
            *(str(path) for path in wheel_files(target, self.config)),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        identities = {
            normalize_repo_path(target, wheel): artifact_identity_evidence(
                target, wheel
            )
            for wheel in wheel_files(target, self.config)
        }
        for line in payload.splitlines():
            match = _ISSUE.match(line.strip())
            if match is None:
                continue
            rule_id = match.group("rule")
            message = match.group("message")
            path = normalize_repo_path(target, match.group("path"))
            finding_id, fingerprint = finding_identity(
                tool=self.name, rule_id=rule_id, path=path
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Wheel content problem: {message}",
                    description=(
                        "check-wheel-contents identified an unexpected, missing, "
                        "duplicated, or otherwise incorrect wheel member."
                    ),
                    impact=(
                        "A malformed or over-inclusive release wheel can ship unintended "
                        "code, data, tests, bytecode, or packaging metadata."
                    ),
                    remediation=(
                        "Correct the build configuration, rebuild the wheel from a clean "
                        "tree, and repeat the artifact scan."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    area="artifact-integrity",
                    classifications=[rule_id],
                    locations=[Location(path=path)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=message,
                            native_severity="error",
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=message,
                            uri=(
                                "https://github.com/jwodder/check-wheel-contents"
                                f"#{rule_id.lower()}"
                            ),
                        )
                    ],
                    evidence=identities.get(path, {}),
                )
            )
        findings.extend(self._source_parity_findings(target))
        return findings

    def _source_parity_findings(self, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for wheel in wheel_files(target, self.config):
            distribution = wheel.name.split("-", maxsplit=1)[0].replace(".", "_")
            package = target / "src" / distribution
            if not package.is_dir() or package.is_symlink():
                continue
            expected = sorted(
                path
                for path in package.rglob("*")
                if path.is_file()
                and not path.is_symlink()
                and (path.suffix.casefold() == ".py" or path.name == "py.typed")
            )
            try:
                with zipfile.ZipFile(wheel) as archive:
                    members = set(archive.namelist())
                    packaged_digests = {
                        member: hashlib.sha256(archive.read(member)).hexdigest()
                        for source in expected
                        if (member := source.relative_to(target / "src").as_posix())
                        in members
                        and archive.getinfo(member).file_size <= 16 * 1024 * 1024
                    }
            except (OSError, zipfile.BadZipFile):
                continue
            for source in expected:
                member = source.relative_to(target / "src").as_posix()
                source_digest = sha256_file(source)
                issue = (
                    "missing"
                    if member not in members
                    else "content-mismatch"
                    if packaged_digests.get(member) != source_digest
                    else ""
                )
                if not issue:
                    continue
                path = source.relative_to(target).as_posix()
                finding_id, fingerprint = finding_identity(
                    tool=self.name,
                    rule_id="source-wheel-parity",
                    path=path,
                    package=wheel.name,
                )
                findings.append(
                    Finding(
                        finding_id=finding_id,
                        fingerprint=fingerprint,
                        title=f"Built wheel differs from maintained source: {path}",
                        description=(
                            f"{wheel.name} has a {issue} condition for maintained "
                            f"package member {member}."
                        ),
                        impact=(
                            "A stale or incomplete wheel can omit security fixes, "
                            "commands, controls, or typing contracts that are present "
                            "in the reviewed source tree."
                        ),
                        remediation=(
                            "Rebuild the wheel from the reviewed source tree in the "
                            "governed release lane, validate it, and rerun the artifact "
                            "or release profile."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        area="artifact-source-parity",
                        domain="supply-chain",
                        classifications=["WHEEL-SOURCE-PARITY"],
                        locations=[Location(path=path)],
                        sources=[
                            Source(
                                tool=self.name,
                                rule_id="source-wheel-parity",
                                message=f"missing wheel member: {member}",
                                native_severity="error",
                            )
                        ],
                        citations=[
                            Citation(
                                kind="standard",
                                identifier="PyPA-binary-distribution",
                                title="Python binary distribution format",
                                uri=(
                                    "https://packaging.python.org/en/latest/"
                                    "specifications/binary-distribution-format/"
                                ),
                            )
                        ],
                        evidence={
                            **artifact_identity_evidence(target, wheel),
                            "wheel": normalize_repo_path(target, wheel),
                            "member": member,
                            "issue": issue,
                            "source_sha256": source_digest,
                            "wheel_member_sha256": packaged_digests.get(member),
                        },
                    )
                )
                if len(findings) >= 50:
                    return findings
        return findings
