from __future__ import annotations

import tempfile
import uuid
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
from ..execution import RawExecution
from .base import AdapterResult, ScannerAdapter
from .common import contains_regular_file, native_suppression_finding

# Gitleaks 8.x always honours a ``.gitleaksignore`` in the scanned source root,
# even when ``--gitleaks-ignore-path`` names a different file. The suite cannot
# switch that off, so every entry is surfaced as an unaccepted finding instead.
NATIVE_IGNORE_FILE = ".gitleaksignore"
_NATIVE_IGNORE_ENTRY_LIMIT = 10_000
_DEFAULT_CONFIG = "[extend]\nuseDefault = true\n"


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    accepted_exit_codes = frozenset({0, 1})

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._report_path: Path | None = None
        self._ignore_path: Path | None = None
        self._config_path: Path | None = None
        self._exit_code: int | None = None
        self._mode = "dir"

    def not_applicable_reason(self, target: Path) -> str | None:
        if not contains_regular_file(target):
            return "the target contains no files to inspect for secret history"
        return None

    def prerequisite_error(self) -> str | None:
        config = self.config.rules_path
        if config is not None and not config.expanduser().resolve().is_file():
            return f"Gitleaks configuration does not exist: {config}"
        return None

    def run(self, target: Path) -> AdapterResult:
        try:
            return super().run(target)
        finally:
            for path in (self._report_path, self._ignore_path, self._config_path):
                if path is not None:
                    path.unlink(missing_ok=True)

    def build_command(self, executable: str, target: Path) -> list[str]:
        stem = Path(tempfile.gettempdir()) / f"pysec-gitleaks-{uuid.uuid4().hex}"
        self._report_path = stem.with_suffix(".json")
        # An empty suite-owned ignore file replaces the default lookup of
        # ``./.gitleaksignore`` in the scanner working directory (the target).
        self._ignore_path = stem.with_suffix(".gitleaksignore")
        self._ignore_path.write_bytes(b"")
        rules = self.config.rules_path
        if rules is None:
            # Without an explicit configuration Gitleaks would load a
            # target-controlled ``.gitleaks.toml`` and its allowlists.
            self._config_path = stem.with_suffix(".toml")
            self._config_path.write_text(_DEFAULT_CONFIG, encoding="utf-8")
            config_path = self._config_path
        else:
            config_path = rules.expanduser().resolve()
        self._mode = "git" if (target / ".git").is_dir() else "dir"
        return [
            executable,
            self._mode,
            "--config",
            str(config_path),
            "--gitleaks-ignore-path",
            str(self._ignore_path),
            "--ignore-gitleaks-allow",
            "--no-banner",
            "--log-level",
            "error",
            "--redact=100",
            "--report-format",
            "json",
            "--report-path",
            str(self._report_path),
            str(target.resolve()),
        ]

    def result_payload(self, execution: RawExecution) -> str:
        self._exit_code = execution.exit_code
        return execution.stdout

    def parse(self, payload: str, target: Path) -> list[Finding]:
        if self._report_path is None:
            raise ValueError("Gitleaks report path was not initialized")
        try:
            if not self._report_path.is_file():
                raise ValueError(
                    f"Gitleaks did not write its JSON report (exit {self._exit_code})"
                )
            report = self._report_path.read_text(encoding="utf-8")
        finally:
            self._report_path.unlink(missing_ok=True)
        if not report.strip():
            raise ValueError(f"Gitleaks wrote an empty report (exit {self._exit_code})")
        document = strict_json_loads(report)
        if not isinstance(document, list):
            raise TypeError("Gitleaks output must be a list")
        if self._exit_code not in (0, None) and not document:
            raise ValueError(
                f"Gitleaks exited {self._exit_code} but its report contains no leaks"
            )
        findings: list[Finding] = native_ignore_findings(self.name, target)
        for result in document:
            if not isinstance(result, dict):
                raise TypeError("Gitleaks finding must be an object")
            rule_id = str(result.get("RuleID") or "gitleaks.unknown")
            description = str(result.get("Description") or rule_id)
            path = normalize_repo_path(target, str(result.get("File") or "<unknown>"))
            line = _integer(result.get("StartLine"))
            commit = str(result.get("Commit") or "")
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
                start_line=line,
                advisory=commit or None,
            )
            historical = self._mode == "git"
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=(
                        "Credential candidate in repository history: "
                        if historical
                        else "Credential candidate in current tree: "
                    )
                    + description,
                    description=(
                        "Gitleaks identified a credential-shaped value. The value "
                        "was fully redacted before the suite parsed the result."
                    ),
                    impact=(
                        "A credential in the current tree or Git history may be "
                        "recoverable and usable by an unauthorized party."
                    ),
                    remediation=(
                        "Confirm the candidate without copying it into tickets, revoke "
                        "and rotate real credentials, remove them from history where "
                        "required, and add a narrowly governed allowlist for test data."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    area="secrets-history",
                    classifications=["CWE-798"],
                    locations=[Location(path=path, start_line=line, end_line=line)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=description,
                            native_severity="secret",
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=description,
                            uri="https://github.com/gitleaks/gitleaks",
                        )
                    ],
                    evidence={
                        "redacted": True,
                        "scan_mode": self._mode,
                        "commit": commit[:64] if commit else None,
                    },
                )
            )
        return findings


def native_ignore_findings(tool: str, target: Path) -> list[Finding]:
    """Surface target-owned ``.gitleaksignore`` entries as unaccepted findings."""
    ignore_file = target / NATIVE_IGNORE_FILE
    if not ignore_file.exists() and not ignore_file.is_symlink():
        return []
    if ignore_file.is_symlink() or not ignore_file.is_file():
        raise ValueError(f"{NATIVE_IGNORE_FILE} is not a regular file")
    entries = [
        number
        for number, line in enumerate(
            ignore_file.read_text(encoding="utf-8", errors="replace").splitlines(),
            start=1,
        )
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(entries) > _NATIVE_IGNORE_ENTRY_LIMIT:
        raise ValueError(f"{NATIVE_IGNORE_FILE} has too many entries to review")
    return [
        native_suppression_finding(
            tool,
            rule_id="gitleaks.native-suppression",
            path=NATIVE_IGNORE_FILE,
            line=number,
            mechanism=".gitleaksignore entry",
            area="secrets-history",
        )
        for number in entries
    ]


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
