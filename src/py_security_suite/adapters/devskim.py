from __future__ import annotations

from pathlib import Path

from ..config import ToolConfig
from ..models import Finding
from .base import AdapterResult, ScannerAdapter
from .sarif import parse_sarif_findings
from .staging import mirrored_source_tree


class DevSkimAdapter(ScannerAdapter):
    name = "devskim"

    def __init__(self, config: ToolConfig, max_output_bytes: int) -> None:
        super().__init__(config, max_output_bytes)
        self._scan_root: Path | None = None

    def run(self, target: Path) -> AdapterResult:
        with mirrored_source_tree(target) as mirror:
            self._scan_root = mirror
            try:
                return super().run(target)
            finally:
                self._scan_root = None

    def build_command(self, executable: str, target: Path) -> list[str]:
        scan_root = self._scan_root or target.resolve()
        command = [
            executable,
            "analyze",
            "-I",
            str(scan_root),
            "-f",
            "sarif",
            "--base-path",
            str(scan_root),
            "--skip-excerpts",
            "--disable-console",
            "--ignore-rule-ids",
            # Dedicated secret scanners provide higher-signal coverage and
            # understand checksum allowlists used by the offline bundle.
            "DS173237",
            "-g",
            ".artifacts,.git,.pysec-tools,.venv,build,dist,node_modules",
        ]
        if self.config.rules_path is not None:
            command.extend(["-r", str(self.config.rules_path.expanduser().resolve())])
        return command

    def parse(self, payload: str, target: Path) -> list[Finding]:
        return parse_sarif_findings(
            payload,
            target,
            tool_name=self.name,
            default_area="code-security-pattern",
            default_impact=(
                "The cited implementation pattern can create an exploitable weakness "
                "or make a security boundary behave differently than intended."
            ),
            default_remediation=(
                "Apply the DevSkim rule guidance, add a regression test, and review "
                "equivalent call sites before accepting a suppression."
            ),
        )
