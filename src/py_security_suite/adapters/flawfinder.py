from __future__ import annotations

from pathlib import Path

from ..config import ToolConfig
from ..models import Finding
from .base import AdapterResult, ScannerAdapter
from .sarif import parse_sarif_findings
from .staging import maintained_files, mirrored_source_tree

_NATIVE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})


class FlawfinderAdapter(ScannerAdapter):
    name = "flawfinder"

    def __init__(self, config: ToolConfig, max_output_bytes: int) -> None:
        super().__init__(config, max_output_bytes)
        self._scan_root: Path | None = None

    def not_applicable_reason(self, target: Path) -> str | None:
        if not maintained_files(target, _NATIVE_SUFFIXES):
            return "no C or C++ native-extension source files were found"
        return None

    def run(self, target: Path) -> AdapterResult:
        if self.not_applicable_reason(target):
            return super().run(target)
        with mirrored_source_tree(target) as mirror:
            self._scan_root = mirror
            try:
                return super().run(target)
            finally:
                self._scan_root = None

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "--sarif",
            "--minlevel=2",
            "--quiet",
            str(self._scan_root or target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        return parse_sarif_findings(
            payload,
            target,
            tool_name=self.name,
            default_area="native-code",
            default_impact=(
                "The native-code construct may permit memory corruption, command "
                "injection, race conditions, or unsafe handling of trusted data."
            ),
            default_remediation=(
                "Replace the risky construct with a bounded alternative, validate all "
                "inputs, and exercise the native boundary with focused tests."
            ),
        )
