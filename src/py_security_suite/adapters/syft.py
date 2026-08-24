from __future__ import annotations

from pathlib import Path
from typing import Any

from ..execution import CommandEnvironment
from ..models import Finding
from ..strict_json import loads as strict_json_loads
from .artifacts import (
    artifact_manifest,
    configured_path,
    distribution_files,
    extracted_distribution_tree,
)
from .base import AdapterResult, ScannerAdapter


class SyftAdapter(ScannerAdapter):
    name = "syft"
    _scan_root: Path | None = None

    def not_applicable_reason(self, target: Path) -> str | None:
        if not distribution_files(target, self.config):
            return "no built wheel or source distribution was found"
        return None

    def environment(self) -> CommandEnvironment:
        return CommandEnvironment(
            extra={
                "SYFT_CHECK_FOR_APP_UPDATE": "false",
                "SYFT_FORMAT_PRETTY": "false",
            }
        )

    def build_command(self, executable: str, target: Path) -> list[str]:
        artifact_root = self._scan_root or configured_path(
            target, self.config.artifacts_path, "dist"
        )
        return [
            executable,
            "scan",
            f"dir:{artifact_root}",
            "--output",
            "cyclonedx-json",
            "--quiet",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = _document(payload)
        if document.get("bomFormat") != "CycloneDX":
            raise ValueError("Syft output is not a CycloneDX BOM")
        return []

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {
            "artifact-sbom.cdx.json": _document(payload),
            "artifact-manifest.json": artifact_manifest(target, self.config),
        }

    def run(self, target: Path) -> AdapterResult:
        if not distribution_files(target, self.config):
            return super().run(target)
        with extracted_distribution_tree(target, self.config) as scan_root:
            self._scan_root = scan_root
            try:
                return super().run(target)
            finally:
                self._scan_root = None


def _document(payload: str) -> dict[str, Any]:
    value = strict_json_loads(payload)
    if not isinstance(value, dict):
        raise TypeError("Syft output must be an object")
    return value
