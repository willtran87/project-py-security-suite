from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Finding
from .base import ScannerAdapter


class CycloneDxAdapter(ScannerAdapter):
    name = "cyclonedx-py"

    def not_applicable_reason(self, target: Path) -> str | None:
        if self._input(target) is None:
            return (
                "no supported locked dependency source was found "
                "(poetry.lock, Pipfile.lock, or pinned requirements file)"
            )
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        selected = self._input(target)
        if selected is None:
            raise ValueError("CycloneDX input selection was not available")
        kind, value = selected
        command = [executable, kind]
        if kind in {"poetry", "pipenv"}:
            command.append(str(value))
        else:
            command.append(str(value))
        command.extend(
            [
                "--output-reproducible",
                "--output-format",
                "JSON",
                "--output-file",
                "-",
            ]
        )
        return command

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = _document(payload)
        if document.get("bomFormat") != "CycloneDX":
            raise ValueError("output is not a CycloneDX BOM")
        components = document.get("components", [])
        if components is not None and not isinstance(components, list):
            raise TypeError("CycloneDX components must be a list")
        return []

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {"sbom.cdx.json": _document(payload)}

    @staticmethod
    def _input(target: Path) -> tuple[str, Path] | None:
        if (target / "poetry.lock").is_file() and (target / "pyproject.toml").is_file():
            return "poetry", target.resolve()
        if (target / "Pipfile.lock").is_file():
            return "pipenv", target.resolve()
        preferred = (
            target / "requirements.txt",
            target / "requirements.lock",
            target / "requirements-dev.txt",
        )
        for path in preferred:
            if path.is_file() and _has_pinned_requirement(path):
                return "requirements", path.resolve()
        return None


def _document(payload: str) -> dict[str, Any]:
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise TypeError("CycloneDX output must be an object")
    return value


def _has_pinned_requirement(path: Path) -> bool:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    return any(
        "==" in line
        for line in lines
        if line.strip() and not line.lstrip().startswith(("#", "-", "git+"))
    )
