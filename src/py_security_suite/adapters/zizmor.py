from __future__ import annotations

from pathlib import Path

from ..models import Finding
from .base import ScannerAdapter
from .sarif import parse_sarif_findings


class ZizmorAdapter(ScannerAdapter):
    name = "zizmor"

    def not_applicable_reason(self, target: Path) -> str | None:
        workflows = target / ".github" / "workflows"
        dependabot = target / ".github" / "dependabot.yml"
        dependabot_yaml = target / ".github" / "dependabot.yaml"
        actions = any(
            path.name in {"action.yml", "action.yaml"}
            for path in target.rglob("action.y*ml")
        )
        if not workflows.is_dir() and not dependabot.is_file() and not dependabot_yaml.is_file() and not actions:
            return "no GitHub Actions, composite actions, or Dependabot configuration found"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "--offline",
            "--format=sarif",
            str(target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        return parse_sarif_findings(
            payload,
            target,
            tool_name=self.name,
            default_area="ci-cd",
            default_impact=(
                "The workflow configuration may expose credentials, execute "
                "untrusted input, or weaken the integrity of the build pipeline."
            ),
            default_remediation=(
                "Apply the cited zizmor guidance, minimize token permissions, "
                "pin dependencies immutably, and separate untrusted input from scripts."
            ),
        )
