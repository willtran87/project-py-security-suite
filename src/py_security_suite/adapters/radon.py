from __future__ import annotations

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
from .staging import maintained_files


class RadonAdapter(ScannerAdapter):
    name = "radon"

    def not_applicable_reason(self, target: Path) -> str | None:
        if not maintained_files(target, frozenset({".py"})):
            return "no Python source files were found"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "cc",
            "--json",
            "--show-complexity",
            "--min",
            "C",
            "--ignore",
            ".artifacts,.git,.mypy_cache,.pysec-tools,.pytest_cache,.ruff_cache,"
            + ".venv,__pycache__,build,dist,node_modules",
            str(target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = strict_json_loads(payload)
        if not isinstance(document, dict):
            raise TypeError("Radon JSON output must be an object")
        findings: list[Finding] = []
        for raw_path, blocks in sorted(document.items()):
            if not isinstance(blocks, list):
                raise TypeError("Radon file entry must be a list")
            path = normalize_repo_path(target, str(raw_path))
            for block in _flatten_blocks(blocks):
                rank = str(block.get("rank") or "C").upper()
                if rank not in {"E", "F"}:
                    continue
                complexity = _integer(block.get("complexity"))
                line = _integer(block.get("lineno"))
                end_line = _integer(block.get("endline")) or line
                name = str(block.get("name") or "unnamed block")
                block_type = str(block.get("type") or "block")
                rule_id = f"CC-{rank}"
                finding_id, fingerprint = finding_identity(
                    tool=self.name,
                    rule_id=rule_id,
                    path=path,
                    start_line=line,
                )
                findings.append(
                    Finding(
                        finding_id=finding_id,
                        fingerprint=fingerprint,
                        title=f"Complex {block_type}: {name} (rank {rank})",
                        description=(
                            f"Radon measured cyclomatic complexity {complexity} "
                            f"with rank {rank} for {name}."
                        ),
                        impact=(
                            "Complex control flow increases regression probability, "
                            "makes negative security paths harder to review, and "
                            "requires more tests for meaningful branch coverage."
                        ),
                        remediation=(
                            "Split independent decisions into focused functions, "
                            "reduce nesting, and add branch-focused tests before "
                            "accepting a complexity exception."
                        ),
                        severity=_rank_severity(rank),
                        confidence=Confidence.HIGH,
                        area="complexity",
                        domain="quality",
                        classifications=[f"RADON-{rule_id}"],
                        locations=[
                            Location(path=path, start_line=line, end_line=end_line)
                        ],
                        sources=[
                            Source(
                                tool=self.name,
                                rule_id=rule_id,
                                message=f"complexity={complexity}; rank={rank}",
                                native_severity=rank,
                            )
                        ],
                        citations=[
                            Citation(
                                kind="tool_rule",
                                identifier=rule_id,
                                title="Radon cyclomatic complexity ranks",
                                uri=(
                                    "https://radon.readthedocs.io/en/stable/"
                                    "commandline.html#the-cc-command"
                                ),
                            )
                        ],
                        evidence={"complexity": complexity, "rank": rank},
                    )
                )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {
            "radon-complexity.json": {
                "schema_version": "1.0",
                "minimum_reported_rank": "C",
                "files": strict_json_loads(payload),
            }
        }


def _flatten_blocks(blocks: list[object]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for value in blocks:
        if not isinstance(value, dict):
            raise TypeError("Radon block must be an object")
        flattened.append(value)
        for key in ("methods", "closures"):
            nested = value.get(key, [])
            if not isinstance(nested, list):
                raise TypeError(f"Radon {key} must be a list")
            flattened.extend(_flatten_blocks(nested))
    return flattened


def _integer(value: object) -> int:
    try:
        return int(str(value or 0))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"Radon integer value is invalid: {value!r}") from exc


def _rank_severity(rank: str) -> Severity:
    if rank in {"E", "F"}:
        return Severity.HIGH
    if rank == "D":
        return Severity.MEDIUM
    return Severity.LOW
