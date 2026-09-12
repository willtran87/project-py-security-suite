"""Narrow live-scan proof for Bandit's interpolation-free f-string false positives."""

from __future__ import annotations

import ast
from dataclasses import asdict
from pathlib import Path

from ..execution import sha256_file
from ..source_index import parse_python, read_python_source
from .base import AdapterResult


def refine_literal_sql(
    result: AdapterResult, target: Path, before: dict[str, str]
) -> None:
    """Only an unchanged, stand-alone assignment of an intrinsic literal qualifies.

    Dynamic interpolation, variable evaluation, calls, import bindings, and
    sanitizers are deliberately outside this proof. Imported findings do not
    pass through this live-run hook. Original exclusions remain in diagnostics.
    """
    retained, excluded = [], []
    for finding in result.findings:
        proof = None
        if (
            len(finding.sources) == 1
            and finding.sources[0].rule_id == "B608"
            and len(finding.locations) == 1
        ):
            location = finding.locations[0]
            path = target / location.path
            try:
                digest = before.get(location.path)
                if digest and sha256_file(path) == digest:
                    tree = parse_python(read_python_source(path, target), location.path)
                    statements = [
                        node
                        for node in ast.walk(tree)
                        if isinstance(node, ast.stmt)
                        and node.lineno == location.start_line
                    ]
                    if len(statements) == 1 and isinstance(statements[0], ast.Assign):
                        value = statements[0].value
                        if (
                            isinstance(value, ast.JoinedStr)
                            and value.lineno == location.start_line
                            and value.end_lineno == location.end_line
                            and all(
                                isinstance(part, ast.Constant)
                                and type(part.value) is str
                                for part in value.values
                            )
                            and sha256_file(path) == digest
                        ):
                            proof = {
                                "method": "interpolation-free-f-string-v1",
                                "source_sha256": digest,
                                "native_finding": asdict(finding),
                            }
            except (OSError, ValueError, SyntaxError):
                pass
        if proof is None:
            retained.append(finding)
        else:
            excluded.append(proof)
    if excluded:
        result.findings = retained
        result.tool_run.finding_count = len(retained)
        result.diagnostic["finding_count"] = len(retained)
        result.diagnostic["literal_sql_refinement"] = {
            "excluded_count": len(excluded),
            "exclusions": excluded,
        }
