from __future__ import annotations

import json
from dataclasses import dataclass
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
)
from .base import ScannerAdapter
from .staging import maintained_files


@dataclass(slots=True, frozen=True)
class IslandPresentation:
    title_prefix: str
    description: str
    impact: str
    remediation: str
    classification: str
    severity: Severity
    cite_dead_code: bool


class ReachabilityAdapter(ScannerAdapter):
    """Normalize the suite's bounded, offline Python reachability analysis."""

    name = "reachability"

    def not_applicable_reason(self, target: Path) -> str | None:
        if not maintained_files(target, frozenset({".py"})):
            return "no Python source files were found"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        command = [
            executable,
            "reachability",
            str(target.resolve()),
            "--minimum-island-loc",
            str(self.config.minimum_island_loc),
        ]
        for root in self.config.source_roots:
            command.extend(("--source-root", root))
        for entry_point in self.config.entry_points:
            command.extend(("--entry-point", entry_point))
        if self.config.coverage_path is not None:
            coverage = self.config.coverage_path.expanduser()
            if not coverage.is_absolute():
                coverage = target / coverage
            command.extend(("--coverage", str(coverage.resolve())))
        if not self.config.discover_framework_roots:
            command.append("--no-framework-roots")
        return command

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = _document(payload)
        findings = [
            _analysis_error_finding(item, index)
            for index, item in enumerate(document["errors"], 1)
        ]
        entry_point_count = int(document["summary"]["entry_points"])
        if entry_point_count == 0:
            findings.append(_missing_roots_finding())
            return findings
        confidence = _confidence(document["analysis"].get("confidence"))
        dynamic_features = [str(value) for value in document["dynamic_features"]]
        precision_features = _strings(document.get("precision_features"))
        for island in document["islands"]:
            if not isinstance(island, dict) or not island.get("reportable"):
                continue
            findings.append(
                _island_finding(
                    island,
                    entry_point_count=entry_point_count,
                    confidence=confidence,
                    dynamic_features=dynamic_features,
                    precision_features=precision_features,
                )
            )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {"reachability.json": _document(payload)}


def _document(payload: str) -> dict[str, Any]:
    document = json.loads(payload)
    if not isinstance(document, dict):
        raise TypeError("reachability output must be an object")
    if document.get("schema_version") != "1.1":
        raise ValueError("unsupported reachability schema version")
    for key, expected in (
        ("analysis", dict),
        ("summary", dict),
        ("entry_points", list),
        ("representative_sequences", list),
        ("islands", list),
        ("nodes", list),
        ("edges", list),
        ("dynamic_features", list),
        ("warnings", list),
        ("errors", list),
    ):
        if not isinstance(document.get(key), expected):
            raise TypeError(f"reachability output {key} must be {expected.__name__}")
    if "precision_features" in document and not isinstance(
        document["precision_features"], list
    ):
        raise TypeError("reachability output precision_features must be list")
    return document


def _island_finding(
    island: dict[str, Any],
    *,
    entry_point_count: int,
    confidence: Confidence,
    dynamic_features: list[str],
    precision_features: list[str],
) -> Finding:
    island_id = str(island.get("id") or "unknown-island")
    island_kind = str(island.get("kind") or "module-island")
    state = str(island.get("state") or "disconnected")
    runtime_observation = str(island.get("runtime_observation") or "not-measured")
    primary = str(island.get("primary_module") or "unknown module")
    primary_symbol = str(island.get("primary_symbol") or "")
    modules = _strings(island.get("modules"))
    paths = _strings(island.get("paths"))
    module_count = _integer(island.get("module_count"))
    symbol_count = _integer(island.get("symbol_count"))
    lines_of_code = _integer(island.get("lines_of_code"))
    location_path = str(island.get("primary_path") or (paths[0] if paths else "."))
    start_line = max(1, _integer(island.get("primary_start_line")))
    end_line = max(start_line, _integer(island.get("primary_end_line")))
    rule_id = (
        "load-only-code" if state == "load-only" else f"disconnected-{island_kind}"
    )
    finding_id, fingerprint = finding_identity(
        tool="reachability",
        rule_id=rule_id,
        path=location_path,
        start_line=start_line,
        advisory=island_id,
    )
    subject = f"{primary}:{primary_symbol}" if primary_symbol else primary
    module_suffix = f" (+{module_count - 1} modules)" if module_count > 1 else ""
    uncertain_dynamic_features = [
        feature
        for feature in dynamic_features
        if not feature.startswith("resolved-literal-dynamic-import:")
    ]
    dynamic_note = (
        " Dynamic mechanisms were detected, so confirm configured roots before removal."
        if uncertain_dynamic_features
        else ""
    )
    raw_triage = island.get("triage")
    triage: dict[str, Any] = dict(raw_triage) if isinstance(raw_triage, dict) else {}
    recommended_actions = _strings(triage.get("recommended_actions"))
    presentation = _island_presentation(
        state=state,
        runtime_observation=runtime_observation,
        island_kind=island_kind,
        entry_point_count=entry_point_count,
        module_count=module_count,
        symbol_count=symbol_count,
        lines_of_code=lines_of_code,
        dynamic_note=dynamic_note,
    )
    classifications = [presentation.classification]
    if presentation.cite_dead_code:
        classifications.append("CWE-561")
    citations = _island_citations(rule_id, presentation.cite_dead_code)
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=(
            f"{presentation.title_prefix}: {subject}{module_suffix} "
            f"({lines_of_code} LOC)"
        ),
        description=presentation.description,
        impact=presentation.impact,
        remediation=(
            f"{presentation.remediation} Next action: {recommended_actions[0]}"
            if recommended_actions
            else presentation.remediation
        ),
        severity=presentation.severity,
        confidence=confidence,
        area="code-reachability",
        domain="quality",
        classifications=classifications,
        locations=[
            Location(path=location_path, start_line=start_line, end_line=end_line)
        ],
        sources=[
            Source(
                tool="reachability",
                rule_id=rule_id,
                message=(
                    f"{lines_of_code} LOC across {module_count} module(s) are "
                    f"classified as {state}"
                ),
                native_severity="candidate",
            )
        ],
        citations=citations,
        evidence={
            "island_id": island_id,
            "island_kind": island_kind,
            "state": state,
            "runtime_observation": runtime_observation,
            "entry_point_count": entry_point_count,
            "module_count": module_count,
            "symbol_count": symbol_count,
            "lines_of_code": lines_of_code,
            "modules": modules,
            "paths": paths,
            "symbols": _strings(island.get("symbols")),
            "dynamic_features": dynamic_features,
            "precision_features": precision_features,
            "reason": str(island.get("reason") or "no static path"),
            "triage": triage,
        },
    )


def _island_presentation(
    *,
    state: str,
    runtime_observation: str,
    island_kind: str,
    entry_point_count: int,
    module_count: int,
    symbol_count: int,
    lines_of_code: int,
    dynamic_note: str,
) -> IslandPresentation:
    if runtime_observation == "observed":
        return _observed_presentation(state, dynamic_note)
    if state == "load-only":
        return _load_only_presentation(
            entry_point_count, module_count, symbol_count, dynamic_note
        )
    return _disconnected_presentation(
        island_kind,
        entry_point_count,
        module_count,
        symbol_count,
        lines_of_code,
        dynamic_note,
    )


def _observed_presentation(state: str, dynamic_note: str) -> IslandPresentation:
    return IslandPresentation(
        title_prefix="Runtime-observed static candidate",
        description=(
            "Runtime coverage observed this code even though the static graph "
            f"classified it as {state}. This can identify a test-only path, indirect "
            "dispatch, or missing production entry-point model that should be "
            f"reviewed.{dynamic_note}"
        ),
        impact=(
            "The code is demonstrably exercised, but an unexplained static/runtime "
            "gap reduces confidence in unused-code conclusions for this path."
        ),
        remediation=(
            "Determine whether the observation is test-only or production-relevant. "
            "Declare missing production roots or framework conventions and retain the "
            "coverage evidence so both paths can be reviewed together."
        ),
        classification="PYREACH-OBSERVED-STATIC-GAP",
        severity=Severity.INFORMATIONAL,
        cite_dead_code=False,
    )


def _load_only_presentation(
    entry_point_count: int,
    module_count: int,
    symbol_count: int,
    dynamic_note: str,
) -> IslandPresentation:
    return IslandPresentation(
        title_prefix="Load-only code candidate",
        description=(
            f"This {module_count}-module, {symbol_count}-symbol candidate is loaded or "
            f"referenced from {entry_point_count} discovered entry point(s), but no "
            f"direct static call path invokes it.{dynamic_note}"
        ),
        impact=(
            "Load-only code increases review and maintenance cost and may indicate an "
            "unused callback, obsolete API, or dynamically dispatched extension."
        ),
        remediation=(
            "Confirm indirect dispatch, callback registration, reflection, dependency "
            "injection, and runtime coverage. Add an intentional entry point or focused "
            "test when the code is used; otherwise remove it in a reviewed change."
        ),
        classification="PYREACH-LOAD-ONLY-CANDIDATE",
        severity=Severity.LOW,
        cite_dead_code=False,
    )


def _disconnected_presentation(
    island_kind: str,
    entry_point_count: int,
    module_count: int,
    symbol_count: int,
    lines_of_code: int,
    dynamic_note: str,
) -> IslandPresentation:
    return IslandPresentation(
        title_prefix="Disconnected code island",
        description=(
            f"No static load or executable path from {entry_point_count} discovered "
            f"entry point(s) reaches this {module_count}-module, "
            f"{symbol_count}-symbol island.{dynamic_note}"
        ),
        impact=(
            "A large disconnected code island expands maintenance, review, test, "
            "and attack surface while potentially retaining obsolete behavior."
        ),
        remediation=(
            "Confirm framework registrations, reflection, dependency-injection, "
            "and plugin roots. Add every intentional dynamic root to "
            "tools.reachability.entry_points; otherwise remove the island in a "
            "reviewed change with focused regression tests."
        ),
        classification=f"PYREACH-DISCONNECTED-{island_kind.upper()}",
        severity=Severity.MEDIUM if lines_of_code >= 1000 else Severity.LOW,
        cite_dead_code=True,
    )


def _island_citations(rule_id: str, cite_dead_code: bool) -> list[Citation]:
    citations = [
        Citation(
            kind="tool_rule",
            identifier=rule_id,
            title="Python Security Suite three-state reachability analysis",
            uri=(
                "https://github.com/willtran87/project-py-security-suite/"
                "blob/main/docs/reachability.md"
            ),
        )
    ]
    if cite_dead_code:
        citations.insert(
            0,
            Citation(
                kind="classification",
                identifier="CWE-561",
                title="CWE-561: Dead Code",
                uri="https://cwe.mitre.org/data/definitions/561.html",
            ),
        )
    return citations


def _missing_roots_finding() -> Finding:
    finding_id, fingerprint = finding_identity(
        tool="reachability",
        rule_id="no-entry-points",
        path="pyproject.toml",
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title="Reachability analysis has no resolvable entry points",
        description=(
            "No package script, Python main module, recognized framework handler, "
            "or configured entry point could be resolved."
        ),
        impact=(
            "The suite cannot distinguish reachable modules from disconnected code, "
            "so unused-island conclusions are intentionally disabled."
        ),
        remediation=(
            "Configure tools.reachability.entry_points with module:function roots "
            "or declare application scripts in pyproject.toml, then rerun."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        area="code-reachability",
        domain="quality",
        classifications=["PYREACH-NO-ENTRY-POINTS"],
        locations=[Location(path="pyproject.toml")],
        sources=[
            Source(
                tool="reachability",
                rule_id="no-entry-points",
                message="no resolvable reachability roots",
                native_severity="incomplete",
            )
        ],
        citations=[
            Citation(
                kind="tool_rule",
                identifier="no-entry-points",
                title="Configuring reachability roots",
                uri=(
                    "https://github.com/willtran87/project-py-security-suite/"
                    "blob/main/docs/reachability.md#entry-point-discovery"
                ),
            )
        ],
        evidence={"entry_point_count": 0, "conclusions_disabled": True},
    )


def _analysis_error_finding(message: object, index: int) -> Finding:
    description = str(message)
    path = description.split(":", 1)[0]
    if not path.endswith(".py"):
        path = "."
    finding_id, fingerprint = finding_identity(
        tool="reachability",
        rule_id="analysis-incomplete",
        path=path,
        advisory=str(index),
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title="Reachability analysis is incomplete",
        description=description,
        impact=(
            "Missing source or graph evidence can hide reachable paths and makes "
            "unused-code conclusions incomplete."
        ),
        remediation="Resolve the cited source, scope, or resource-limit error and rerun.",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        area="code-reachability",
        domain="quality",
        classifications=["PYREACH-ANALYSIS-INCOMPLETE"],
        locations=[Location(path=path)],
        sources=[
            Source(
                tool="reachability",
                rule_id="analysis-incomplete",
                message=description,
                native_severity="error",
            )
        ],
        citations=[
            Citation(
                kind="tool_rule",
                identifier="analysis-incomplete",
                title="Reachability analysis limits",
                uri=(
                    "https://github.com/willtran87/project-py-security-suite/"
                    "blob/main/docs/reachability.md#limits-and-confidence"
                ),
            )
        ],
        evidence={"analysis_error": description},
    )


def _confidence(value: object) -> Confidence:
    try:
        return Confidence(str(value))
    except ValueError:
        return Confidence.UNKNOWN


def _integer(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _strings(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []
