"""Typed contracts for high-value governed artifact boundaries.

These types deliberately model only schema-stable, cross-module records. Parser-local
JSON remains dynamically validated at its trust boundary instead of being cast early.
"""

from __future__ import annotations

from typing import TypedDict


class FrameworkImport(TypedDict):
    path: str
    line: int


class FrameworkModel(TypedDict):
    framework: str
    engine: str
    model_path: str
    model_sha256: str
    positive_canary_path: str
    positive_canary_sha256: str
    negative_canary_path: str
    negative_canary_sha256: str
    expected_rule_ids: list[str]
    verified: bool
    canary_execution_verified: bool
    positive_matches: list[str]
    negative_matches: list[str]


class FrameworkRecord(TypedDict):
    framework: str
    category: str
    imports: list[FrameworkImport]
    declared_models: list[FrameworkModel]
    completed_model_engines: list[str]
    complete: bool
    gaps: list[str]


class FrameworkCoverageArtifact(TypedDict):
    schema_version: str
    analysis: str
    manifest_path: str | None
    manifest_present: bool
    frameworks_detected: int
    frameworks_modeled: int
    complete: bool
    frameworks: list[FrameworkRecord]
    parse_errors: list[str]
    parse_errors_omitted: int
    manifest_errors: list[str]
    qualified_canary_finding_ids: list[str]
    claim_boundary: str
