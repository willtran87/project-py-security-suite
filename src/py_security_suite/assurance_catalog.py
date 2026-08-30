from __future__ import annotations

import hashlib
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .benchmark_adapters import benchmark_adapter_specs, benchmark_execution_contracts
from .industry_assurance import (
    _ASSURANCE_PROFILES,
    _BENCHMARKS,
    _STANDARDS,
    _STANDARDS_WATCHLIST,
)
from .path_safety import read_regular_file, resolve_regular_file
from .standards_monitor import StandardsMonitorError, _validate_manifest
from .strict_json import canonical_bytes, loads as strict_loads


_MAX_INVENTORY_BYTES = 8 * 1024 * 1024
_MEDIA_TYPES = {
    "text/plain",
    "text/html",
    "application/json",
    "application/xml",
    "text/xml",
    "application/pdf",
}


class AssuranceCatalogError(ValueError):
    """Raised when a catalog or standards baseline cannot be compiled safely."""


def export_assurance_catalog() -> dict[str, Any]:
    """Export the executable registry as deterministic, digest-addressed data."""
    components: dict[str, Any] = {
        "standards": deepcopy(list(_STANDARDS)),
        "profiles": [
            {"id": identifier, **deepcopy(profile)}
            for identifier, profile in sorted(_ASSURANCE_PROFILES.items())
        ],
        "benchmarks": deepcopy(list(_BENCHMARKS)),
        "adapter_specs": benchmark_adapter_specs(),
        "execution_contracts": [
            deepcopy(contract)
            for _, contract in sorted(benchmark_execution_contracts().items())
        ],
        "standards_watchlist": deepcopy(list(_STANDARDS_WATCHLIST)),
    }
    component_sha256 = {
        name: hashlib.sha256(canonical_bytes(value)).hexdigest()
        for name, value in components.items()
    }
    result = {
        "schema_version": "1.0",
        "analysis": "industry-assurance-catalog-export",
        "counts": {name: len(value) for name, value in components.items()},
        "component_sha256": component_sha256,
        "components": components,
        "claim_boundary": (
            "This deterministic export makes the compiled registry reviewable and "
            "diffable. It does not assert publisher currency or certification."
        ),
    }
    result["catalog_sha256"] = hashlib.sha256(canonical_bytes(result)).hexdigest()
    return result


def build_standards_source_manifest(
    inventory_path: Path, *, selected_ids: set[str] | None = None
) -> dict[str, Any]:
    """Build a complete monitor manifest from verified local publisher baselines."""
    inventory_file, payload = read_regular_file(
        inventory_path,
        "standards baseline inventory",
        maximum_bytes=_MAX_INVENTORY_BYTES,
    )
    try:
        inventory = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise AssuranceCatalogError(
            "standards baseline inventory is invalid JSON"
        ) from exc
    records = _validate_inventory(inventory)
    standards = {str(item["id"]): item for item in _STANDARDS}
    selected = set(standards) if selected_ids is None else set(selected_ids)
    unknown = sorted(selected - set(standards))
    if unknown:
        raise AssuranceCatalogError(
            "unknown standards requested: " + ", ".join(unknown)
        )
    missing = sorted(selected - set(records))
    if missing:
        raise AssuranceCatalogError(
            "baseline inventory is incomplete for: " + ", ".join(missing[:20])
        )

    sources = []
    root = inventory_file.parent.resolve()
    for identifier in sorted(selected):
        standard = standards[identifier]
        record = records[identifier]
        path = resolve_regular_file(
            root / record["baseline_path"],
            f"{identifier} publisher baseline",
        )
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise AssuranceCatalogError(
                f"{identifier} baseline escapes the inventory directory"
            ) from exc
        actual = _sha256(path)
        if actual != record["baseline_sha256"]:
            raise AssuranceCatalogError(f"{identifier} baseline digest does not match")
        if path.stat().st_size > record["maximum_bytes"]:
            raise AssuranceCatalogError(f"{identifier} baseline exceeds its size limit")
        profiles, controls = _standard_impact(identifier)
        sources.append(
            {
                "id": identifier,
                "baseline_version": str(standard["version"]),
                "publisher": record["publisher"],
                "url": standard["reference"],
                "baseline_sha256": actual,
                "maximum_bytes": record["maximum_bytes"],
                "baseline_path": relative.as_posix(),
                "media_type": record["media_type"],
                "impact": {
                    "profiles": profiles,
                    "controls": controls,
                    "benchmarks": [],
                },
            }
        )
    hosts = sorted(
        {
            str(urlsplit(source["url"]).hostname).lower().rstrip(".")
            for source in sources
        }
    )
    manifest = {"schema_version": "1.0", "allowed_hosts": hosts, "sources": sources}
    try:
        _validate_manifest(manifest)
    except StandardsMonitorError as exc:  # pragma: no cover - defensive parity check
        raise AssuranceCatalogError(str(exc)) from exc
    return manifest


def _validate_inventory(value: object) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "baselines"}:
        raise AssuranceCatalogError("standards baseline inventory contract is invalid")
    baselines = value["baselines"]
    if value["schema_version"] != "1.0" or not isinstance(baselines, list):
        raise AssuranceCatalogError("standards baseline inventory contract is invalid")
    records: dict[str, dict[str, Any]] = {}
    expected = {
        "id",
        "publisher",
        "baseline_path",
        "baseline_sha256",
        "media_type",
        "maximum_bytes",
    }
    for record in baselines:
        if not isinstance(record, dict) or set(record) != expected:
            raise AssuranceCatalogError("standards baseline record is invalid")
        identifier = record["id"]
        maximum = record["maximum_bytes"]
        if (
            not isinstance(identifier, str)
            or identifier in records
            or not isinstance(record["publisher"], str)
            or not record["publisher"]
            or not isinstance(record["baseline_path"], str)
            or not record["baseline_path"]
            or Path(record["baseline_path"]).is_absolute()
            or ".." in Path(record["baseline_path"]).parts
            or not isinstance(record["baseline_sha256"], str)
            or len(record["baseline_sha256"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in record["baseline_sha256"]
            )
            or record["media_type"] not in _MEDIA_TYPES
            or not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or not 1 <= maximum <= 16 * 1024 * 1024
        ):
            raise AssuranceCatalogError("standards baseline record is invalid")
        records[identifier] = record
    return records


def _standard_impact(identifier: str) -> tuple[list[str], list[str]]:
    profiles = []
    controls = set()
    for profile_id, profile in _ASSURANCE_PROFILES.items():
        standards = set(profile["standards"])
        for standard, control_id, *_ in profile["controls"]:
            if standard == identifier:
                controls.add(str(control_id))
        for standard, *_ in profile["procedures"]:
            standards.add(str(standard))
        if identifier in standards:
            profiles.append(profile_id)
    return sorted(profiles), sorted(controls)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
