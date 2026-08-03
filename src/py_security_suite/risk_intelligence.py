from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import IntelligenceConfig
from .models import Citation, Finding, json_ready
from .path_safety import resolve_regular_file

_MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
_MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024
_MAX_RECORDS = 500_000
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


@dataclass(slots=True)
class IntelligenceResult:
    errors: list[str] = field(default_factory=list)
    artifact: dict[str, Any] = field(default_factory=dict)


def enrich_findings(
    findings: list[Finding], config: IntelligenceConfig
) -> IntelligenceResult:
    configured = any((config.kev_path, config.epss_path, config.vex_path))
    if not configured:
        return IntelligenceResult(
            artifact={
                "schema_version": "1.0",
                "configured": False,
                "enriched_findings": 0,
                "snapshots": {},
            }
        )

    errors: list[str] = []
    snapshots: dict[str, dict[str, Any]] = {}
    kev: dict[str, dict[str, Any]] = {}
    epss: dict[str, dict[str, Any]] = {}
    vex: dict[str, dict[str, Any]] = {}
    for name, path, approved, loader in (
        ("kev", config.kev_path, config.kev_sha256, _load_kev),
        ("epss", config.epss_path, config.epss_sha256, _load_epss),
        ("vex", config.vex_path, config.vex_sha256, _load_vex),
    ):
        if path is None:
            continue
        try:
            data, metadata = _validated_snapshot(
                name, path, approved, config.maximum_age_days, loader
            )
            snapshots[name] = metadata
            if name == "kev":
                kev = data
            elif name == "epss":
                epss = data
            else:
                vex = data
        except (
            OSError,
            TypeError,
            ValueError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            errors.append(f"offline {name.upper()} intelligence is invalid: {exc}")

    enriched = 0
    kev_matches = 0
    epss_matches = 0
    vex_matches = 0
    for finding in findings:
        cves = _finding_cves(finding)
        if not cves:
            continue
        evidence: dict[str, Any] = {"cves": sorted(cves)}
        matched_kev = [kev[cve] for cve in sorted(cves) if cve in kev]
        matched_epss = [epss[cve] for cve in sorted(cves) if cve in epss]
        matched_vex = [vex[cve] for cve in sorted(cves) if cve in vex]
        if matched_kev:
            evidence["known_exploited"] = matched_kev
            _append_unique(finding.classifications, "CISA-KEV")
            _append_citation(
                finding,
                "CISA-KEV",
                "CISA Known Exploited Vulnerabilities Catalog",
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            )
            kev_matches += 1
        if matched_epss:
            highest = max(matched_epss, key=lambda item: float(item["probability"]))
            evidence["epss"] = matched_epss
            if (
                float(highest["probability"]) >= config.epss_high_probability
                or float(highest["percentile"]) >= config.epss_high_percentile
            ):
                _append_unique(finding.classifications, "EPSS-HIGH")
            _append_citation(
                finding,
                "EPSS",
                "FIRST Exploit Prediction Scoring System",
                "https://www.first.org/epss/",
            )
            epss_matches += 1
        if matched_vex:
            evidence["vex"] = matched_vex
            for item in matched_vex:
                _append_unique(
                    finding.classifications,
                    f"VEX-{str(item['state']).upper().replace('_', '-')}",
                )
            _append_citation(
                finding,
                "CYCLONEDX-VEX",
                "CycloneDX Vulnerability Exploitability Exchange",
                "https://cyclonedx.org/capabilities/vex/",
            )
            vex_matches += 1
        if len(evidence) > 1:
            finding.evidence = {**finding.evidence, "risk_intelligence": evidence}
            enriched += 1

    return IntelligenceResult(
        errors=errors,
        artifact={
            "schema_version": "1.0",
            "configured": True,
            "enriched_findings": enriched,
            "known_exploited_matches": kev_matches,
            "epss_matches": epss_matches,
            "vex_matches": vex_matches,
            "thresholds": {
                "epss_high_probability": config.epss_high_probability,
                "epss_high_percentile": config.epss_high_percentile,
                "maximum_age_days": config.maximum_age_days,
            },
            "snapshots": snapshots,
            "errors": errors,
        },
    )


def _validated_snapshot(
    name: str,
    path: Path,
    approved: str,
    maximum_age_days: float,
    loader: Any,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    resolved = resolve_regular_file(path, "snapshot")
    size = resolved.stat().st_size
    if size > _MAX_SNAPSHOT_BYTES:
        raise ValueError(f"snapshot exceeds {_MAX_SNAPSHOT_BYTES} bytes")
    data = resolved.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if not approved:
        raise ValueError("an approved SHA-256 digest is required")
    if digest != approved:
        raise ValueError(f"SHA-256 {digest} does not match approved digest")
    age_days = (datetime.now(UTC).timestamp() - resolved.stat().st_mtime) / 86_400
    if age_days < -1.0 or age_days > maximum_age_days:
        raise ValueError(
            f"snapshot age {age_days:.2f} days exceeds {maximum_age_days:.2f} days"
        )
    records, source_date = loader(data, resolved.suffix.casefold())
    return records, {
        "path": str(resolved),
        "sha256": digest,
        "size_bytes": size,
        "age_days": round(max(age_days, 0.0), 3),
        "source_date": source_date,
        "record_count": len(records),
        "kind": name,
    }


def _load_kev(data: bytes, suffix: str) -> tuple[dict[str, dict[str, Any]], str]:
    del suffix
    document = json.loads(data.decode("utf-8"))
    if not isinstance(document, dict) or not isinstance(
        document.get("vulnerabilities"), list
    ):
        raise TypeError("KEV JSON requires a vulnerabilities list")
    values = document["vulnerabilities"]
    if len(values) > _MAX_RECORDS:
        raise ValueError("KEV snapshot contains too many records")
    records: dict[str, dict[str, Any]] = {}
    for value in values:
        if not isinstance(value, dict):
            raise TypeError("KEV records must be objects")
        cve = _cve(value.get("cveID"))
        if not cve:
            raise ValueError("KEV record has an invalid cveID")
        records[cve] = {
            "cve": cve,
            "date_added": _bounded(value.get("dateAdded"), 30),
            "due_date": _bounded(value.get("dueDate"), 30),
            "known_ransomware_campaign_use": _bounded(
                value.get("knownRansomwareCampaignUse"), 30
            ),
            "required_action": _bounded(value.get("requiredAction"), 500),
        }
    return records, _bounded(document.get("dateReleased"), 50)


def _load_epss(data: bytes, suffix: str) -> tuple[dict[str, dict[str, Any]], str]:
    if suffix == ".gz" or data[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as package:
            data = package.read(_MAX_DECOMPRESSED_BYTES + 1)
        if len(data) > _MAX_DECOMPRESSED_BYTES:
            raise ValueError("EPSS snapshot exceeds decompression limit")
    text = data.decode("utf-8-sig")
    lines = text.splitlines()
    source_date = ""
    while lines and lines[0].startswith("#"):
        source_date = lines.pop(0)[:500]
    reader = csv.DictReader(lines)
    if not reader.fieldnames or not {"cve", "epss", "percentile"}.issubset(
        reader.fieldnames
    ):
        raise TypeError("EPSS CSV requires cve, epss, and percentile columns")
    records: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(reader):
        if index >= _MAX_RECORDS:
            raise ValueError("EPSS snapshot contains too many records")
        cve = _cve(value.get("cve"))
        if not cve:
            raise ValueError("EPSS record has an invalid CVE")
        probability = _probability(value.get("epss"), "epss")
        percentile = _probability(value.get("percentile"), "percentile")
        records[cve] = {
            "cve": cve,
            "probability": probability,
            "percentile": percentile,
        }
    return records, source_date


def _load_vex(data: bytes, suffix: str) -> tuple[dict[str, dict[str, Any]], str]:
    del suffix
    document = json.loads(data.decode("utf-8"))
    if not isinstance(document, dict) or not isinstance(
        document.get("vulnerabilities"), list
    ):
        raise TypeError("CycloneDX VEX requires a vulnerabilities list")
    values = document["vulnerabilities"]
    if len(values) > _MAX_RECORDS:
        raise ValueError("VEX snapshot contains too many records")
    records: dict[str, dict[str, Any]] = {}
    allowed_states = {
        "resolved",
        "resolved_with_pedigree",
        "exploitable",
        "in_triage",
        "false_positive",
        "not_affected",
    }
    for value in values:
        if not isinstance(value, dict):
            raise TypeError("VEX records must be objects")
        cve = _cve(value.get("id"))
        analysis = value.get("analysis", {})
        if not cve or not isinstance(analysis, dict):
            raise ValueError("VEX record requires a CVE id and analysis object")
        state = str(analysis.get("state") or "in_triage").casefold()
        if state not in allowed_states:
            raise ValueError(f"unsupported VEX analysis state: {state}")
        responses = analysis.get("response", [])
        if not isinstance(responses, list):
            responses = []
        records[cve] = {
            "cve": cve,
            "state": state,
            "justification": _bounded(analysis.get("justification"), 100),
            "detail": _bounded(analysis.get("detail"), 500),
            "response": [_bounded(item, 100) for item in responses[:20]],
        }
    metadata = document.get("metadata", {})
    source_date = (
        _bounded(metadata.get("timestamp"), 50) if isinstance(metadata, dict) else ""
    )
    return records, source_date


def _finding_cves(finding: Finding) -> set[str]:
    values: list[object] = [finding.title, finding.description]
    values.extend(finding.classifications)
    values.extend(item.identifier for item in finding.citations)
    values.extend(item.message for item in finding.sources)
    values.append(json.dumps(json_ready(finding.evidence), sort_keys=True))
    return {
        match.group(0).upper()
        for value in values
        for match in _CVE_PATTERN.finditer(str(value))
    }


def _cve(value: object) -> str:
    text = str(value or "").upper()
    return text if _CVE_PATTERN.fullmatch(text) else ""


def _probability(value: object, name: str) -> float:
    try:
        result = float(str(value))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"EPSS {name} must be numeric") from exc
    if not 0.0 <= result <= 1.0:
        raise ValueError(f"EPSS {name} must be between 0 and 1")
    return round(result, 6)


def _bounded(value: object, maximum: int) -> str:
    text = " ".join(str(value or "").split())
    return text[:maximum]


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _append_citation(finding: Finding, identifier: str, title: str, uri: str) -> None:
    if any(item.identifier == identifier for item in finding.citations):
        return
    finding.citations.append(
        Citation(
            kind="threat-intelligence", identifier=identifier, title=title, uri=uri
        )
    )
