from __future__ import annotations

import hashlib
import json
import tomllib
from datetime import date
from pathlib import Path

import jsonschema

from py_security_suite.risk_acceptance import validate_risk_acceptances


_ROOT = Path(__file__).resolve().parents[1]
_LEDGER = _ROOT / "security" / "self-scan-risk-acceptances.json"
_ACCEPTED_PACKAGES = {"mcp 1.29.0", "opentelemetry-api 1.37.0", "wcmatch 8.5.2"}


def test_self_scan_ledger_is_pinned_by_the_self_scan_policy() -> None:
    policy = tomllib.loads(
        (_ROOT / "security" / "self-scan.toml").read_text(encoding="utf-8")
    )["policy"]

    assert policy["risk_acceptance_path"] == (
        "/workspace/security/self-scan-risk-acceptances.json"
    )
    assert (
        policy["risk_acceptance_sha256"]
        == hashlib.sha256(_LEDGER.read_bytes()).hexdigest()
    )


def test_self_scan_ledger_accepts_only_the_semgrep_pinned_advisories() -> None:
    document = json.loads(_LEDGER.read_text(encoding="utf-8"))
    schema = json.loads(
        (_ROOT / "docs" / "schemas" / "risk-acceptance.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.validate(document, schema)
    entries = document["acceptances"]

    assert len(entries) == 8
    assert {entry["disposition"] for entry in entries} == {"accepted_risk"}
    assert {entry["expires"] for entry in entries} == {"2027-01-26"}
    for entry in entries:
        assert entry["finding_id"].startswith("PYSEC-")
        assert "semgrep==1.187.0" in entry["rationale"]
        assert any(package in entry["rationale"] for package in _ACCEPTED_PACKAGES)
    assert (
        validate_risk_acceptances(
            _LEDGER,
            hashlib.sha256(_LEDGER.read_bytes()).hexdigest(),
            today=date(2026, 11, 27),
        )
        == []
    )
