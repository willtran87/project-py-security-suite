from __future__ import annotations

import json
from pathlib import Path

from scripts.validate_public_api import (
    _baseline_contract_failures,
    _compatible_action,
    main,
)


def test_checked_in_public_api_baseline_matches_live_surface() -> None:
    assert main() == 0


def test_public_api_baseline_covers_python_entry_points() -> None:
    root = Path(__file__).resolve().parents[1]
    baseline = json.loads(
        (root / "security" / "api-surface-1.1.json").read_text(encoding="utf-8")
    )
    assert baseline["stable_console_scripts"] == {
        "py-security-suite": "py_security_suite.cli:main",
        "pysec": "py_security_suite.cli:main",
        "pysec-evidence": "py_security_suite.evidence_ingest:main",
    }
    assert set(baseline["stable_python_callables"]) == {
        "py_security_suite.cli:main",
        "py_security_suite.evidence_ingest:main",
    }


def test_option_contract_allows_additive_choices_but_rejects_shape_changes() -> None:
    expected = {
        "action": "_StoreAction",
        "required": False,
        "nargs": None,
        "type": "str",
        "choices": ["stable"],
    }
    assert _compatible_action({**expected, "choices": ["stable", "new"]}, expected)
    assert not _compatible_action({**expected, "required": True}, expected)
    assert not _compatible_action({**expected, "type": "Path"}, expected)
    assert not _compatible_action({**expected, "choices": []}, expected)


def test_baseline_contract_rejects_detached_options_and_schema_digests() -> None:
    baseline = {
        "stable_cli_commands": ["scan"],
        "stable_cli_options": {"removed": ["--output"]},
        "stable_cli_option_contracts": {"scan": {"--missing": {}}},
        "stable_schema_resources": ["schema-1.0"],
        "stable_schema_sha256": {},
    }
    failures = _baseline_contract_failures(baseline)
    assert len(failures) == 6
