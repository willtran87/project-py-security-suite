from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import (  # pylint: disable=import-error
    Draft202012Validator,
    ValidationError,
)

from py_security_suite.report_inspection import (
    _entrypoint_integrity,
    _bounded_names,
    _line_number,
    _local_artifact_reference,
    _safe_text,
    _safe_web_uri,
    inspect_report,
    render_inspection,
)
from py_security_suite.passport import REQUIRED_REPORT_ARTIFACTS
from tests.report_fixtures import write_embedded_statement


_INSPECTION_SCHEMA = json.loads(
    files("py_security_suite")
    .joinpath("schemas", "report-inspection.schema.json")
    .read_text(encoding="utf-8")
)


class ReportInspectionTests(unittest.TestCase):
    def test_inspection_output_conforms_to_the_versioned_json_schema(self) -> None:
        Draft202012Validator.check_schema(_INSPECTION_SCHEMA)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_report(root)
            document = inspect_report(root)

        validator = Draft202012Validator(_INSPECTION_SCHEMA)
        validator.validate(document)
        self.assertEqual(document["schema_version"], "1.0")
        self.assertEqual(document["schema_id"], _INSPECTION_SCHEMA["$id"])
        invalid = json.loads(json.dumps(document))
        invalid["entrypoint_integrity"]["actions"][0]["required_actions"] = [
            "unversioned_action"
        ]
        with self.assertRaises(ValidationError):
            validator.validate(invalid)

    def test_verified_report_is_summarized_and_prioritized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_report(root)
            document = inspect_report(root, limit=1)
            complete_document = inspect_report(root, limit=2)
            local_rendered = render_inspection(document, report_root=root)

        self.assertTrue(document["verified"])
        self.assertEqual(document["findings"]["total"], 2)
        self.assertEqual(document["findings"]["blocking"], 1)
        self.assertEqual(document["tool_health"]["by_status"]["completed"], 1)
        self.assertEqual(document["tool_health"]["applicable"], 2)
        self.assertEqual(document["tool_health"]["not_applicable"], 1)
        self.assertEqual(document["tool_health"]["execution_gaps"], 1)
        self.assertFalse(document["tool_health"]["coverage_complete"])
        self.assertEqual(document["entrypoint_integrity"]["observed"], 3)
        self.assertEqual(document["entrypoint_integrity"]["approved_and_unchanged"], 1)
        self.assertEqual(
            document["entrypoint_integrity"]["unchanged_after_execution"], 2
        )
        self.assertEqual(document["entrypoint_integrity"]["postcheck_gaps"], 1)
        self.assertFalse(document["entrypoint_integrity"]["fully_approved"])
        self.assertEqual(
            document["entrypoint_integrity"]["approval_gap_entrypoints"],
            ["bandit:helper"],
        )
        self.assertEqual(
            document["entrypoint_integrity"]["postcheck_gap_entrypoints"],
            ["semgrep"],
        )
        self.assertEqual(
            document["entrypoint_integrity"]["approval_candidate_entrypoints"], 1
        )
        self.assertEqual(
            document["entrypoint_integrity"]["approval_candidate_unique_digests"],
            1,
        )
        trust_actions = document["entrypoint_integrity"]["actions"]
        self.assertEqual(
            [action["entrypoint"] for action in trust_actions],
            ["semgrep", "bandit:helper"],
        )
        self.assertEqual(trust_actions[0]["priority"], "P1")
        self.assertEqual(
            trust_actions[0]["required_actions"],
            ["restore_post_execution_verification"],
        )
        self.assertFalse(trust_actions[0]["approval_candidate"])
        self.assertIsNone(trust_actions[0]["configuration_key"])
        self.assertEqual(trust_actions[1]["priority"], "P2")
        self.assertEqual(trust_actions[1]["sha256"], "b" * 64)
        self.assertEqual(
            trust_actions[1]["configuration_key"],
            "tools.bandit.auxiliary_executable_sha256",
        )
        self.assertEqual(
            trust_actions[1]["required_actions"],
            ["verify_provenance_before_approval", "approve_exact_digest"],
        )
        self.assertEqual(document["scan_policy"]["disposition"], "block")
        self.assertEqual(document["top_actions"][0]["finding_id"], "PYSEC-HIGH")
        self.assertEqual(document["top_actions"][0]["source_rules"], ["bandit/B602"])
        self.assertEqual(document["top_actions"][0]["classifications"], ["CWE-78"])
        self.assertEqual(
            document["top_actions"][0]["citations"][0]["identifier"], "CWE-78"
        )
        self.assertEqual(document["top_actions"][0]["citations"][2]["uri"], "")
        self.assertEqual(document["top_actions"][0]["owners"], ["@security"])
        self.assertEqual(document["top_actions"][0]["details"], "index.html#PYSEC-HIGH")
        self.assertEqual(
            document["entrypoints"],
            {
                "html": "index.html",
                "summary": "summary.md",
                "action_plan": "action-plan.md",
            },
        )
        self.assertEqual(complete_document["top_actions"][1]["path"], "<repository>")
        self.assertEqual(complete_document["top_actions"][1]["source_rules"], [])
        self.assertEqual(complete_document["top_actions"][1]["classifications"], [])
        self.assertEqual(complete_document["top_actions"][1]["citations"], [])
        self.assertEqual(complete_document["top_actions"][1]["owners"], [])
        rendered = render_inspection(document)
        complete_rendered = render_inspection(complete_document)
        self.assertIn("FAIL: fixture", rendered)
        self.assertIn("Decision: BLOCK; report integrity: VERIFIED", rendered)
        self.assertIn("1 blocking", rendered)
        self.assertIn(
            "1/2 applicable completed; 1 not applicable; 1 execution gaps", rendered
        )
        self.assertIn(
            "Entrypoints: 1/3 approved and unchanged; 2/3 unchanged after execution",
            rendered,
        )
        self.assertIn("Trust action: approve digests for bandit:helper", rendered)
        self.assertIn("Trust action: restore post-checks for semgrep", rendered)
        self.assertIn(
            "Approval workload: 1 candidate binding across 1 unique digest",
            rendered,
        )
        self.assertIn("Policy reasons:", rendered)
        self.assertIn(
            "finding PYSEC-HIGH; bandit/B602; classification CWE-78; owner @security",
            rendered,
        )
        self.assertIn(
            "Reference: CWE command injection - https://cwe.example/78", rendered
        )
        self.assertIn("Reference: B602", rendered)
        self.assertIn("Action: Remediate the fixture.", rendered)
        self.assertIn("Review: ", rendered)
        self.assertIn("index.html#PYSEC-HIGH", rendered)
        self.assertNotIn("javascript:", rendered)
        self.assertIn("app.py:7", rendered)
        self.assertIn("Low fixture | <repository>", complete_rendered)
        self.assertIn(str(root.resolve() / "index.html"), local_rendered)
        self.assertIn(str(root.resolve() / "action-plan.md"), local_rendered)
        self.assertNotIn(str(root.resolve()), json.dumps(document))

    def test_terminal_text_and_citation_uris_are_safely_bounded(self) -> None:
        self.assertEqual(
            _bounded_names(["one", "two", "three"], limit=2),
            "one, two (+1 more)",
        )
        empty_integrity = _entrypoint_integrity([])
        self.assertEqual(empty_integrity["observed"], 0)
        self.assertFalse(empty_integrity["fully_approved"])
        self.assertEqual(empty_integrity["actions"], [])
        self.assertTrue(
            _entrypoint_integrity(
                [
                    {
                        "executable_sha256": "a" * 64,
                        "executable_integrity_verified": True,
                        "executable_unchanged": True,
                    }
                ]
            )["fully_approved"]
        )
        changed = _entrypoint_integrity(
            [
                {
                    "tool": "changed-tool",
                    "executable_sha256": "d" * 64,
                    "executable_integrity_verified": None,
                    "executable_unchanged": False,
                }
            ]
        )["actions"][0]
        self.assertEqual(changed["priority"], "P0")
        self.assertEqual(changed["postcheck_status"], "changed")
        self.assertFalse(changed["approval_candidate"])
        self.assertIsNone(changed["configuration_key"])
        self.assertEqual(
            changed["required_actions"],
            [
                "quarantine_changed_toolchain",
                "verify_provenance_before_approval",
                "approve_exact_digest",
            ],
        )
        sanitized = _safe_text("trusted\x1b[31m\u202espoof")
        self.assertEqual(sanitized, "trusted�[31m�spoof")
        self.assertNotIn("\x1b", sanitized)
        self.assertNotIn("\u202e", sanitized)
        self.assertEqual(_safe_text("token=exposed"), "token=<redacted>")
        self.assertEqual(len(_safe_text("x" * 5000)), 4096)
        self.assertTrue(_safe_text("x" * 5000).endswith("…"))
        self.assertEqual(
            _safe_web_uri("https://example.test/reference"),
            "https://example.test/reference",
        )
        self.assertEqual(_safe_web_uri("javascript:alert(1)"), "")
        self.assertEqual(_safe_web_uri("https://[invalid"), "")
        self.assertEqual(_line_number(7), 7)
        self.assertIsNone(_line_number("7\x1b[31m"))
        self.assertIsNone(_line_number(True))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(
                _local_artifact_reference("index.html#finding", root),
                f"{root.resolve() / 'index.html'}#finding",
            )
            self.assertEqual(
                _local_artifact_reference("../outside.html", root),
                "../outside.html",
            )
            original_resolve = Path.resolve
            linked = root / "linked.html"
            outside = root.parent / "outside.html"

            def resolve_link(path: Path, strict: bool = False) -> Path:
                if path == linked:
                    return outside
                return original_resolve(path, strict=strict)

            with patch.object(Path, "resolve", resolve_link):
                self.assertEqual(
                    _local_artifact_reference("linked.html", root),
                    "linked.html",
                )

    def test_limit_is_bounded(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 0 and 100"):
            inspect_report(Path("unused"), limit=101)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid_outcome = root / "invalid-outcome"
            invalid_outcome.mkdir()
            _write_report(invalid_outcome, outcome="unexpected")
            with self.assertRaisesRegex(ValueError, "outcome is invalid"):
                inspect_report(invalid_outcome)
            invalid_reasons = root / "invalid-reasons"
            invalid_reasons.mkdir()
            _write_report(invalid_reasons, policy_reasons={"bad": "shape"})
            with self.assertRaisesRegex(ValueError, "reasons must be a list"):
                inspect_report(invalid_reasons)
            invalid_findings = root / "invalid-findings"
            invalid_findings.mkdir()
            _write_report(invalid_findings, findings_value=["bad shape"])
            with self.assertRaisesRegex(ValueError, "findings must be a list"):
                inspect_report(invalid_findings)


def _write_report(
    root: Path,
    *,
    outcome: str = "fail",
    policy_reasons: object = None,
    findings_value: object = None,
) -> None:
    manifest = {
        "schema_version": "1.0",
        "suite_version": "0.1.0",
        "scan_id": "scan-fixture",
        "target": "fixture",
        "profile": "standard",
        "outcome": outcome,
        "duration_seconds": 1.25,
        "finished_at": "2026-08-01T00:00:00Z",
        "configuration_sha256": "b" * 64,
        "network_isolation_attested": True,
        "inventory": {
            "source_sha256": "a" * 64,
            "source_integrity_verified": True,
        },
        "finding_counts": {},
        "risk_acceptance_sha256": "",
        "intelligence": {},
        "baseline": {},
        "policy_reasons": (
            ["one blocking finding"] if policy_reasons is None else policy_reasons
        ),
        "artifacts": REQUIRED_REPORT_ARTIFACTS,
        "tools": [
            {
                "tool": "bandit",
                "status": "completed",
                "executable_sha256": "a" * 64,
                "executable_integrity_verified": True,
                "executable_unchanged": True,
                "auxiliary_executable_sha256": "b" * 64,
                "auxiliary_executable_integrity_verified": None,
                "auxiliary_executable_unchanged": True,
            },
            {"tool": "osv-scanner", "status": "skipped", "applicable": False},
            {
                "tool": "semgrep",
                "status": "skipped",
                "applicable": True,
                "executable_sha256": "c" * 64,
                "executable_integrity_verified": True,
                "executable_unchanged": None,
            },
        ],
    }
    findings = {
        "findings": (
            [
                _finding("PYSEC-LOW", "low", False, "existing", 20, sparse=True),
                _finding("PYSEC-HIGH", "high", True, "new", 7),
            ]
            if findings_value is None
            else findings_value
        )
    }
    files = {
        "scan-manifest.json": json.dumps(manifest),
        "findings.json": json.dumps(findings),
        "summary.md": "# Fixture\n",
        "action-plan.md": "# Actions\n",
        "index.html": "<!doctype html><title>Fixture</title>\n",
    }
    for relative in REQUIRED_REPORT_ARTIFACTS.values():
        if relative not in {"checksums.sha256", "security-passport.json"}:
            files.setdefault(relative, "fixture\n")
    for name, value in files.items():
        (root / name).write_text(value, encoding="utf-8", newline="\n")
    write_embedded_statement(root, manifest)
    files["security-passport.json"] = (root / "security-passport.json").read_text(
        encoding="utf-8"
    )
    checksums = [
        f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}"
        for name in sorted(files)
    ]
    (root / "checksums.sha256").write_text(
        "\n".join(checksums) + "\n", encoding="utf-8", newline="\n"
    )


def _finding(
    finding_id: str,
    severity: str,
    blocking: bool,
    status: str,
    line: int,
    *,
    sparse: bool = False,
) -> dict[str, object]:
    finding: dict[str, object] = {
        "finding_id": finding_id,
        "title": f"{severity.title()} fixture",
        "severity": severity,
        "blocking": blocking,
        "status": status,
        "domain": "security",
        "locations": [{"path": "app.py", "start_line": line}],
        "sources": [{"tool": "bandit", "rule_id": "B602"}],
        "classifications": ["CWE-78"],
        "citations": [
            {
                "identifier": "CWE-78",
                "title": "CWE command injection",
                "uri": "https://cwe.example/78",
            },
            {"identifier": "B602"},
            {
                "identifier": "unsafe-link",
                "title": "Unsafe citation",
                "uri": "javascript:alert(1)",
            },
        ],
        "evidence": {"owners": ["@security"]},
        "remediation": "Remediate the fixture.",
    }
    if sparse:
        finding.pop("locations")
        finding.pop("sources")
        finding.pop("classifications")
        finding.pop("citations")
        finding.pop("evidence")
        finding["remediation"] = ""
    return finding


if __name__ == "__main__":
    unittest.main()
