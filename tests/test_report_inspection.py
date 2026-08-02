from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from py_security_suite.report_inspection import inspect_report, render_inspection


class ReportInspectionTests(unittest.TestCase):
    def test_verified_report_is_summarized_and_prioritized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_report(root)
            document = inspect_report(root, limit=1)

        self.assertTrue(document["verified"])
        self.assertEqual(document["findings"]["total"], 2)
        self.assertEqual(document["findings"]["blocking"], 1)
        self.assertEqual(document["tool_health"]["by_status"]["completed"], 1)
        self.assertEqual(document["top_actions"][0]["finding_id"], "PYSEC-HIGH")
        self.assertEqual(document["top_actions"][0]["owners"], ["@security"])
        rendered = render_inspection(document)
        self.assertIn("FAIL: fixture", rendered)
        self.assertIn("1 blocking", rendered)
        self.assertIn("app.py:7", rendered)

    def test_limit_is_bounded(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 0 and 100"):
            inspect_report(Path("unused"), limit=101)


def _write_report(root: Path) -> None:
    manifest = {
        "schema_version": "1.0",
        "suite_version": "0.1.0",
        "scan_id": "scan-fixture",
        "target": "fixture",
        "profile": "standard",
        "outcome": "fail",
        "duration_seconds": 1.25,
        "finished_at": "2026-08-01T00:00:00Z",
        "policy_reasons": ["one blocking finding"],
        "tools": [
            {"tool": "bandit", "status": "completed"},
            {"tool": "osv-scanner", "status": "skipped"},
        ],
    }
    findings = {
        "findings": [
            _finding("PYSEC-LOW", "low", False, "existing", 20),
            _finding("PYSEC-HIGH", "high", True, "new", 7),
        ]
    }
    files = {
        "scan-manifest.json": json.dumps(manifest),
        "findings.json": json.dumps(findings),
        "summary.md": "# Fixture\n",
        "action-plan.md": "# Actions\n",
        "index.html": "<!doctype html><title>Fixture</title>\n",
    }
    for name, value in files.items():
        (root / name).write_text(value, encoding="utf-8", newline="\n")
    checksums = [
        f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}"
        for name in sorted(files)
    ]
    (root / "checksums.sha256").write_text(
        "\n".join(checksums) + "\n", encoding="utf-8", newline="\n"
    )


def _finding(
    finding_id: str, severity: str, blocking: bool, status: str, line: int
) -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "title": f"{severity.title()} fixture",
        "severity": severity,
        "blocking": blocking,
        "status": status,
        "domain": "security",
        "locations": [{"path": "app.py", "start_line": line}],
        "sources": [{"tool": "bandit"}],
        "evidence": {"owners": ["@security"]},
    }


if __name__ == "__main__":
    unittest.main()
