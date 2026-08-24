from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from companion.assurance_manifest import _execution_summary, main


def _execution() -> dict[str, object]:
    return {
        "status": "completed",
        "targets_discovered": 2,
        "targets_exercised": 2,
        "requests": 4,
        "coverage_percent": 100.0,
        "coverage_metric": "native-tool-target-coverage",
        "roles": ["anonymous"],
        "features": ["health-canary"],
        "skipped_checks": [],
        "canaries_expected": 1,
        "canaries_observed": 1,
    }


class CompanionAssuranceManifestTests(unittest.TestCase):
    def test_execution_summary_is_derived_from_a_strict_native_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "normalized.json"
            path.write_text(json.dumps({"execution": _execution(), "findings": []}))

            result = _execution_summary(path)

        self.assertEqual(result["targets_exercised"], 2)
        self.assertEqual(result["canaries_observed"], 1)

    def test_execution_summary_rejects_skips_and_missing_canaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "normalized.json"
            execution = _execution()
            execution["skipped_checks"] = ["authz"]
            path.write_text(json.dumps({"execution": execution, "findings": []}))
            with self.assertRaisesRegex(ValueError, "skipped"):
                _execution_summary(path)

            execution["skipped_checks"] = []
            execution["canaries_observed"] = 0
            path.write_text(json.dumps({"execution": execution, "findings": []}))
            with self.assertRaisesRegex(ValueError, "canary"):
                _execution_summary(path)

    def test_cli_has_no_free_form_coverage_or_canary_flags(self) -> None:
        with self.assertRaises(SystemExit):
            main(["--kind", "nuclei", "--coverage-percent", "100"])


if __name__ == "__main__":
    unittest.main()
