from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from py_security_suite.adapters.artifacts import (
    artifact_manifest,
    extracted_distribution_tree,
)
from py_security_suite.adapters.codeql import CodeQlAdapter
from py_security_suite.adapters.grype import GrypeAdapter
from py_security_suite.adapters.pypi_attestations import PyPiAttestationsAdapter
from py_security_suite.adapters.syft import SyftAdapter
from py_security_suite.adapters.trufflehog import TruffleHogAdapter
from py_security_suite.adapters.twine import TwineAdapter
from py_security_suite.adapters.wheel_contents import CheckWheelContentsAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.models import Severity, json_ready


class ArtifactAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.target = Path(self.temp.name).resolve()
        self.dist = self.target / "dist"
        self.dist.mkdir()
        self.wheel = self.dist / "example-1.0-py3-none-any.whl"
        self.wheel.write_bytes(b"fixture")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_syft_retains_artifact_sbom(self) -> None:
        payload = json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        )
        adapter = SyftAdapter(ToolConfig(artifacts_path=Path("dist")), 4096)
        self.assertEqual(adapter.parse(payload, self.target), [])
        self.assertEqual(
            adapter.derived_artifacts(payload, self.target)[
                "artifact-sbom.cdx.json"
            ]["bomFormat"],
            "CycloneDX",
        )
        command = adapter.build_command("syft", self.target)
        self.assertIn("cyclonedx-json", command)

    def test_artifact_manifest_binds_distribution_digest(self) -> None:
        manifest = artifact_manifest(
            self.target, ToolConfig(artifacts_path=Path("dist"))
        )
        record = manifest["artifacts"][0]
        self.assertEqual(record["path"], "dist/example-1.0-py3-none-any.whl")
        self.assertEqual(len(record["sha256"]), 64)
        self.assertEqual(record["size_bytes"], len(b"fixture"))

    def test_distribution_extraction_rejects_path_traversal(self) -> None:
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr("../outside.txt", "must not escape")
        with self.assertRaisesRegex(ValueError, "escapes extraction root"):
            with extracted_distribution_tree(
                self.target, ToolConfig(artifacts_path=Path("dist"))
            ):
                pass
        self.assertFalse((self.target / "outside.txt").exists())

    def test_grype_vulnerability_is_actionable(self) -> None:
        payload = json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "GHSA-test",
                            "severity": "High",
                            "description": "Example vulnerability",
                            "fix": {"versions": ["2.0"]},
                            "urls": ["https://example.invalid/GHSA-test"],
                        },
                        "artifact": {
                            "name": "example",
                            "version": "1.0",
                            "type": "python",
                            "locations": [{"path": "dist/example.whl"}],
                        },
                    }
                ]
            }
        )
        finding = GrypeAdapter(ToolConfig(), 4096).parse(
            payload, self.target
        )[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.area, "artifact-vulnerability")
        self.assertIn("2.0", finding.remediation)
        self.assertEqual(finding.sources[0].tool, "grype")

    def test_wheel_issue_is_normalized(self) -> None:
        payload = f"{self.wheel}: W001: Wheel contains bytecode\n"
        finding = CheckWheelContentsAdapter(ToolConfig(), 4096).parse(
            payload, self.target
        )[0]
        self.assertEqual(finding.area, "artifact-integrity")
        self.assertEqual(finding.classifications, ["W001"])

    def test_twine_error_is_normalized(self) -> None:
        payload = (
            f"Checking {self.wheel}: FAILED\n"
            "ERROR InvalidDistribution: malformed metadata\n"
        )
        finding = TwineAdapter(ToolConfig(), 4096).parse(
            payload, self.target
        )[0]
        self.assertEqual(finding.area, "artifact-metadata")
        self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_trufflehog_discards_secret_material(self) -> None:
        excludes = self.target / "trufflehog-excludes.txt"
        excludes.write_text(r"(^|[/\\])\.git([/\\]|$)", encoding="utf-8")
        payload = json.dumps(
            {
                "DetectorName": "PrivateKey",
                "DecoderName": "PLAIN",
                "Verified": False,
                "Raw": "must-not-be-retained",
                "RawV2": "must-not-be-retained",
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "keys.txt", "line": 3}}
                },
            }
        )
        finding = TruffleHogAdapter(
            ToolConfig(rules_path=excludes), 4096
        ).parse(
            payload, self.target
        )[0]
        self.assertNotIn(
            "must-not-be-retained", json.dumps(json_ready(finding))
        )
        self.assertFalse(finding.evidence["verification_enabled"])
        command = TruffleHogAdapter(
            ToolConfig(rules_path=excludes), 4096
        ).build_command("trufflehog", self.target)
        self.assertIn("--no-verification", command)
        self.assertIn("--no-update", command)

    def test_attestation_requires_expected_publisher(self) -> None:
        adapter = PyPiAttestationsAdapter(ToolConfig(), 4096)
        self.assertIn("repository_url", adapter.prerequisite_error() or "")

    def test_codeql_uses_run_codeql_without_repository_override(self) -> None:
        command = CodeQlAdapter(ToolConfig(), 4096).build_command(
            "run-codeql", self.target
        )
        self.assertEqual(command[command.index("--lang") + 1], "python")
        self.assertEqual(command[command.index("--config") + 1], "")
        self.assertNotIn("--no-fail", command)


if __name__ == "__main__":
    unittest.main()
