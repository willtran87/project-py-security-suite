from __future__ import annotations

import json
import io
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import cast
from unittest.mock import patch

from py_security_suite.adapters.artifacts import (
    artifact_manifest,
    configured_path,
    distribution_files,
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
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.target = Path(self.enterContext(temporary)).resolve()
        self.dist = self.target / "dist"
        self.dist.mkdir()
        self.wheel = self.dist / "example-1.0-py3-none-any.whl"
        self.wheel.write_bytes(b"fixture")

    def test_artifact_roots_and_distribution_links_are_rejected(self) -> None:
        wheel = self.dist / "fixture.whl"
        wheel.write_bytes(b"fixture")
        with patch.object(Path, "is_junction", return_value=True, create=True):
            with self.assertRaisesRegex(ValueError, "symbolic link or junction"):
                configured_path(self.target, Path("dist"), "dist")
        with patch(
            "py_security_suite.adapters.artifacts.is_link_like",
            side_effect=lambda path: path == wheel,
        ):
            with self.assertRaisesRegex(ValueError, "artifact cannot be a link"):
                distribution_files(self.target, ToolConfig(artifacts_path=self.dist))

    def test_syft_retains_artifact_sbom(self) -> None:
        payload = json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        )
        adapter = SyftAdapter(ToolConfig(artifacts_path=Path("dist")), 4096)
        self.assertEqual(adapter.parse(payload, self.target), [])
        self.assertEqual(
            adapter.derived_artifacts(payload, self.target)["artifact-sbom.cdx.json"][
                "bomFormat"
            ],
            "CycloneDX",
        )
        command = adapter.build_command("syft", self.target)
        self.assertIn("cyclonedx-json", command)

    def test_artifact_manifest_binds_distribution_digest(self) -> None:
        manifest = artifact_manifest(
            self.target, ToolConfig(artifacts_path=Path("dist"))
        )
        artifacts = cast(list[object], manifest["artifacts"])
        self.assertIsInstance(artifacts, list)
        record = cast(dict[str, object], artifacts[0])
        self.assertIsInstance(record, dict)
        self.assertEqual(record["path"], "dist/example-1.0-py3-none-any.whl")
        self.assertEqual(len(cast(str, record["sha256"])), 64)
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

    def test_distribution_extraction_supports_safe_wheels_and_source_archives(
        self,
    ) -> None:
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr("example/__init__.py", "VERSION = '1.0'\n")
            archive.writestr("example/data/", "")
        source = self.dist / "example-1.0.tar.gz"
        with tarfile.open(source, "w:gz") as archive:
            body = b"from example import VERSION\n"
            member = tarfile.TarInfo("example-1.0/setup.py")
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))

        with extracted_distribution_tree(
            self.target, ToolConfig(artifacts_path=Path("dist"))
        ) as extracted:
            self.assertTrue(
                any(path.name == "__init__.py" for path in extracted.rglob("*.py"))
            )
            self.assertTrue(
                any(path.name == "setup.py" for path in extracted.rglob("*.py"))
            )

    def test_distribution_extraction_rejects_archive_links(self) -> None:
        with zipfile.ZipFile(self.wheel, "w") as archive:
            zip_link = zipfile.ZipInfo("example/link")
            zip_link.create_system = 3
            zip_link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(zip_link, "../outside")
        with self.assertRaisesRegex(ValueError, "links are not allowed"):
            with extracted_distribution_tree(
                self.target, ToolConfig(artifacts_path=Path("dist"))
            ):
                pass

        source = self.dist / "example-1.0.tar.gz"
        with tarfile.open(source, "w:gz") as archive:
            tar_link = tarfile.TarInfo("example-1.0/link")
            tar_link.type = tarfile.SYMTYPE
            tar_link.linkname = "../outside"
            archive.addfile(tar_link)
        self.wheel.unlink()
        with self.assertRaisesRegex(ValueError, "special files are not allowed"):
            with extracted_distribution_tree(
                self.target, ToolConfig(artifacts_path=Path("dist"))
            ):
                pass

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
        finding = GrypeAdapter(ToolConfig(), 4096).parse(payload, self.target)[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.area, "artifact-vulnerability")
        self.assertIn("2.0", finding.remediation)
        self.assertEqual(finding.sources[0].tool, "grype")
        self.assertEqual(
            GrypeAdapter(ToolConfig(), 4096)
            .environment()
            .extra["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"],
            "240h",
        )

    def test_wheel_issue_is_normalized(self) -> None:
        payload = f"{self.wheel}: W001: Wheel contains bytecode\n"
        finding = CheckWheelContentsAdapter(ToolConfig(), 4096).parse(
            payload, self.target
        )[0]
        self.assertEqual(finding.area, "artifact-integrity")
        self.assertEqual(finding.classifications, ["W001"])
        self.assertEqual(
            finding.evidence["artifact_path"],
            "dist/example-1.0-py3-none-any.whl",
        )
        self.assertEqual(
            finding.evidence["artifact_size_bytes"], self.wheel.stat().st_size
        )

    def test_wheel_missing_maintained_module_fails_source_parity(self) -> None:
        package = self.target / "src" / "example"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "security.py").write_text("ENABLED = True\n", encoding="utf-8")
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr("example/__init__.py", "")
        findings = CheckWheelContentsAdapter(ToolConfig(), 4096).parse("", self.target)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].classifications, ["WHEEL-SOURCE-PARITY"])
        self.assertEqual(findings[0].domain, "supply-chain")
        self.assertIn("example/security.py", findings[0].title)
        self.assertEqual(
            findings[0].evidence["artifact_path"],
            "dist/example-1.0-py3-none-any.whl",
        )

    def test_wheel_changed_module_fails_source_parity(self) -> None:
        package = self.target / "src" / "example"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("VERSION = 2\n", encoding="utf-8")
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr("example/__init__.py", "VERSION = 1\n")
        finding = CheckWheelContentsAdapter(ToolConfig(), 4096).parse("", self.target)[
            0
        ]
        self.assertEqual(finding.evidence["issue"], "content-mismatch")
        self.assertNotEqual(
            finding.evidence["source_sha256"],
            finding.evidence["wheel_member_sha256"],
        )

    def test_twine_error_is_normalized(self) -> None:
        payload = (
            f"Checking {self.wheel}: FAILED\n"
            "ERROR InvalidDistribution: malformed metadata\n"
        )
        finding = TwineAdapter(ToolConfig(), 4096).parse(payload, self.target)[0]
        self.assertEqual(finding.area, "artifact-metadata")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(
            finding.evidence["artifact_path"],
            "dist/example-1.0-py3-none-any.whl",
        )

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
        finding = TruffleHogAdapter(ToolConfig(rules_path=excludes), 4096).parse(
            payload, self.target
        )[0]
        self.assertNotIn("must-not-be-retained", json.dumps(json_ready(finding)))
        self.assertFalse(finding.evidence["verification_enabled"])
        command = TruffleHogAdapter(
            ToolConfig(rules_path=excludes), 4096
        ).build_command("trufflehog", self.target)
        self.assertIn("--no-verification", command)
        self.assertIn("--no-update", command)

    def test_attestation_requires_expected_publisher(self) -> None:
        adapter = PyPiAttestationsAdapter(ToolConfig(), 4096)
        self.assertIn("repository_url", adapter.prerequisite_error() or "")

    def test_attestation_is_not_applicable_to_unpublished_artifacts(self) -> None:
        distribution = self.target / "dist" / "package-1.0.0-py3-none-any.whl"
        distribution.parent.mkdir(exist_ok=True)
        distribution.write_bytes(b"wheel")
        adapter = PyPiAttestationsAdapter(ToolConfig(artifacts_path=Path("dist")), 4096)
        self.assertIn("unpublished", adapter.not_applicable_reason(self.target) or "")

    def test_codeql_uses_run_codeql_without_repository_override(self) -> None:
        command = CodeQlAdapter(ToolConfig(), 4096).build_command(
            "run-codeql", self.target
        )
        self.assertEqual(command[command.index("--lang") + 1], "python")
        self.assertEqual(command[command.index("--config") + 1], "")
        self.assertNotIn("--no-fail", command)


if __name__ == "__main__":
    unittest.main()
