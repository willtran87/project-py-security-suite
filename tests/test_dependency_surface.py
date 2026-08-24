from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from py_security_suite.dependency_surface import dependency_surface_artifact
from py_security_suite.models import ToolRun, ToolStatus
from py_security_suite.strict_json import canonical_bytes


class DependencySurfaceTests(unittest.TestCase):
    def test_polyglot_lockfiles_require_vulnerability_and_semantic_coverage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "package-lock.json").write_text("{}", encoding="utf-8")
            artifacts = _receipts("package-lock.json", b"{}")
            partial = dependency_surface_artifact(
                target, [_run("osv-scanner")], artifacts
            )
            complete = dependency_surface_artifact(
                target, [_run("osv-scanner"), _run("polyglot")], artifacts
            )
        self.assertFalse(partial["complete"])
        self.assertTrue(complete["complete"])
        self.assertEqual(complete["coverage"][0]["ecosystem"], "javascript")
        self.assertEqual(complete["coverage"][0]["manifest"], "package-lock.json")
        self.assertEqual(len(complete["coverage"][0]["manifest_sha256"]), 64)
        self.assertEqual(len(complete["coverage"][0]["execution_receipts"]), 2)

    def test_completed_scanner_without_manifest_output_receipt_is_uncovered(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "uv.lock").write_text("version = 1", encoding="utf-8")
            artifact = dependency_surface_artifact(target, [_run("osv-scanner")], {})
        self.assertFalse(artifact["complete"])
        self.assertFalse(artifact["coverage"][0]["covered"])

    def test_unlocked_declaration_does_not_claim_resolved_dependency_coverage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "package.json").write_text("{}", encoding="utf-8")
            artifact = dependency_surface_artifact(
                target, [_run("osv-scanner"), _run("polyglot")]
            )
        self.assertFalse(artifact["complete"])
        self.assertFalse(artifact["coverage"][0]["resolved_dependency_identity"])


def _run(tool: str) -> ToolRun:
    return ToolRun(
        tool=tool,
        status=ToolStatus.COMPLETED,
        command=[tool],
        duration_seconds=0.1,
    )


def _receipts(manifest: str, payload: bytes) -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema_version": "1.0",
        "analysis": "osv-scanner-manifest-output-receipts",
        "tool": "osv-scanner",
        "raw_output_sha256": "a" * 64,
        "manifests": [
            {
                "manifest": manifest,
                "manifest_sha256": hashlib.sha256(payload).hexdigest(),
            }
        ],
    }
    receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    return {"osv-manifest-receipts.json": receipt}
