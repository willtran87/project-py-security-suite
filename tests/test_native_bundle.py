from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.execution import RawExecution
from py_security_suite.native_bundle import (
    render_native_bundle_verification,
    render_native_bundle_verification_markdown,
    verify_native_bundle,
)
from py_security_suite.report_inspection import read_bundled_schema


class NativeBundleVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        # unittest owns and closes this context at test cleanup.
        self.root = Path(
            self.enterContext(tempfile.TemporaryDirectory())  # pylint: disable=R1732
        )

    def test_closed_bundle_and_wheels_are_verified_without_execution(self) -> None:
        manifest = self._bundle(schema="2.0")
        document = verify_native_bundle(self.root)

        self.assertTrue(document["verified"])
        self.assertEqual(document["summary"]["declared_files"], 2)
        self.assertEqual(document["summary"]["wheels"], 1)
        self.assertEqual(document["wheelhouse_resolution"]["status"], "not_checked")
        self.assertIn(
            "VERIFIED: native bundle", render_native_bundle_verification(document)
        )
        self.assertIn(
            "# Native scanner bundle verification",
            render_native_bundle_verification_markdown(document),
        )
        schema = json.loads(read_bundled_schema("native-bundle-verification-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self.assertTrue(
            verify_native_bundle(self.root, manifest_sha256=digest)["verified"]
        )

    def test_closed_set_rejects_added_missing_changed_and_unsafe_paths(self) -> None:
        manifest = self._bundle(schema="1")
        (self.root / "unexpected.txt").write_text("extra", encoding="utf-8")
        failed = verify_native_bundle(self.root)
        self.assertFalse(failed["verified"])
        self.assertEqual(failed["unexpected"], ["unexpected.txt"])

        (self.root / "unexpected.txt").unlink()
        (self.root / "policy.txt").write_text("changed", encoding="utf-8")
        changed = verify_native_bundle(self.root)
        self.assertFalse(changed["verified"])
        self.assertEqual(changed["changed"][0]["path"], "policy.txt")

        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["files"][0]["path"] = "../escape"
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsafe relative path"):
            verify_native_bundle(self.root)
        with self.assertRaisesRegex(ValueError, "approved SHA-256"):
            verify_native_bundle(self.root, manifest_sha256="0" * 64)

    def test_required_wheelhouse_closure_is_fail_closed_and_bounded(self) -> None:
        self._bundle(schema="2.0")
        without_python = verify_native_bundle(
            self.root, require_wheelhouse_closure=True
        )
        self.assertFalse(without_python["verified"])
        self.assertEqual(without_python["wheelhouse_resolution"]["status"], "failed")

        def resolve(command: list[str], **_: object) -> RawExecution:
            report = Path(command[command.index("--report") + 1])
            report.write_text(json.dumps({"install": [{"metadata": {}}]}))
            self.assertIn("--no-index", command)
            self.assertIn("--isolated", command)
            return RawExecution(command, 0, "", "", 0.01)

        with patch("py_security_suite.native_bundle.run_command", side_effect=resolve):
            verified = verify_native_bundle(
                self.root,
                python=Path(sys.executable),
                require_wheelhouse_closure=True,
            )
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["wheelhouse_resolution"]["status"], "passed")
        self.assertEqual(verified["wheelhouse_resolution"]["passed"], 1)

    def test_manifest_wheel_and_resolution_failures_remain_actionable(self) -> None:
        manifest = self._bundle(schema="2.0")
        original_manifest = manifest.read_bytes()
        with self.assertRaisesRegex(ValueError, "exactly 64 hexadecimal"):
            verify_native_bundle(self.root, manifest_sha256="invalid")

        document = json.loads(original_manifest)
        document["schema_version"] = "unsupported"
        manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "schema_version"):
            verify_native_bundle(self.root)
        manifest.write_bytes(original_manifest)

        policy = self.root / "policy.txt"
        policy.unlink()
        missing = verify_native_bundle(self.root)
        self.assertEqual(missing["missing"], ["policy.txt"])
        policy.write_text("approved", encoding="utf-8")

        wheel = self.root / "wheelhouse" / "sample-1.0-py3-none-any.whl"
        wheel.write_bytes(b"not-a-wheel")
        document = json.loads(original_manifest)
        record = next(
            item for item in document["files"] if item["path"].endswith(".whl")
        )
        record["sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
        record["size"] = wheel.stat().st_size
        manifest.write_text(json.dumps(document), encoding="utf-8")
        malformed = verify_native_bundle(self.root)
        self.assertFalse(malformed["verified"])
        self.assertEqual(malformed["summary"]["wheel_errors"], 1)

        # Restore a valid bundle, then prove a resolver failure is a closed gate.
        # A second lifecycle-managed context isolates resolver evidence.
        self.root = Path(
            self.enterContext(tempfile.TemporaryDirectory())  # pylint: disable=R1732
        )
        self._bundle(schema="2.0")
        failure = RawExecution(["python"], 1, "", "missing", 0.01)
        with patch("py_security_suite.native_bundle.run_command", return_value=failure):
            unresolved = verify_native_bundle(
                self.root,
                python=Path(sys.executable),
                require_wheelhouse_closure=True,
            )
        self.assertFalse(unresolved["verified"])
        self.assertEqual(unresolved["wheelhouse_resolution"]["status"], "failed")

    def _bundle(self, *, schema: str) -> Path:
        wheelhouse = self.root / "wheelhouse"
        wheelhouse.mkdir()
        wheel = wheelhouse / "sample-1.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("sample.py", "VALUE = 1\n")
            archive.writestr(
                "sample-1.0.dist-info/METADATA",
                "Metadata-Version: 2.1\nName: sample\nVersion: 1.0\n",
            )
            archive.writestr(
                "sample-1.0.dist-info/WHEEL",
                "Wheel-Version: 1.0\nTag: py3-none-any\n",
            )
            archive.writestr(
                "sample/_vendor/nested-0.1.dist-info/METADATA",
                "Name: nested\nVersion: 0.1\n",
            )
        policy = self.root / "policy.txt"
        policy.write_text("approved", encoding="utf-8")
        files = [
            {
                "path": path.relative_to(self.root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size": path.stat().st_size,
            }
            for path in (policy, wheel)
        ]
        document: dict[str, object] = {
            "schema_version": schema,
            "platform": "test-platform",
            "files": files,
        }
        if schema == "2.0":
            document["python_environments"] = [
                {"name": "core", "requirements": ["sample==1.0"]}
            ]
        manifest = self.root / "bundle-manifest.json"
        manifest.write_text(json.dumps(document), encoding="utf-8")
        return manifest


if __name__ == "__main__":
    unittest.main()
