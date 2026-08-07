from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.execution import RawExecution, sha256_file
from py_security_suite.passport import _SigningContext, sign_release_artifacts


def _empty_password() -> str:
    return ""


class ReleaseArtifactSigningTests(unittest.TestCase):
    def test_signs_every_distribution_and_publishes_verified_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / "dist"
            artifacts.mkdir()
            wheel = artifacts / "example-1.0-py3-none-any.whl"
            sdist = artifacts / "example-1.0.tar.gz"
            wheel.write_bytes(b"wheel")
            sdist.write_bytes(b"sdist")
            (artifacts / "ignore.txt").write_text("ignored", encoding="utf-8")
            executable = root / "cosign.exe"
            executable.write_bytes(b"approved cosign")
            key = root / "cosign.key"
            key.write_text("fixture key", encoding="utf-8")
            context = _SigningContext(
                key=key,
                executable=executable,
                executable_sha256=sha256_file(executable),
                integrity_verified=True,
                major_version=3,
                config=None,
                config_sha256="",
                password=_empty_password(),
            )

            def sign(command: list[str], **_: object) -> RawExecution:
                bundle = Path(command[command.index("--bundle") + 1])
                bundle.write_text('{"verificationMaterial":{}}', encoding="utf-8")
                return RawExecution(command, 0, "", "", 0.1)

            output = root / "provenance"
            with (
                patch(
                    "py_security_suite.passport._preflight_signing",
                    return_value=context,
                ),
                patch("py_security_suite.passport.run_command", side_effect=sign),
            ):
                material = sign_release_artifacts(
                    artifacts=artifacts,
                    output=output,
                    signing_key=key,
                    cosign_sha256=context.executable_sha256,
                )
                replacement = sign_release_artifacts(
                    artifacts=artifacts,
                    output=output,
                    signing_key=key,
                    cosign_sha256=context.executable_sha256,
                    overwrite=True,
                )

            self.assertEqual(material["artifact_count"], 2)
            self.assertEqual(replacement["artifact_count"], 2)
            self.assertTrue((output / f"{wheel.name}.sigstore.json").is_file())
            self.assertTrue((output / f"{sdist.name}.sigstore.json").is_file())
            manifest = json.loads(
                (output / "release-signing-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                {item["name"] for item in manifest["artifacts"]},
                {wheel.name, sdist.name},
            )
            self.assertTrue((output / "checksums.sha256").is_file())

    def test_refuses_to_overwrite_unrecognized_or_source_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "example.whl"
            artifact.write_bytes(b"wheel")
            key = root / "key"
            key.write_bytes(b"key")
            with self.assertRaisesRegex(ValueError, "cannot replace"):
                sign_release_artifacts(
                    artifacts=root,
                    output=root,
                    signing_key=key,
                    cosign_sha256="a" * 64,
                )

    def test_requires_distributions_and_cosign_three(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / "dist"
            artifacts.mkdir()
            key = root / "key"
            key.write_bytes(b"key")
            with self.assertRaisesRegex(ValueError, "contains no wheel"):
                sign_release_artifacts(
                    artifacts=artifacts,
                    output=root / "provenance",
                    signing_key=key,
                    cosign_sha256="a" * 64,
                )

            (artifacts / "example.whl").write_bytes(b"wheel")
            executable = root / "cosign.exe"
            executable.write_bytes(b"cosign")
            context = _SigningContext(
                key=key,
                executable=executable,
                executable_sha256=sha256_file(executable),
                integrity_verified=True,
                major_version=2,
                config=None,
                config_sha256="",
                password=_empty_password(),
            )
            with (
                patch(
                    "py_security_suite.passport._preflight_signing",
                    return_value=context,
                ),
                self.assertRaisesRegex(ValueError, "requires Cosign 3"),
            ):
                sign_release_artifacts(
                    artifacts=artifacts,
                    output=root / "provenance",
                    signing_key=key,
                    cosign_sha256=context.executable_sha256,
                )

    def test_failed_signing_does_not_publish_partial_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / "dist"
            artifacts.mkdir()
            (artifacts / "example.whl").write_bytes(b"wheel")
            executable = root / "cosign.exe"
            executable.write_bytes(b"cosign")
            key = root / "key"
            key.write_bytes(b"key")
            context = _SigningContext(
                key=key,
                executable=executable,
                executable_sha256=sha256_file(executable),
                integrity_verified=True,
                major_version=3,
                config=None,
                config_sha256="",
                password=_empty_password(),
            )
            output = root / "provenance"
            with (
                patch(
                    "py_security_suite.passport._preflight_signing",
                    return_value=context,
                ),
                patch(
                    "py_security_suite.passport.run_command",
                    return_value=RawExecution([], 1, "", "failed", 0.1),
                ),
                self.assertRaisesRegex(ValueError, "could not sign"),
            ):
                sign_release_artifacts(
                    artifacts=artifacts,
                    output=output,
                    signing_key=key,
                    cosign_sha256=context.executable_sha256,
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
