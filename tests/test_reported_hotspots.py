from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.adapters.actionlint import ActionlintAdapter
from py_security_suite.adapters.cosign import CosignAdapter, _bundle_for
from py_security_suite.adapters.hadolint import HadolintAdapter
from py_security_suite.adapters.pysa import PysaAdapter, _classify
from py_security_suite.adapters.shellcheck import ShellCheckAdapter
from py_security_suite.adapters.staging import (
    maintained_files,
    maintained_repository_files,
    mirrored_source_tree,
)
from py_security_suite.adapters.trivy import (
    TrivyAdapter,
    _licenses,
    _misconfigurations,
    _safe_uri,
)
from py_security_suite.adapters.vulture import VultureAdapter, _rule_id
from py_security_suite.adapters.zizmor import ZizmorAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.execution import RawExecution
from py_security_suite.models import ToolStatus


def _execution(
    command: list[str],
    *,
    exit_code: int | None = 0,
    stderr: str = "",
    timed_out: bool = False,
) -> RawExecution:
    return RawExecution(
        command=command,
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
        duration_seconds=0.01,
        timed_out=timed_out,
    )


class EntrypointAndStagingTests(unittest.TestCase):
    def test_module_entrypoint_propagates_cli_exit_code(self) -> None:
        with patch("py_security_suite.cli.main", return_value=7):
            with self.assertRaises(SystemExit) as raised:
                runpy.run_module("py_security_suite.__main__", run_name="__main__")
        self.assertEqual(raised.exception.code, 7)

    def test_maintained_file_inventory_and_mirror_prune_generated_trees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "src").mkdir()
            source = root / "src" / "app.py"
            source.write_text("value = 1\n", encoding="utf-8")
            (root / "README.md").write_text("# Fixture\n", encoding="utf-8")
            (root / ".artifacts").mkdir()
            (root / ".artifacts" / "secret.py").write_text(
                "ignored = True\n", encoding="utf-8"
            )

            inventory = maintained_repository_files(root)
            self.assertEqual(
                [path.relative_to(root).as_posix() for path in inventory],
                ["README.md", "src/app.py"],
            )
            self.assertEqual(maintained_files(root, frozenset({".py"})), [source])
            with mirrored_source_tree(root) as mirror:
                self.assertTrue((mirror / "src" / "app.py").is_file())
                self.assertTrue((mirror / "README.md").is_file())
                self.assertFalse((mirror / ".artifacts").exists())
            self.assertFalse(mirror.exists())


class LocalLinterGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()
        self.rules = self.root / "rules.yml"
        self.rules.write_text("fixture: true\n", encoding="utf-8")

    def test_actionlint_discovers_only_workflows_and_requires_local_rules(self) -> None:
        adapter = ActionlintAdapter(ToolConfig(), 4096)
        self.assertIn(
            "no GitHub Actions", adapter.not_applicable_reason(self.root) or ""
        )
        self.assertIn("configuration", adapter.prerequisite_error() or "")
        with self.assertRaisesRegex(ValueError, "rules path"):
            adapter.build_command("actionlint", self.root)

        workflows = self.root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        workflow = workflows / "ci.yml"
        workflow.write_text("name: ci\n", encoding="utf-8")
        (workflows / "notes.txt").write_text("ignored\n", encoding="utf-8")
        configured = ActionlintAdapter(ToolConfig(rules_path=self.rules), 4096)
        self.assertIsNone(configured.not_applicable_reason(self.root))
        self.assertIsNone(configured.prerequisite_error())
        command = configured.build_command("actionlint", self.root)
        self.assertIn(str(workflow.resolve()), command)
        self.assertNotIn(str((workflows / "notes.txt").resolve()), command)
        self.assertEqual(command[command.index("-shellcheck") + 1], "")
        with self.assertRaisesRegex(TypeError, "JSON list"):
            configured.parse("{}", self.root)
        with self.assertRaisesRegex(TypeError, "must be an object"):
            configured.parse("[1]", self.root)
        finding = configured.parse('[{"kind":"syntax","line":"bad"}]', self.root)[0]
        self.assertIsNone(finding.locations[0].start_line)

    def test_hadolint_discovers_dockerfiles_and_binds_rules_to_version(self) -> None:
        adapter = HadolintAdapter(ToolConfig(), 4096)
        self.assertIn("no Dockerfiles", adapter.not_applicable_reason(self.root) or "")
        self.assertIn("configuration", adapter.prerequisite_error() or "")
        self.assertEqual(adapter.version_command("hadolint"), ["hadolint", "--version"])
        with self.assertRaisesRegex(ValueError, "rules path"):
            adapter.build_command("hadolint", self.root)

        dockerfile = self.root / "service.dockerfile"
        dockerfile.write_text("FROM scratch\n", encoding="utf-8")
        configured = HadolintAdapter(ToolConfig(rules_path=self.rules), 4096)
        self.assertIsNone(configured.not_applicable_reason(self.root))
        self.assertIsNone(configured.prerequisite_error())
        command = configured.build_command("hadolint", self.root)
        self.assertIn(str(dockerfile.resolve()), command)
        self.assertIn(str(self.rules.resolve()), configured.version_command("hadolint"))
        with self.assertRaisesRegex(TypeError, "JSON list"):
            configured.parse("{}", self.root)
        with self.assertRaisesRegex(TypeError, "must be an object"):
            configured.parse("[1]", self.root)
        finding = configured.parse(
            '[{"code":"DL1","line":"bad","level":"note"}]', self.root
        )[0]
        self.assertIsNone(finding.locations[0].start_line)

    def test_shellcheck_discovers_extensions_and_shebangs(self) -> None:
        adapter = ShellCheckAdapter(ToolConfig(), 4096)
        self.assertIn(
            "no supported shell", adapter.not_applicable_reason(self.root) or ""
        )
        extension = self.root / "deploy.sh"
        extension.write_text("echo ok\n", encoding="utf-8")
        shebang = self.root / "release"
        shebang.write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
        (self.root / "README.md").write_text("#!/bin/sh\n", encoding="utf-8")
        scripts = adapter._scripts(self.root)
        self.assertEqual(scripts, sorted([extension.resolve(), shebang.resolve()]))
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertIn(
            "--severity=style", adapter.build_command("shellcheck", self.root)
        )
        with self.assertRaisesRegex(TypeError, "must be a list"):
            adapter.parse("{}", self.root)
        with self.assertRaisesRegex(TypeError, "must be an object"):
            adapter.parse("[1]", self.root)
        finding = adapter.parse('[{"code":"SC2086","line":"bad"}]', self.root)[0]
        self.assertEqual(finding.sources[0].rule_id, "SC2086")
        self.assertIsNone(finding.locations[0].start_line)

    def test_vulture_preflight_command_parser_and_rule_fallbacks(self) -> None:
        adapter = VultureAdapter(ToolConfig(), 4096)
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        self.assertIn("configuration", adapter.prerequisite_error() or "")
        with self.assertRaisesRegex(ValueError, "rules path"):
            adapter.build_command("vulture", self.root)
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        configured = VultureAdapter(ToolConfig(rules_path=self.rules), 4096)
        self.assertIsNone(configured.not_applicable_reason(self.root))
        self.assertIsNone(configured.prerequisite_error())
        command = configured.build_command("vulture", self.root)
        self.assertEqual(command[command.index("--min-confidence") + 1], "100")
        self.assertEqual(configured.parse("\n", self.root), [])
        with self.assertRaisesRegex(ValueError, "unexpected Vulture"):
            configured.parse("not native output", self.root)
        self.assertEqual(_rule_id("unused variable 'x'"), "unused-variable")
        self.assertEqual(_rule_id("unreachable code after return"), "unreachable-code")
        self.assertEqual(_rule_id("unused"), "dead-code")

    def test_zizmor_applicability_and_offline_command_cover_supported_inputs(
        self,
    ) -> None:
        adapter = ZizmorAdapter(ToolConfig(), 4096)
        self.assertIn(
            "no GitHub Actions", adapter.not_applicable_reason(self.root) or ""
        )
        dependabot = self.root / ".github" / "dependabot.yaml"
        dependabot.parent.mkdir()
        dependabot.write_text("version: 2\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        command = adapter.build_command("zizmor", self.root)
        self.assertIn("--offline", command)
        self.assertIn("--format=sarif", command)


class DeepScannerNormalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()

    def test_pysa_applicability_shapes_and_classification_matrix(self) -> None:
        adapter = PysaAdapter(ToolConfig(), 4096)
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.assertIn("configuration", adapter.not_applicable_reason(self.root) or "")
        (self.root / ".pyre_configuration").write_text("{}", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertEqual(
            adapter.build_command("pyre", self.root),
            ["pyre", "--noninteractive", "analyze"],
        )
        with self.assertRaisesRegex(TypeError, "list of issues"):
            adapter.parse('{"errors":{"bad":1}}', self.root)
        with self.assertRaisesRegex(TypeError, "must be an object"):
            adapter.parse("[1]", self.root)
        finding = adapter.parse(
            '{"results":[{"code":"x","concise_description":"path traversal","line":"bad"}]}',
            self.root,
        )[0]
        self.assertEqual(finding.area, "filesystem")
        self.assertIsNone(finding.locations[0].start_line)
        cases = (
            ("SQL query injection", "injection", "CWE-89"),
            ("shell command", "injection", "CWE-78"),
            ("path traversal", "filesystem", "CWE-22"),
            ("cross-site scripting", "web-output", "CWE-79"),
            ("credential logging", "data-exposure", "CWE-532"),
            ("generic flow", "data-flow", None),
        )
        for text, area, classification in cases:
            with self.subTest(text=text):
                _, actual_area, classifications = _classify(text, "")
                self.assertEqual(actual_area, area)
                if classification:
                    self.assertIn(classification, classifications)

    def test_trivy_applicability_environment_commands_and_validation(self) -> None:
        adapter = TrivyAdapter(ToolConfig(), 4096)
        self.assertIn(
            "no supported deployment", adapter.not_applicable_reason(self.root) or ""
        )
        (self.root / "requirements.txt").write_text("package==1\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        command = adapter.build_command("trivy", self.root)
        self.assertIn("--offline-scan", command)
        self.assertIn("--disable-telemetry", command)
        self.assertEqual(
            adapter.environment().extra["TRIVY_CACHE_DIR"],
            command[command.index("--cache-dir") + 1],
        )
        with self.assertRaisesRegex(TypeError, "Results must be a list"):
            adapter.parse('{"Results":{"bad":1}}', self.root)
        with self.assertRaisesRegex(TypeError, "result must be an object"):
            adapter.parse('{"Results":[1]}', self.root)

    def test_trivy_misconfiguration_and_license_edge_cases_are_safe(self) -> None:
        self.assertEqual(
            _misconfigurations({"Misconfigurations": {}}, "Dockerfile"), []
        )
        self.assertEqual(
            _misconfigurations({"Misconfigurations": [1]}, "Dockerfile"), []
        )
        misconfiguration = _misconfigurations(
            {
                "Misconfigurations": [
                    {
                        "AVDID": "AVD-1",
                        "Message": "unsafe deployment",
                        "Severity": "MEDIUM",
                        "PrimaryURL": "file:///not-allowed",
                        "CauseMetadata": [],
                    }
                ]
            },
            "Dockerfile",
        )[0]
        self.assertIsNone(misconfiguration.citations[0].uri)
        self.assertIsNone(misconfiguration.locations[0].start_line)

        self.assertEqual(_licenses({"Licenses": {}}, "LICENSE", self.root), [])
        self.assertEqual(_licenses({"Licenses": [1]}, "LICENSE", self.root), [])
        self.assertEqual(
            _licenses(
                {"Licenses": [{"Name": "MIT", "Severity": "LOW"}]},
                "LICENSE",
                self.root,
            ),
            [],
        )
        license_finding = _licenses(
            {
                "Licenses": [
                    {
                        "Name": "GPL-3.0",
                        "Category": "restricted",
                        "Severity": "HIGH",
                        "PkgName": "fixture",
                        "FilePath": str(self.root.parent / "outside.txt"),
                        "Link": "https://spdx.org/licenses/GPL-3.0-only.html",
                    }
                ]
            },
            "requirements.txt",
            self.root,
        )[0]
        self.assertEqual(license_finding.locations[0].path, "requirements.txt")
        self.assertEqual(license_finding.locations[0].package, "fixture")
        self.assertEqual(
            _safe_uri("https://example.test/rule"), "https://example.test/rule"
        )
        plain_http = "http" + "://example.test/rule"
        self.assertEqual(_safe_uri(plain_http), plain_http)
        self.assertIsNone(_safe_uri("file:///tmp/rule"))


class CosignRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.artifact = self.dist / "fixture-1.0-py3-none-any.whl"
        self.key = self.root / "cosign.pub"

    def _adapter(self, *, keyless: bool = False) -> CosignAdapter:
        if keyless:
            trusted_root = self.root / "trusted-root.json"
            trusted_root.write_text("{}", encoding="utf-8")
            config = ToolConfig(
                executable="cosign",
                artifacts_path=Path("dist"),
                provenance_path=Path("dist"),
                database_path=trusted_root,
                certificate_identity="release@example.test",
                certificate_oidc_issuer="https://issuer.example.test",
            )
        else:
            self.key.write_text("fixture", encoding="utf-8")
            config = ToolConfig(
                executable="cosign",
                artifacts_path=Path("dist"),
                provenance_path=Path("dist"),
                public_key_path=self.key,
            )
        return CosignAdapter(config, 4096)

    def test_cosign_applicability_prerequisites_and_contract(self) -> None:
        adapter = self._adapter()
        self.assertIn("no built wheel", adapter.not_applicable_reason(self.root) or "")
        skipped = adapter.run(self.root)
        self.assertEqual(skipped.tool_run.status, ToolStatus.SKIPPED)
        self.artifact.write_bytes(b"wheel")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertIsNone(adapter.prerequisite_error())
        self.key.unlink()
        self.assertIn("does not exist", adapter.prerequisite_error() or "")
        missing_identity = CosignAdapter(ToolConfig(), 4096)
        self.assertIn(
            "certificate_identity", missing_identity.prerequisite_error() or ""
        )
        missing_root = CosignAdapter(
            ToolConfig(
                certificate_identity="identity",
                certificate_oidc_issuer="issuer",
            ),
            4096,
        )
        self.assertIn("trusted-root", missing_root.prerequisite_error() or "")
        with self.assertRaises(NotImplementedError):
            adapter.build_command("cosign", self.root)
        self.assertEqual(adapter.parse("ignored", self.root), [])

    def test_cosign_run_unavailable_and_successful_key_verification(self) -> None:
        self.artifact.write_bytes(b"wheel")
        adapter = self._adapter()
        with patch.object(
            adapter, "_prepare_executable", return_value=(None, "bad hash")
        ):
            unavailable = adapter.run(self.root)
        self.assertEqual(unavailable.tool_run.status, ToolStatus.UNAVAILABLE)

        bundle = self.dist / f"{self.artifact.name}.sigstore.json"
        bundle.write_text("{}", encoding="utf-8")
        with (
            patch.object(adapter, "_prepare_executable", return_value=("cosign", None)),
            patch.object(adapter, "_detect_version", return_value="cosign 3"),
            patch.object(adapter, "_executable_changed_error", return_value=None),
            patch(
                "py_security_suite.adapters.cosign.run_command",
                return_value=_execution(["cosign", "verify-blob"]),
            ) as executed,
        ):
            result = adapter.run(self.root)
        self.assertEqual(result.tool_run.status, ToolStatus.COMPLETED)
        self.assertEqual(result.findings, [])
        command = executed.call_args.args[0]
        self.assertIn("--key", command)
        self.assertEqual(_bundle_for(self.dist, self.artifact), bundle.resolve())

    def test_cosign_keyless_failure_timeout_and_integrity_change_are_explicit(
        self,
    ) -> None:
        self.artifact.write_bytes(b"wheel")
        bundle = self.dist / f"{self.artifact.name}.bundle.json"
        bundle.write_text("{}", encoding="utf-8")
        cases = (
            (
                "verification",
                _execution(["cosign"], exit_code=1, stderr="invalid signature"),
                None,
                ToolStatus.COMPLETED,
            ),
            (
                "timeout",
                _execution(["cosign"], timed_out=True),
                None,
                ToolStatus.TIMED_OUT,
            ),
            ("changed", _execution(["cosign"]), "cosign changed", ToolStatus.FAILED),
        )
        for name, execution, changed, expected in cases:
            with self.subTest(name=name):
                adapter = self._adapter(keyless=True)
                with (
                    patch.object(
                        adapter, "_prepare_executable", return_value=("cosign", None)
                    ),
                    patch.object(adapter, "_detect_version", return_value="cosign 3"),
                    patch.object(
                        adapter, "_executable_changed_error", return_value=changed
                    ),
                    patch(
                        "py_security_suite.adapters.cosign.run_command",
                        return_value=execution,
                    ) as executed,
                ):
                    result = adapter.run(self.root)
                self.assertEqual(result.tool_run.status, expected)
                command = executed.call_args.args[0]
                self.assertIn("--trusted-root", command)
                if name == "verification":
                    self.assertEqual(
                        result.findings[0].sources[0].rule_id,
                        "COSIGN-VERIFICATION-FAILED",
                    )


if __name__ == "__main__":
    unittest.main()
