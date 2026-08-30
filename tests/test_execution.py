from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import signal
import subprocess  # nosec B404 - subprocess behavior is the test subject
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from py_security_suite.execution import (
    CommandEnvironment,
    _darwin_shared_cache_dependency,
    _kill_process_group_after_leader_exit,
    _process_tree_resident_bytes,
    _terminate_process_tree,
    governed_asset_sha256,
    isolated_environment,
    native_runtime_closure_sha256,
    python_runtime_closure_sha256,
    resolve_executable,
    run_command,
    sealed_governed_assets,
    sanitize_diagnostic,
    sanitize_terminal_text,
    sha256_file,
)


class IsolatedEnvironmentTests(unittest.TestCase):
    def test_governed_input_boundaries_reject_abusive_commands(self) -> None:
        cases = [
            ([], 30, 1024),
            (["x"] * 1025, 30, 1024),
            (["bad\x00argument"], 30, 1024),
            (["x"], 0, 1024),
            (["x"], 30, 0),
        ]
        for command, timeout, output_limit in cases:
            with self.subTest(command_length=len(command), timeout=timeout):
                with self.assertRaises(ValueError):
                    run_command(
                        command,
                        cwd=Path.cwd(),
                        timeout_seconds=timeout,
                        max_output_bytes=output_limit,
                    )

    def test_governed_input_boundaries_reject_oversized_environment(self) -> None:
        with self.assertRaisesRegex(ValueError, "environment"):
            run_command(
                [sys.executable, "-c", "pass"],
                cwd=Path.cwd(),
                timeout_seconds=30,
                max_output_bytes=1024,
                environment=CommandEnvironment(
                    extra={f"PYSEC_TEST_{index}": "x" for index in range(257)}
                ),
            )

    def test_missing_sandbox_launcher_is_rejected_before_spawn(self) -> None:
        with (
            patch("py_security_suite.execution.resolve_executable", return_value=None),
            self.assertRaisesRegex(ValueError, "sandbox launcher was not found"),
        ):
            run_command(
                [sys.executable, "-c", "pass"],
                cwd=Path.cwd(),
                timeout_seconds=30,
                max_output_bytes=1024,
                environment=CommandEnvironment(sandbox_prefix=("missing-sandbox",)),
            )

    def test_missing_governed_asset_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with self.assertRaisesRegex(ValueError, "not a regular file or directory"):
                governed_asset_sha256(missing)

    def test_darwin_shared_cache_allowlist_is_system_scoped(self) -> None:
        with patch("py_security_suite.execution.sys.platform", "darwin"):
            self.assertTrue(
                _darwin_shared_cache_dependency("/usr/lib/libSystem.B.dylib")
            )
            self.assertTrue(
                _darwin_shared_cache_dependency(
                    "/System/Library/Frameworks/Security.framework/Security"
                )
            )
            self.assertFalse(
                _darwin_shared_cache_dependency("/usr/local/lib/untrusted.dylib")
            )

    def test_process_tree_resident_memory_is_measured(self) -> None:
        self.assertGreater(_process_tree_resident_bytes(os.getpid()), 0)

    def test_resident_memory_limit_rejects_unsafe_floor(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 64 MiB"):
            run_command(
                [sys.executable, "-c", "pass"],
                cwd=Path.cwd(),
                timeout_seconds=10,
                max_output_bytes=1024,
                environment=CommandEnvironment(max_resident_memory_bytes=1),
            )

    def test_file_sha256_is_streamed_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scanner"
            path.write_bytes(b"approved scanner entry point")
            self.assertEqual(
                sha256_file(path),
                hashlib.sha256(b"approved scanner entry point").hexdigest(),
            )

    def test_governed_asset_snapshot_is_private_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "rules.json"
            original.write_bytes(b'{"rule":"approved"}')
            digest = hashlib.sha256(original.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "changed during scanner execution"):
                with sealed_governed_assets(
                    {"rules": original}, {"rules": digest}
                ) as copies:
                    snapshot = copies["rules"]
                    self.assertNotEqual(snapshot, original)
                    self.assertEqual(snapshot.read_bytes(), original.read_bytes())
                    original.write_bytes(b'{"rule":"unapproved"}')
                    self.assertEqual(snapshot.read_bytes(), b'{"rule":"approved"}')
                    os.chmod(snapshot, 0o600)
                    snapshot.write_bytes(b'{"rule":"tampered"}')

    def test_governed_directory_snapshot_is_sealed_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "rules"
            nested = original / "nested"
            nested.mkdir(parents=True)
            (original / "root.json").write_bytes(b'{"rule":"root"}')
            (nested / "child.json").write_bytes(b'{"rule":"child"}')
            digest = governed_asset_sha256(original)

            with sealed_governed_assets(
                {"rules": original}, {"rules": digest}
            ) as copies:
                snapshot = copies["rules"]
                self.assertEqual(governed_asset_sha256(snapshot), digest)
                self.assertEqual(
                    (snapshot / "nested" / "child.json").read_bytes(),
                    b'{"rule":"child"}',
                )

            with sealed_governed_assets({}, {}) as copies:
                self.assertEqual(copies, {})
            with self.assertRaisesRegex(ValueError, "no preflight digest"):
                with sealed_governed_assets({"rules": original}, {}):
                    pass

    def test_python_runtime_closure_binds_packages_stdlib_and_native_code(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package_root = root / "packages"
            stdlib = root / "stdlib"
            package_root.mkdir()
            stdlib.mkdir()
            primary_file = package_root / "scanner.py"
            dependency_file = package_root / "dependency.py"
            native_file = root / "native-component.bin"
            primary_file.write_bytes(b"scanner package")
            dependency_file.write_bytes(b"dependency package")
            native_file.write_bytes(b"native runtime")
            (stdlib / "runtime.py").write_bytes(b"standard library")

            primary = MagicMock()
            primary.metadata = {"Name": "scanner-package"}
            primary.files = [Path("scanner.py")]
            primary.locate_file.side_effect = lambda relative: package_root / relative
            primary.requires = ["dependency-package>=1", "not a requirement"]
            dependency = MagicMock()
            dependency.metadata = {"Name": "dependency-package"}
            dependency.files = [Path("dependency.py")]
            dependency.locate_file.side_effect = lambda relative: (
                package_root / relative
            )
            dependency.requires = []
            entry_point = MagicMock(name="scanner")
            entry_point.name = "scanner"
            entry_point.dist = primary
            entry_points = MagicMock()
            entry_points.select.return_value = [entry_point]

            def distribution(name: str) -> MagicMock:
                if name == "dependency-package":
                    return dependency
                raise importlib.metadata.PackageNotFoundError(name)

            with (
                patch(
                    "py_security_suite.execution.importlib.metadata.entry_points",
                    return_value=entry_points,
                ),
                patch(
                    "py_security_suite.execution.importlib.metadata.distributions",
                    return_value=[primary, dependency],
                ),
                patch(
                    "py_security_suite.execution.importlib.metadata.distribution",
                    side_effect=distribution,
                ),
                patch(
                    "py_security_suite.execution.sysconfig.get_path",
                    return_value=str(stdlib),
                ),
                patch(
                    "py_security_suite.execution._native_runtime_components",
                    return_value={native_file},
                ),
                patch(
                    "py_security_suite.execution._native_dependency_closure",
                    return_value=[native_file],
                ),
                patch(
                    "py_security_suite.execution._darwin_system_runtime_record",
                    return_value=None,
                ),
                patch("py_security_suite.execution._ENVIRONMENT_RUNTIME_CLOSURE", None),
            ):
                digest = python_runtime_closure_sha256(
                    str(root / "scanner-script.py"),
                    include_environment=True,
                    refresh=True,
                )
                self.assertEqual(len(digest or ""), 64)
                self.assertEqual(
                    python_runtime_closure_sha256(
                        str(root / "scanner-script.py"), include_environment=True
                    ),
                    digest,
                )

    def test_ambient_proxy_configuration_is_not_forwarded(self) -> None:
        ambient = {
            "HTTP_PROXY": "https://proxy.invalid",
            "HTTPS_PROXY": "https://proxy.invalid",
            "ALL_PROXY": "socks5://proxy.invalid",
            "NO_PROXY": "internal.example",
        }
        with patch.dict(os.environ, ambient, clear=False):
            environment = isolated_environment()

        for name in ambient:
            self.assertNotIn(name, environment)

    def test_loader_and_ambient_path_configuration_is_not_forwarded(self) -> None:
        ambient = {
            "PATH": str(Path.cwd()),
            "LD_LIBRARY_PATH": str(Path.cwd()),
            "DYLD_LIBRARY_PATH": str(Path.cwd()),
            "PYTHONPATH": str(Path.cwd()),
        }
        with patch.dict(os.environ, ambient, clear=False):
            environment = isolated_environment(executable=sys.executable)
        self.assertNotIn("LD_LIBRARY_PATH", environment)
        self.assertNotIn("DYLD_LIBRARY_PATH", environment)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn(str(Path.cwd()), environment["PATH"].split(os.pathsep))

    def test_isolated_environment_rejects_loader_path_overrides(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot override"):
            isolated_environment({"PYTHONPATH": "untrusted"})

    def test_scanner_process_receives_disposable_private_home(self) -> None:
        process = MagicMock()
        process.poll.return_value = 0
        process.returncode = 0
        with patch(
            "py_security_suite.execution.subprocess.Popen",
            return_value=process,
        ) as mocked_popen:
            run_command(
                ["scanner"],
                cwd=Path.cwd(),
                timeout_seconds=10,
                max_output_bytes=1024,
                environment=CommandEnvironment(),
            )

        environment = mocked_popen.call_args.kwargs["env"]
        private_home = Path(environment["HOME"])
        self.assertEqual(environment["USERPROFILE"], str(private_home))
        self.assertEqual(
            environment["LOCALAPPDATA"],
            str(private_home / "AppData" / "Local"),
        )
        self.assertFalse(private_home.exists())

    def test_timeout_terminates_process_tree_and_retains_bounded_output(self) -> None:
        process = MagicMock()
        process.poll.return_value = None
        with (
            patch(
                "py_security_suite.execution.subprocess.Popen",
                return_value=process,
            ),
            patch(
                "py_security_suite.execution._terminate_process_tree",
                return_value=True,
            ) as terminate,
            patch(
                "py_security_suite.execution.time.monotonic",
                side_effect=[0.0, *([2.0] * 8)],
            ),
        ):
            result = run_command(
                ["scanner"],
                cwd=Path.cwd(),
                timeout_seconds=1,
                max_output_bytes=4,
            )

        terminate.assert_called_once_with(process)
        self.assertTrue(result.timed_out)
        self.assertTrue(result.process_tree_terminated)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_interrupt_terminates_process_tree_before_propagating(self) -> None:
        process = MagicMock()
        process.poll.return_value = None
        with (
            patch(
                "py_security_suite.execution.subprocess.Popen",
                return_value=process,
            ),
            patch(
                "py_security_suite.execution._terminate_process_tree",
                return_value=True,
            ) as terminate,
            patch(
                "py_security_suite.execution.time.monotonic",
                side_effect=[0.0] * 8,
            ),
            patch(
                "py_security_suite.execution._directory_size_exceeds",
                side_effect=KeyboardInterrupt(),
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            run_command(
                ["scanner"],
                cwd=Path.cwd(),
                timeout_seconds=10,
                max_output_bytes=1024,
            )

        terminate.assert_called_once_with(process)

    def test_output_limit_terminates_process_without_buffering_unbounded_output(
        self,
    ) -> None:
        result = run_command(
            [sys.executable, "-c", "print('x' * 1000000)"],
            cwd=Path.cwd(),
            timeout_seconds=10,
            max_output_bytes=1024,
        )
        self.assertTrue(result.output_limit_exceeded)
        self.assertTrue(result.process_tree_terminated)
        self.assertLessEqual(len(result.stdout.encode()), 1024)
        self.assertTrue(result.stdout_truncated)

    def test_fast_exit_with_oversized_output_still_fails_closed(self) -> None:
        result = run_command(
            [sys.executable, "-c", "import os; os.write(1, b'x' * 2048)"],
            cwd=Path.cwd(),
            timeout_seconds=10,
            max_output_bytes=1024,
        )
        self.assertTrue(result.output_limit_exceeded)
        self.assertTrue(result.stdout_truncated)

    def test_digest_pinned_sandbox_launcher_wraps_the_scanner_command(self) -> None:
        launcher = (
            sys.executable,
            "-c",
            "import subprocess,sys; raise SystemExit(subprocess.run(sys.argv[1:]).returncode)",
        )
        result = run_command(
            [sys.executable, "-c", "print('sandboxed')"],
            cwd=Path.cwd(),
            timeout_seconds=10,
            max_output_bytes=1024,
            environment=CommandEnvironment(
                sandbox_prefix=launcher,
                sandbox_executable_sha256=sha256_file(Path(sys.executable)),
            ),
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout.strip(), "sandboxed")
        self.assertEqual(result.command[0], str(Path(sys.executable).resolve()))

    def test_sandbox_private_root_placeholder_is_scoped_and_masked(self) -> None:
        launcher = (
            sys.executable,
            "-c",
            (
                "import pathlib,subprocess,sys; "
                "assert pathlib.Path(sys.argv[1]).is_dir(); "
                "raise SystemExit(subprocess.run(sys.argv[2:]).returncode)"
            ),
            "{PYSEC_PRIVATE_ROOT}",
        )
        result = run_command(
            [sys.executable, "-c", "print('scoped')"],
            cwd=Path.cwd(),
            timeout_seconds=10,
            max_output_bytes=1024,
            environment=CommandEnvironment(
                sandbox_prefix=launcher,
                sandbox_executable_sha256=sha256_file(Path(sys.executable)),
            ),
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout.strip(), "scoped")
        self.assertIn("{PYSEC_PRIVATE_ROOT}", result.command)
        self.assertFalse(any("pysec-process-home-" in item for item in result.command))

    def test_sandbox_launcher_digest_mismatch_fails_before_execution(self) -> None:
        with self.assertRaisesRegex(ValueError, "sandbox launcher"):
            run_command(
                [sys.executable, "-c", "print('must not run')"],
                cwd=Path.cwd(),
                timeout_seconds=10,
                max_output_bytes=1024,
                environment=CommandEnvironment(
                    sandbox_prefix=(sys.executable,),
                    sandbox_executable_sha256="0" * 64,
                ),
            )

    def test_windows_process_tree_uses_resolved_taskkill_and_fallback(self) -> None:
        process = MagicMock()
        process.pid = 42
        process.poll.side_effect = [None, None, 0]
        completed = MagicMock(returncode=1)
        with (
            patch("py_security_suite.execution._running_on_windows", return_value=True),
            patch("py_security_suite.execution.Path.is_file", return_value=True),
            patch(
                "py_security_suite.execution.subprocess.run",
                return_value=completed,
            ) as taskkill,
        ):
            self.assertTrue(_terminate_process_tree(process))

        self.assertTrue(taskkill.call_args.args[0][0].endswith("taskkill.exe"))
        process.kill.assert_called_once()

    def test_windows_process_tree_falls_back_when_taskkill_is_missing(self) -> None:
        process = MagicMock()
        process.poll.side_effect = [None, 0]
        with (
            patch("py_security_suite.execution._running_on_windows", return_value=True),
            patch("py_security_suite.execution.Path.is_file", return_value=False),
        ):
            self.assertTrue(_terminate_process_tree(process))
        process.kill.assert_called_once()

    def test_posix_process_tree_escalates_the_process_group(self) -> None:
        process = MagicMock()
        process.pid = 42
        process.poll.side_effect = [None, 0]
        process.wait.side_effect = [
            subprocess.TimeoutExpired(["scanner"], 2),
            None,
        ]
        kill_process_group = MagicMock()
        with (
            patch("py_security_suite.execution.os.name", "posix"),
            patch.dict(
                "py_security_suite.execution.os.__dict__",
                {"killpg": kill_process_group},
            ),
            patch.dict(
                "py_security_suite.execution.signal.__dict__",
                {"SIGKILL": 9},
            ),
        ):
            self.assertTrue(_terminate_process_tree(process))

        self.assertEqual(
            kill_process_group.call_args_list,
            [call(42, signal.SIGTERM), call(42, 9)],
        )

    def test_process_tree_cleanup_is_idempotent_after_process_exit(self) -> None:
        process = MagicMock()
        process.poll.return_value = 0
        self.assertTrue(_terminate_process_tree(process))
        process.kill.assert_not_called()

    def test_post_exit_cleanup_rejects_unsafe_process_groups(self) -> None:
        kill_process_group = MagicMock()
        process = MagicMock()
        with (
            patch.dict(
                "py_security_suite.execution.os.__dict__",
                {"killpg": kill_process_group, "getpgrp": MagicMock(return_value=42)},
            ),
            patch.dict(
                "py_security_suite.execution.signal.__dict__",
                {"SIGKILL": 9},
            ),
        ):
            for pid, poll_result in ((1, 0), (42, 0), (MagicMock(), 0), (84, None)):
                process.pid = pid
                process.poll.return_value = poll_result
                _kill_process_group_after_leader_exit(process)

        kill_process_group.assert_not_called()

    def test_post_exit_cleanup_kills_only_the_isolated_process_group(self) -> None:
        kill_process_group = MagicMock()
        process = MagicMock(pid=84)
        process.pid = 84
        process.poll.return_value = 0
        with (
            patch.dict(
                "py_security_suite.execution.os.__dict__",
                {"killpg": kill_process_group, "getpgrp": MagicMock(return_value=42)},
            ),
            patch.dict(
                "py_security_suite.execution.signal.__dict__",
                {"SIGKILL": 9},
            ),
        ):
            _kill_process_group_after_leader_exit(process)

        kill_process_group.assert_called_once_with(84, 9)

    def test_executable_resolution_and_terminal_sanitization_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "scanner.exe"
            executable.write_bytes(b"scanner")
            self.assertEqual(resolve_executable(str(executable)), str(executable))
            self.assertIsNone(resolve_executable(str(executable.with_name("missing"))))
        self.assertEqual(
            sanitize_diagnostic("token=visible\nmessage", maximum=100),
            "token=<redacted>\nmessage",
        )
        self.assertEqual(
            sanitize_terminal_text("line\nsecret=x", maximum=12), "line�secret…"
        )

    def test_native_runtime_closure_binds_declared_plugin_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "scanner"
            plugin = root / "plugins" / "custom.plugin"
            plugin.parent.mkdir()
            executable.write_bytes(b"scanner entry point")
            plugin.write_bytes(b"approved plugin")
            manifest = executable.with_name(f"{executable.name}.runtime-closure.json")
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "plugins": [
                            {
                                "path": "plugins/custom.plugin",
                                "sha256": hashlib.sha256(
                                    b"approved plugin"
                                ).hexdigest(),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            approved = native_runtime_closure_sha256(executable)
            self.assertEqual(approved, native_runtime_closure_sha256(executable))
            plugin.write_bytes(b"replaced plugin")
            with self.assertRaisesRegex(ValueError, "plugin SHA-256"):
                native_runtime_closure_sha256(executable)

    def test_production_native_runtime_requires_explicit_plugin_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "scanner.bin"
            executable.write_bytes(b"not-a-platform-binary")
            with self.assertRaisesRegex(ValueError, "runtime-plugin manifest"):
                native_runtime_closure_sha256(executable, require_plugin_manifest=True)

    @patch("py_security_suite.trusted_observation.scan_observed_at")
    @patch("py_security_suite.execution.verify_governance_quorum")
    def test_production_native_runtime_requires_loader_observation(
        self, verify_authority: MagicMock, observed_at: MagicMock
    ) -> None:
        observed_at.return_value = datetime.now(UTC)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "scanner.bin"
            plugin = root / "plugin.bin"
            collector = root / "collector.bin"
            os_component = root / "os-component.bin"
            for path, payload in (
                (executable, b"scanner"),
                (plugin, b"plugin"),
                (collector, b"collector"),
                (os_component, b"os-component"),
            ):
                path.write_bytes(payload)
            manifest = executable.with_name(f"{executable.name}.runtime-closure.json")
            component = {
                "path": "plugin.bin",
                "sha256": hashlib.sha256(b"plugin").hexdigest(),
            }
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": "1.2",
                        "plugins": [component],
                        "observation": {
                            "collector": "collector.bin",
                            "collector_sha256": hashlib.sha256(
                                b"collector"
                            ).hexdigest(),
                            "platform": sys.platform,
                            "observed_components": [
                                {**component, "scope": "plugin"},
                                {
                                    "path": "os-component.bin",
                                    "sha256": hashlib.sha256(
                                        b"os-component"
                                    ).hexdigest(),
                                    "scope": "os-tcb",
                                },
                            ],
                        },
                        "minimum_authority_signatures": 2,
                        "authorities": [
                            {"receipt": "authority-a"},
                            {"receipt": "authority-b"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            digest = native_runtime_closure_sha256(
                executable, require_plugin_manifest=True
            )
            self.assertEqual(len(digest), 64)
            verify_authority.assert_called_once()
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["observation"]["observed_components"] = value["observation"][
                "observed_components"
            ][1:]
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "observed plugin set"):
                native_runtime_closure_sha256(executable, require_plugin_manifest=True)

    @patch("py_security_suite.execution.shutil.which")
    def test_executable_resolution_falls_back_to_interpreter_directory(
        self, which: MagicMock
    ) -> None:
        expected = str(Path(sys.executable).resolve().parent / "scanner")
        which.side_effect = [None, expected]

        self.assertEqual(resolve_executable("scanner"), expected)
        self.assertEqual(which.call_count, 2)
        self.assertEqual(
            which.call_args_list[1].kwargs["path"],
            str(Path(sys.executable).resolve().parent),
        )


if __name__ == "__main__":
    unittest.main()
