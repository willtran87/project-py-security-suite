from __future__ import annotations

import hashlib
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
    _process_tree_resident_bytes,
    _terminate_process_tree,
    isolated_environment,
    native_runtime_closure_sha256,
    resolve_executable,
    run_command,
    sealed_governed_assets,
    sanitize_diagnostic,
    sanitize_terminal_text,
    sha256_file,
)


class IsolatedEnvironmentTests(unittest.TestCase):
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
                side_effect=[0.0, 2.0, 2.0],
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
                side_effect=[0.0, 0.0],
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
            patch("py_security_suite.execution.os.name", "nt"),
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
            patch("py_security_suite.execution.os.name", "nt"),
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
