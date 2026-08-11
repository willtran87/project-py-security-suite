from __future__ import annotations

import hashlib
import os
import signal
import subprocess  # nosec B404 - subprocess behavior is the test subject
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from py_security_suite.execution import (
    CommandEnvironment,
    _terminate_process_tree,
    isolated_environment,
    resolve_executable,
    run_command,
    sanitize_diagnostic,
    sanitize_terminal_text,
    sha256_file,
)


class IsolatedEnvironmentTests(unittest.TestCase):
    def test_file_sha256_is_streamed_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scanner"
            path.write_bytes(b"approved scanner entry point")
            self.assertEqual(
                sha256_file(path),
                hashlib.sha256(b"approved scanner entry point").hexdigest(),
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

    def test_scanner_process_receives_disposable_private_home(self) -> None:
        process = MagicMock()
        process.communicate.return_value = (b"", b"")
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
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(["scanner"], 1),
            (b"stdout", b"stderr"),
        ]
        with (
            patch(
                "py_security_suite.execution.subprocess.Popen",
                return_value=process,
            ),
            patch(
                "py_security_suite.execution._terminate_process_tree",
                return_value=True,
            ) as terminate,
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
        self.assertEqual(result.stdout, "stdo")
        self.assertEqual(result.stderr, "stde")
        self.assertTrue(result.stdout_truncated)
        self.assertTrue(result.stderr_truncated)

    def test_interrupt_terminates_process_tree_before_propagating(self) -> None:
        process = MagicMock()
        process.communicate.side_effect = [KeyboardInterrupt(), (b"", b"")]
        with (
            patch(
                "py_security_suite.execution.subprocess.Popen",
                return_value=process,
            ),
            patch(
                "py_security_suite.execution._terminate_process_tree",
                return_value=True,
            ) as terminate,
            self.assertRaises(KeyboardInterrupt),
        ):
            run_command(
                ["scanner"],
                cwd=Path.cwd(),
                timeout_seconds=10,
                max_output_bytes=1024,
            )

        terminate.assert_called_once_with(process)

    def test_windows_process_tree_uses_resolved_taskkill_and_fallback(self) -> None:
        process = MagicMock()
        process.pid = 42
        process.poll.side_effect = [None, None, 0]
        completed = MagicMock(returncode=1)
        with (
            patch("py_security_suite.execution.os.name", "nt"),
            patch(
                "py_security_suite.execution.resolve_executable",
                return_value="C:/Windows/System32/taskkill.exe",
            ),
            patch(
                "py_security_suite.execution.subprocess.run",
                return_value=completed,
            ) as taskkill,
        ):
            self.assertTrue(_terminate_process_tree(process))

        self.assertEqual(
            taskkill.call_args.args[0][0], "C:/Windows/System32/taskkill.exe"
        )
        process.kill.assert_called_once()

    def test_windows_process_tree_falls_back_when_taskkill_is_missing(self) -> None:
        process = MagicMock()
        process.poll.side_effect = [None, 0]
        with (
            patch("py_security_suite.execution.os.name", "nt"),
            patch("py_security_suite.execution.resolve_executable", return_value=None),
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
