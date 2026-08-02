from __future__ import annotations

import os
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from py_security_suite.execution import (
    CommandEnvironment,
    isolated_environment,
    run_command,
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
        completed = SimpleNamespace(
            returncode=0,
            stdout=b"",
            stderr=b"",
        )
        with patch(
            "py_security_suite.execution.subprocess.run",
            return_value=completed,
        ) as mocked_run:
            run_command(
                ["scanner"],
                cwd=Path.cwd(),
                timeout_seconds=10,
                max_output_bytes=1024,
                environment=CommandEnvironment(),
            )

        environment = mocked_run.call_args.kwargs["env"]
        private_home = Path(environment["HOME"])
        self.assertEqual(environment["USERPROFILE"], str(private_home))
        self.assertEqual(
            environment["LOCALAPPDATA"],
            str(private_home / "AppData" / "Local"),
        )
        self.assertFalse(private_home.exists())


if __name__ == "__main__":
    unittest.main()
