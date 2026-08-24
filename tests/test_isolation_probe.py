from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.config import IsolationConfig
from py_security_suite.execution import RawExecution
from py_security_suite.isolation_probe import probe_isolation_boundary


class IsolationProbeTests(unittest.TestCase):
    @pytest.mark.enable_socket
    def test_required_probe_records_both_enforced_capabilities(self) -> None:
        execution = RawExecution(
            command=["probe"],
            exit_code=0,
            stdout=(
                '{"tcp4_denied":true,"udp4_denied":true,"tcp6_denied":true,'
                '"host_tcp4_denied":true,"host_udp4_denied":true,'
                '"udp6_denied":true,"unix_socket_denied":true,'
                '"raw_socket_denied":true,"proxy_environment_cleared":true,'
                '"host_interface_tested":true,"unix_socket_tested":true,'
                '"target_root_read_only":true,"target_nested_read_only":true,'
                '"link_creation_denied":true,"private_scratch_writable":true,'
                '"host_secret_read_denied":true,'
                '"credential_environment_cleared":true,'
                '"parent_process_access_denied":true,'
                '"process_namespace_isolated":true,'
                '"host_shared_memory_denied":true,'
                '"device_namespace_isolated":true,'
                '"linux_policy_tested":false,'
                '"linux_no_new_privileges":true,'
                '"linux_capabilities_dropped":true,'
                '"linux_seccomp_mode":-1,'
                '"linux_seccomp_filters":-1,'
                '"windows_policy_tested":false,'
                '"windows_dep_enabled":true,'
                '"windows_aslr_enabled":true,'
                '"windows_dynamic_code_prohibited":true,'
                '"windows_child_processes_prohibited":true}'
            ),
            stderr="",
            duration_seconds=0.1,
            resource_limits_enforced=(
                "cpu-time",
                "bounded-output-pipes",
                "bounded-private-scratch",
            ),
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "py_security_suite.isolation_probe.run_command", return_value=execution
            ),
        ):
            artifact, errors = probe_isolation_boundary(
                Path(directory), IsolationConfig(), required=True
            )
        self.assertEqual(errors, [])
        self.assertTrue(artifact["complete"])
        self.assertTrue(artifact["capabilities"]["network-tcp4-denied"])

    def test_optional_probe_does_not_make_standard_scan_incomplete(self) -> None:
        artifact, errors = probe_isolation_boundary(
            Path.cwd(), IsolationConfig(), required=False
        )
        self.assertEqual(errors, [])
        self.assertFalse(artifact["executed"])
