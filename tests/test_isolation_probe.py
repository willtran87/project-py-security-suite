from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.config import IsolationConfig
from py_security_suite.execution import RawExecution
from py_security_suite.isolation_probe import (
    _apply_platform_policy_capabilities,
    _host_ipv4_address,
    _platform_policy_observations,
    probe_isolation_boundary,
)


class IsolationProbeTests(unittest.TestCase):
    def test_linux_policy_interpretation_requires_bound_seccomp_controls(self) -> None:
        parsed: dict[str, object] = {
            "process_id": 123,
            "kernel_identity_sha256": "a" * 64,
            "linux_policy_tested": True,
            "linux_no_new_privileges": True,
            "linux_capabilities_dropped": True,
            "linux_seccomp_mode": 2,
            "linux_seccomp_filters": 1,
        }
        with patch.dict(
            "py_security_suite.isolation_probe.os.environ",
            {"PYSEC_SECCOMP_POLICY_SHA256": "b" * 64},
            clear=False,
        ):
            observations = _platform_policy_observations(
                parsed, IsolationConfig(), "linux"
            )
        capabilities: dict[str, bool] = {}
        _apply_platform_policy_capabilities(capabilities, observations)

        self.assertTrue(all(capabilities.values()))
        self.assertEqual(observations["seccomp_mode"], 2)

    def test_macos_policy_interpretation_binds_the_complete_launcher_contract(
        self,
    ) -> None:
        parsed: dict[str, object] = {
            "process_id": 123,
            "kernel_identity_sha256": "a" * 64,
            "linux_policy_tested": False,
            "windows_policy_tested": False,
        }
        config = IsolationConfig(
            sandbox_executable="sandbox-exec",
            sandbox_executable_sha256="b" * 64,
            sandbox_runtime_closure_sha256="c" * 64,
            sandbox_arguments=("-f", "profile.sb"),
        )
        observations = _platform_policy_observations(parsed, config, "darwin")
        capabilities: dict[str, bool] = {}
        _apply_platform_policy_capabilities(capabilities, observations)

        self.assertEqual(observations["platform"], "macos")
        self.assertEqual(len(str(observations["sandbox_profile_sha256"])), 64)
        self.assertTrue(capabilities["macos-sandbox-profile-bound"])

    def test_host_interface_selection_rejects_unsafe_ipv4_addresses(self) -> None:
        addresses = [
            (2, 1, 6, "", ("0.0.0.0", 0)),  # noqa: S104 - rejection fixture
            (2, 1, 6, "", ("127.0.0.1", 0)),
            (2, 1, 6, "", ("169.254.4.5", 0)),
            (2, 1, 6, "", ("224.0.0.1", 0)),
            (2, 1, 6, "", ("192.0.2.8", 0)),
        ]
        with patch(
            "py_security_suite.isolation_probe.socket.getaddrinfo",
            return_value=addresses,
        ):
            self.assertEqual(_host_ipv4_address(), "192.0.2.8")

        with patch(
            "py_security_suite.isolation_probe.socket.getaddrinfo",
            return_value=addresses[:-1],
        ):
            self.assertIsNone(_host_ipv4_address())

    @pytest.mark.enable_socket
    def test_required_probe_records_both_enforced_capabilities(self) -> None:
        execution = RawExecution(
            command=["probe"],
            exit_code=0,
            stdout=(
                '{"process_id":123,"kernel_identity_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
                '"tcp4_denied":true,"udp4_denied":true,"tcp6_denied":true,'
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
            patch("py_security_suite.isolation_probe.sys.platform", "test"),
        ):
            artifact, errors = probe_isolation_boundary(
                Path(directory), IsolationConfig(), required=True
            )
        self.assertEqual(errors, [])
        self.assertTrue(artifact["complete"])
        self.assertTrue(artifact["capabilities"]["network-tcp4-denied"])

    @pytest.mark.enable_socket
    def test_required_probe_fails_closed_without_linux_policy_introspection(
        self,
    ) -> None:
        execution = RawExecution(
            command=["probe"],
            exit_code=0,
            stdout=(
                '{"process_id":123,"kernel_identity_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
                '"tcp4_denied":true,"udp4_denied":true,"tcp6_denied":true,'
                '"host_tcp4_denied":true,"host_udp4_denied":true,'
                '"udp6_denied":true,"unix_socket_denied":true,'
                '"raw_socket_denied":true,"proxy_environment_cleared":true,'
                '"host_interface_tested":true,"unix_socket_tested":true,'
                '"target_root_read_only":true,"target_nested_read_only":true,'
                '"link_creation_denied":true,"private_scratch_writable":true,'
                '"host_secret_read_denied":true,"credential_environment_cleared":true,'
                '"parent_process_access_denied":true,"process_namespace_isolated":true,'
                '"host_shared_memory_denied":true,"device_namespace_isolated":true,'
                '"linux_policy_tested":false,"linux_no_new_privileges":true,'
                '"linux_capabilities_dropped":true,"linux_seccomp_mode":-1,'
                '"linux_seccomp_filters":-1,"windows_policy_tested":false,'
                '"windows_dep_enabled":true,"windows_aslr_enabled":true,'
                '"windows_dynamic_code_prohibited":true,'
                '"windows_child_processes_prohibited":true}'
            ),
            stderr="",
            duration_seconds=0.1,
            resource_limits_enforced=(
                "bounded-output-pipes",
                "bounded-private-scratch",
            ),
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "py_security_suite.isolation_probe.run_command", return_value=execution
            ),
            patch("py_security_suite.isolation_probe.sys.platform", "linux"),
        ):
            artifact, errors = probe_isolation_boundary(
                Path(directory), IsolationConfig(), required=True
            )

        self.assertFalse(artifact["complete"])
        self.assertNotEqual(errors, [])
        self.assertFalse(artifact["capabilities"]["linux-no-new-privileges"])

    @pytest.mark.enable_socket
    def test_malformed_probe_output_fails_closed_before_policy_interpretation(
        self,
    ) -> None:
        execution = RawExecution(
            command=["probe"],
            exit_code=0,
            stdout="not-json",
            stderr="",
            duration_seconds=0.1,
            resource_limits_enforced=(
                "bounded-output-pipes",
                "bounded-private-scratch",
            ),
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "py_security_suite.isolation_probe.run_command", return_value=execution
            ),
            patch("py_security_suite.isolation_probe.sys.platform", "darwin"),
        ):
            artifact, errors = probe_isolation_boundary(
                Path(directory), IsolationConfig(), required=True
            )

        self.assertFalse(artifact["complete"])
        self.assertNotEqual(errors, [])
        self.assertEqual(
            artifact["policy_observations"],
            {"platform": "macos", "policy_introspection_available": False},
        )
        self.assertEqual(
            artifact["capabilities"], {"macos-sandbox-profile-bound": False}
        )
        self.assertIsInstance(artifact["error"], str)

    def test_optional_probe_does_not_make_standard_scan_incomplete(self) -> None:
        artifact, errors = probe_isolation_boundary(
            Path.cwd(), IsolationConfig(), required=False
        )
        self.assertEqual(errors, [])
        self.assertFalse(artifact["executed"])
