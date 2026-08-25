from __future__ import annotations

import hashlib
from multiprocessing import shared_memory
import os
import socket
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .config import IsolationConfig
from .deployment_receipt import verify_deployment_receipt
from .execution import CommandEnvironment, run_command, sha256_file
from .path_safety import read_regular_file
from .strict_json import canonical_bytes, loads as strict_loads


_PROBE_SOURCE = r"""
import hashlib, json, os, socket, sys, tempfile
from multiprocessing import shared_memory
from pathlib import Path
target = Path(sys.argv[1])
tcp4_port = int(sys.argv[2])
udp4_port = int(sys.argv[3])
tcp6_port = int(sys.argv[4])
name = sys.argv[5]
host4 = sys.argv[6]
host_tcp_port = int(sys.argv[7])
host_udp_port = int(sys.argv[8])
udp6_port = int(sys.argv[9])
unix_path = sys.argv[10]
host_secret = Path(sys.argv[11])
parent_pid = int(sys.argv[12])
shared_memory_name = sys.argv[13]
result = {
    "process_id": os.getpid(), "kernel_identity_sha256": "",
    "tcp4_denied": False, "udp4_denied": False, "tcp6_denied": tcp6_port == 0,
    "host_tcp4_denied": host_tcp_port == 0, "host_udp4_denied": host_udp_port == 0,
    "udp6_denied": udp6_port == 0, "unix_socket_denied": not unix_path,
    "raw_socket_denied": False, "proxy_environment_cleared": False,
    "host_interface_tested": host_tcp_port != 0 and host_udp_port != 0,
    "unix_socket_tested": bool(unix_path),
    "target_root_read_only": False, "target_nested_read_only": False,
    "link_creation_denied": False, "private_scratch_writable": False,
    "host_secret_read_denied": False, "credential_environment_cleared": False,
    "parent_process_access_denied": False, "process_namespace_isolated": False,
    "host_shared_memory_denied": False, "device_namespace_isolated": False,
    "linux_policy_tested": sys.platform.startswith("linux"),
    "linux_no_new_privileges": not sys.platform.startswith("linux"),
    "linux_capabilities_dropped": not sys.platform.startswith("linux"),
    "linux_seccomp_mode": 0 if sys.platform.startswith("linux") else -1,
    "linux_seccomp_filters": 0 if sys.platform.startswith("linux") else -1,
    "windows_policy_tested": os.name == "nt",
    "windows_dep_enabled": os.name != "nt", "windows_aslr_enabled": os.name != "nt",
    "windows_dynamic_code_prohibited": os.name != "nt",
    "windows_child_processes_prohibited": os.name != "nt",
}
kernel_identity = {"pid": os.getpid(), "platform": sys.platform}
if sys.platform.startswith("linux"):
    try:
        kernel_identity.update({
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "pid_namespace_inode": os.stat("/proc/self/ns/pid").st_ino,
            "cgroup": Path("/proc/self/cgroup").read_text().strip(),
        })
    except OSError:
        pass
result["kernel_identity_sha256"] = hashlib.sha256(
    json.dumps(kernel_identity, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
try:
    host_secret.read_bytes()
except OSError:
    result["host_secret_read_denied"] = True
result["credential_environment_cleared"] = not any(
    key.upper() in {"AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET", "GITHUB_TOKEN", "SSH_AUTH_SOCK"}
    for key in os.environ
)
try:
    os.kill(parent_pid, 0)
except OSError:
    result["parent_process_access_denied"] = True
if sys.platform.startswith("linux"):
    try:
        status = {}
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                status[key] = value.strip()
        result["linux_no_new_privileges"] = status.get("NoNewPrivs") == "1"
        result["linux_capabilities_dropped"] = int(status.get("CapEff", "1"), 16) == 0
        result["linux_seccomp_mode"] = int(status.get("Seccomp", "0"))
        result["linux_seccomp_filters"] = int(status.get("Seccomp_filters", "0"))
        visible = {int(item.name) for item in Path("/proc").iterdir() if item.name.isdigit()}
        result["process_namespace_isolated"] = parent_pid not in visible
    except (OSError, ValueError):
        pass
else:
    result["process_namespace_isolated"] = result["parent_process_access_denied"]
if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.GetProcessMitigationPolicy.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        kernel32.GetProcessMitigationPolicy.restype = ctypes.c_int
        def mitigation(policy):
            flags = ctypes.c_ulong(0)
            if not kernel32.GetProcessMitigationPolicy(kernel32.GetCurrentProcess(), policy, ctypes.byref(flags), ctypes.sizeof(flags)):
                raise OSError(ctypes.get_last_error())
            return flags.value
        result["windows_dep_enabled"] = bool(mitigation(0) & 1)
        result["windows_aslr_enabled"] = bool(mitigation(1) & 0x7)
        result["windows_dynamic_code_prohibited"] = bool(mitigation(2) & 1)
        result["windows_child_processes_prohibited"] = bool(mitigation(13) & 1)
    except (AttributeError, OSError):
        pass
try:
    shared = shared_memory.SharedMemory(name=shared_memory_name, create=False)
    shared.close()
except (FileNotFoundError, PermissionError, OSError):
    result["host_shared_memory_denied"] = True
if os.name == "nt":
    try:
        handle = open(r"\\.\PhysicalDrive0", "rb")
        handle.close()
    except OSError:
        result["device_namespace_isolated"] = True
else:
    safe_devices = {"null", "zero", "full", "random", "urandom", "tty", "ptmx", "fd", "stdin", "stdout", "stderr", "core"}
    try:
        visible_devices = set(os.listdir("/dev"))
        result["device_namespace_isolated"] = not bool(visible_devices - safe_devices - {"pts", "shm"})
    except OSError:
        result["device_namespace_isolated"] = True
try:
    connection = socket.create_connection(("127.0.0.1", tcp4_port), timeout=1.0)
    connection.close()
except OSError:
    result["tcp4_denied"] = True
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    udp.connect(("127.0.0.1", udp4_port))
    udp.send(b"pysec-isolation-canary")
except OSError:
    result["udp4_denied"] = True
finally:
    udp.close()
if tcp6_port:
    try:
        connection = socket.create_connection(("::1", tcp6_port), timeout=1.0)
        connection.close()
    except OSError:
        result["tcp6_denied"] = True
if host_tcp_port:
    try:
        connection = socket.create_connection((host4, host_tcp_port), timeout=1.0)
        connection.close()
    except OSError:
        result["host_tcp4_denied"] = True
if host_udp_port:
    host_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        host_udp.connect((host4, host_udp_port))
        host_udp.send(b"pysec-host-egress-canary")
    except OSError:
        result["host_udp4_denied"] = True
    finally:
        host_udp.close()
if udp6_port:
    udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        udp6.connect(("::1", udp6_port))
        udp6.send(b"pysec-ipv6-udp-canary")
    except OSError:
        result["udp6_denied"] = True
    finally:
        udp6.close()
if unix_path:
    unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        unix_socket.connect(unix_path)
    except OSError:
        result["unix_socket_denied"] = True
    finally:
        unix_socket.close()
try:
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    raw.close()
except OSError:
    result["raw_socket_denied"] = True
result["proxy_environment_cleared"] = not any(
    name.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
    for name in os.environ
)
directories = [target]
for candidate in sorted(target.iterdir()):
    if candidate.is_dir() and not candidate.is_symlink():
        directories.append(candidate)
        break
for index, directory in enumerate(directories):
    canary = directory / (name + f"-{index}")
    descriptor = None
    try:
        descriptor = os.open(canary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(descriptor, b"isolation-canary")
    except OSError:
        result["target_root_read_only" if index == 0 else "target_nested_read_only"] = True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            canary.unlink()
        except OSError:
            pass
if len(directories) == 1:
    result["target_nested_read_only"] = result["target_root_read_only"]
link = target / (name + "-link")
try:
    link.symlink_to(target / name)
except OSError:
    result["link_creation_denied"] = True
finally:
    try:
        link.unlink()
    except OSError:
        pass
scratch = Path(tempfile.gettempdir()) / (name + "-scratch")
try:
    scratch.write_bytes(b"writable-private-output")
    result["private_scratch_writable"] = scratch.read_bytes() == b"writable-private-output"
finally:
    try:
        scratch.unlink()
    except OSError:
        pass
print(json.dumps(result, sort_keys=True))
""".strip()


def probe_isolation_boundary(
    target: Path,
    config: IsolationConfig,
    *,
    required: bool,
) -> tuple[dict[str, Any], list[str]]:
    """Actively test egress denial and target immutability inside the scan boundary."""
    subject = {
        "schema_version": "1.0",
        "analysis": "active-isolation-capability-canaries",
        "required": required,
    }
    if not required:
        return {
            **subject,
            "executed": False,
            "complete": True,
            "capabilities": {},
            "policy_observations": {},
        }, []
    tcp4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp4.bind(("127.0.0.1", 0))
    tcp4.listen(1)
    udp4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp4.bind(("127.0.0.1", 0))
    tcp6: socket.socket | None = None
    udp6: socket.socket | None = None
    host_tcp: socket.socket | None = None
    host_udp: socket.socket | None = None
    unix_listener: socket.socket | None = None
    unix_path = ""
    try:
        tcp6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        tcp6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp6.bind(("::1", 0))
        tcp6.listen(1)
    except OSError:
        if tcp6 is not None:
            tcp6.close()
        tcp6 = None
    try:
        udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        udp6.bind(("::1", 0))
    except OSError:
        if udp6 is not None:
            udp6.close()
        udp6 = None
    host4 = ""
    for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
        candidate = item[4][0]
        if isinstance(candidate, str) and not candidate.startswith("127."):
            host4 = candidate
            break
    if host4:
        try:
            host_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            host_tcp.bind((host4, 0))
            host_tcp.listen(1)
            host_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            host_udp.bind((host4, 0))
        except OSError:
            if host_tcp is not None:
                host_tcp.close()
            if host_udp is not None:
                host_udp.close()
            host_tcp = None
            host_udp = None
    if hasattr(socket, "AF_UNIX"):
        unix_path = str(
            Path(tempfile.gettempdir()) / f"pysec-probe-{uuid.uuid4().hex}.sock"
        )
        try:
            unix_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            unix_listener.bind(unix_path)
            unix_listener.listen(1)
        except OSError:
            if unix_listener is not None:
                unix_listener.close()
            unix_listener = None
            unix_path = ""
    secret_parent = Path(tempfile.mkdtemp(prefix="pysec-host-secret-"))
    host_secret = secret_parent / "credential-canary"
    host_secret.write_bytes(os.urandom(32))
    shared_canary = shared_memory.SharedMemory(create=True, size=32)
    shared_buffer = shared_canary.buf
    if shared_buffer is None:
        shared_canary.close()
        try:
            shared_canary.unlink()
        except FileNotFoundError:
            pass
        raise RuntimeError("shared-memory isolation canary is unavailable")
    shared_buffer[:32] = os.urandom(32)
    environment = CommandEnvironment()
    if config.sandbox_executable:
        environment.sandbox_prefix = (
            config.sandbox_executable,
            *(
                argument.replace("{PYSEC_PROBE_SECRET_PARENT}", str(secret_parent))
                for argument in config.sandbox_arguments
            ),
        )
        environment.sandbox_executable_sha256 = config.sandbox_executable_sha256
        environment.sandbox_runtime_closure_sha256 = (
            config.sandbox_runtime_closure_sha256
        )
    canary_name = f".pysec-isolation-canary-{uuid.uuid4().hex}"
    try:
        execution = run_command(
            [
                sys.executable,
                "-I",
                "-c",
                _PROBE_SOURCE,
                str(target),
                str(int(tcp4.getsockname()[1])),
                str(int(udp4.getsockname()[1])),
                str(int(tcp6.getsockname()[1]) if tcp6 is not None else 0),
                canary_name,
                host4,
                str(int(host_tcp.getsockname()[1]) if host_tcp is not None else 0),
                str(int(host_udp.getsockname()[1]) if host_udp is not None else 0),
                str(int(udp6.getsockname()[1]) if udp6 is not None else 0),
                unix_path,
                str(host_secret),
                str(os.getpid()),
                shared_canary.name,
            ],
            cwd=target,
            timeout_seconds=15,
            max_output_bytes=4096,
            environment=environment,
        )
    finally:
        tcp4.close()
        udp4.close()
        if tcp6 is not None:
            tcp6.close()
        if udp6 is not None:
            udp6.close()
        if host_tcp is not None:
            host_tcp.close()
        if host_udp is not None:
            host_udp.close()
        if unix_listener is not None:
            unix_listener.close()
        if unix_path:
            try:
                Path(unix_path).unlink()
            except OSError:
                pass
        try:
            host_secret.unlink()
            secret_parent.rmdir()
        except OSError:
            pass
        shared_canary.close()
        shared_canary.unlink()
        for canary in target.rglob(canary_name + "*"):
            if not canary.is_symlink():
                try:
                    canary.unlink()
                except OSError:
                    pass
    capabilities: dict[str, bool] = {}
    parse_error = ""
    try:
        value = strict_loads(execution.stdout)
        expected = {
            "process_id",
            "kernel_identity_sha256",
            "tcp4_denied",
            "udp4_denied",
            "tcp6_denied",
            "host_tcp4_denied",
            "host_udp4_denied",
            "udp6_denied",
            "unix_socket_denied",
            "raw_socket_denied",
            "proxy_environment_cleared",
            "host_interface_tested",
            "unix_socket_tested",
            "target_root_read_only",
            "target_nested_read_only",
            "link_creation_denied",
            "private_scratch_writable",
            "host_secret_read_denied",
            "credential_environment_cleared",
            "parent_process_access_denied",
            "process_namespace_isolated",
            "host_shared_memory_denied",
            "device_namespace_isolated",
            "linux_policy_tested",
            "linux_no_new_privileges",
            "linux_capabilities_dropped",
            "linux_seccomp_mode",
            "linux_seccomp_filters",
            "windows_policy_tested",
            "windows_dep_enabled",
            "windows_aslr_enabled",
            "windows_dynamic_code_prohibited",
            "windows_child_processes_prohibited",
        }
        if (
            not isinstance(value, dict)
            or set(value) != expected
            or isinstance(value.get("process_id"), bool)
            or not isinstance(value.get("process_id"), int)
            or value["process_id"] < 1
            or len(str(value.get("kernel_identity_sha256") or "")) != 64
            or any(
                character not in "0123456789abcdef"
                for character in str(value.get("kernel_identity_sha256") or "")
            )
        ):
            raise ValueError("probe output fields do not match")
        capabilities = {
            "network-tcp4-denied": value["tcp4_denied"] is True,
            "network-udp4-denied": value["udp4_denied"] is True,
            "network-tcp6-denied": value["tcp6_denied"] is True,
            "network-host-tcp4-denied": value["host_tcp4_denied"] is True,
            "network-host-udp4-denied": value["host_udp4_denied"] is True,
            "network-udp6-denied": value["udp6_denied"] is True,
            "network-unix-socket-denied": value["unix_socket_denied"] is True,
            "network-raw-socket-denied": value["raw_socket_denied"] is True,
            "proxy-environment-cleared": value["proxy_environment_cleared"] is True,
            "network-host-interface-tested": value["host_interface_tested"] is True,
            "network-unix-socket-tested": value["unix_socket_tested"] is True,
            "target-root-read-only": value["target_root_read_only"] is True,
            "target-nested-read-only": value["target_nested_read_only"] is True,
            "target-link-creation-denied": value["link_creation_denied"] is True,
            "private-scratch-writable": value["private_scratch_writable"] is True,
            "host-filesystem-read-denied": value["host_secret_read_denied"] is True,
            "credential-environment-cleared": value["credential_environment_cleared"]
            is True,
            "parent-process-access-denied": value["parent_process_access_denied"]
            is True,
            "process-namespace-isolated": value["process_namespace_isolated"] is True,
            "device-namespace-isolated": value["device_namespace_isolated"] is True,
            "host-ipc-denied": value["host_shared_memory_denied"] is True,
            "bounded-output-pipes": "bounded-output-pipes"
            in execution.resource_limits_enforced,
            "bounded-private-scratch": "bounded-private-scratch"
            in execution.resource_limits_enforced,
        }
    except (TypeError, ValueError) as exc:
        parse_error = str(exc)
    policy_observations = (
        {
            "platform": "linux",
            "process_id": value["process_id"],
            "kernel_identity_sha256": value["kernel_identity_sha256"],
            "no_new_privileges": value["linux_no_new_privileges"] is True,
            "capabilities_dropped": value["linux_capabilities_dropped"] is True,
            "seccomp_mode": value["linux_seccomp_mode"],
            "seccomp_active": value["linux_seccomp_mode"] in {1, 2},
            "seccomp_filters": value["linux_seccomp_filters"],
            "seccomp_policy_sha256": os.environ.get("PYSEC_SECCOMP_POLICY_SHA256", "")
            .strip()
            .casefold(),
        }
        if isinstance(locals().get("value"), dict)
        and value.get("linux_policy_tested") is True
        else {
            "platform": "windows",
            "process_id": value["process_id"],
            "kernel_identity_sha256": value["kernel_identity_sha256"],
            "dep_enabled": value["windows_dep_enabled"] is True,
            "aslr_enabled": value["windows_aslr_enabled"] is True,
            "dynamic_code_prohibited": value["windows_dynamic_code_prohibited"] is True,
            "child_processes_prohibited": value["windows_child_processes_prohibited"]
            is True,
        }
        if isinstance(locals().get("value"), dict)
        and value.get("windows_policy_tested") is True
        else {
            "platform": "macos",
            "process_id": value["process_id"],
            "kernel_identity_sha256": value["kernel_identity_sha256"],
            "sandbox_profile_sha256": hashlib.sha256(
                canonical_bytes(
                    {
                        "sandbox_executable_sha256": config.sandbox_executable_sha256,
                        "sandbox_runtime_closure_sha256": config.sandbox_runtime_closure_sha256,
                        "sandbox_arguments": list(config.sandbox_arguments),
                    }
                )
            ).hexdigest()
            if config.sandbox_executable_sha256
            and config.sandbox_runtime_closure_sha256
            and config.sandbox_arguments
            else "",
        }
        if sys.platform == "darwin"
        else {
            "platform": "windows" if sys.platform == "win32" else sys.platform,
            "policy_introspection_available": False,
        }
    )
    if policy_observations.get("platform") == "linux":
        if policy_observations.get("policy_introspection_available") is False:
            capabilities.update(
                {
                    "linux-no-new-privileges": False,
                    "linux-capabilities-dropped": False,
                    "linux-seccomp-filter-enforced": False,
                    "linux-seccomp-policy-bound": False,
                }
            )
        else:
            seccomp_filters = policy_observations.get("seccomp_filters")
            capabilities["linux-no-new-privileges"] = (
                policy_observations.get("no_new_privileges") is True
            )
            capabilities["linux-capabilities-dropped"] = (
                policy_observations.get("capabilities_dropped") is True
            )
            capabilities["linux-seccomp-filter-enforced"] = (
                policy_observations.get("seccomp_mode") == 2
                and isinstance(seccomp_filters, int)
                and not isinstance(seccomp_filters, bool)
                and seccomp_filters >= 1
            )
            seccomp_policy = str(policy_observations.get("seccomp_policy_sha256") or "")
            capabilities["linux-seccomp-policy-bound"] = len(
                seccomp_policy
            ) == 64 and all(
                character in "0123456789abcdef" for character in seccomp_policy
            )
    elif policy_observations.get("platform") == "windows":
        introspected = (
            policy_observations.get("policy_introspection_available") is not False
        )
        capabilities["windows-dep-enabled"] = (
            introspected and policy_observations.get("dep_enabled") is True
        )
        capabilities["windows-aslr-enabled"] = (
            introspected and policy_observations.get("aslr_enabled") is True
        )
        capabilities["windows-dynamic-code-prohibited"] = (
            introspected and policy_observations.get("dynamic_code_prohibited") is True
        )
        capabilities["windows-child-processes-prohibited"] = (
            introspected
            and policy_observations.get("child_processes_prohibited") is True
        )
    elif policy_observations.get("platform") == "macos":
        capabilities["macos-sandbox-profile-bound"] = (
            len(str(policy_observations["sandbox_profile_sha256"])) == 64
        )
    if policy_observations.get("platform") in {"linux", "macos"} and (
        policy_observations.get("policy_introspection_available") is not False
    ):
        attestation_sha, attestation, authority = _effective_policy_attestation(
            policy_observations
        )
        policy_observations["effective_policy_attestation_sha256"] = attestation_sha
        policy_observations["effective_policy_attestation"] = attestation
        policy_observations["effective_policy_authority_receipt"] = authority
        capabilities["effective-kernel-policy-attested"] = bool(attestation_sha)
    complete = (
        execution.exit_code == 0
        and not execution.timed_out
        and not execution.output_limit_exceeded
        and not execution.scratch_limit_exceeded
        and not execution.resident_memory_limit_exceeded
        and capabilities
        and all(capabilities.values())
    )
    artifact = {
        **subject,
        "executed": True,
        "complete": bool(complete),
        "capabilities": capabilities,
        "policy_observations": policy_observations,
        "exit_code": execution.exit_code,
        "timed_out": execution.timed_out,
        "output_limit_exceeded": execution.output_limit_exceeded,
        "scratch_limit_exceeded": execution.scratch_limit_exceeded,
        "resident_memory_limit_exceeded": execution.resident_memory_limit_exceeded,
        "resource_limits_enforced": list(execution.resource_limits_enforced),
        "resource_limit_errors": list(execution.resource_limit_errors),
        "probe_sha256": hashlib.sha256(_PROBE_SOURCE.encode()).hexdigest(),
        "interpreter_sha256": sha256_file(Path(sys.executable).resolve()),
        "sandbox_executable_sha256": config.sandbox_executable_sha256 or None,
        "result_sha256": hashlib.sha256(canonical_bytes(capabilities)).hexdigest(),
        "error": parse_error or None,
    }
    errors = (
        []
        if complete
        else [
            "active isolation canaries did not prove protocol egress denial, process/IPC separation, host read confidentiality, credential clearing, target immutability, platform policy, and bounded writable scratch"
        ]
    )
    return artifact, errors


def _effective_policy_attestation(
    observations: dict[str, Any],
) -> tuple[str, dict[str, Any] | None, dict[str, Any] | None]:
    raw_path = os.environ.get("PYSEC_EFFECTIVE_SANDBOX_ATTESTATION_PATH", "").strip()
    expected = (
        os.environ.get("PYSEC_EFFECTIVE_SANDBOX_ATTESTATION_SHA256", "")
        .strip()
        .casefold()
    )
    if not raw_path and not expected:
        return "", None, None
    if (
        not raw_path
        or len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
    ):
        raise ValueError("effective sandbox attestation configuration is incomplete")
    path = Path(raw_path).expanduser().resolve()
    _, payload = read_regular_file(
        path, "effective sandbox policy attestation", maximum_bytes=1024 * 1024
    )
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError(
            "effective sandbox attestation does not match its deployment pin"
        )
    value = strict_loads(payload)
    fields = {
        "schema_version",
        "platform",
        "policy_sha256",
        "effective_identity",
        "observations_sha256",
        "attestor",
        "process_id",
        "kernel_identity_sha256",
    }
    policy_sha256 = str(
        observations.get("seccomp_policy_sha256")
        or observations.get("sandbox_profile_sha256")
        or ""
    )
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schema_version") != "1.0"
        or value.get("platform") != observations.get("platform")
        or value.get("policy_sha256") != policy_sha256
        or value.get("observations_sha256")
        != hashlib.sha256(canonical_bytes(observations)).hexdigest()
        or value.get("process_id") != observations.get("process_id")
        or value.get("kernel_identity_sha256")
        != observations.get("kernel_identity_sha256")
        or not str(value.get("effective_identity") or "").strip()
        or not str(value.get("attestor") or "").strip()
    ):
        raise ValueError("effective sandbox attestation policy is invalid")
    authority = verify_deployment_receipt(
        value,
        purpose="effective-sandbox-policy",
        environment_prefix="PYSEC_EFFECTIVE_SANDBOX_AUTHORITY",
    )
    return expected, value, authority
