from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.integration


def _oci_configuration() -> tuple[Path, str]:
    runtime_value = os.environ.get("PYSEC_TEST_OCI_RUNTIME", "").strip()
    image = os.environ.get("PYSEC_TEST_OCI_IMAGE", "").strip()
    if not runtime_value or not image:
        pytest.skip("set PYSEC_TEST_OCI_RUNTIME and PYSEC_TEST_OCI_IMAGE")
    runtime = Path(runtime_value).expanduser().resolve()
    if not runtime.is_file() or "@sha256:" not in image:
        pytest.fail("live OCI test requires a runtime file and digest-pinned image")
    return runtime, image


def test_live_oci_runtime_enforces_core_containment_controls() -> None:
    runtime, image = _oci_configuration()
    script = """
set -eu
[ "$(id -u)" != "0" ]
[ "$(awk '/CapEff/ {print $2}' /proc/self/status)" = "0000000000000000" ]
if touch /pysec-root-write 2>/dev/null; then exit 31; fi
[ "$(wc -l < /proc/net/route)" -le 1 ]
command -v wget >/dev/null
if wget -T 2 -qO /tmp/ipv4-egress http://1.1.1.1 2>/dev/null; then exit 32; fi
if wget -T 2 -qO /tmp/dns-egress http://example.com 2>/dev/null; then exit 33; fi
printf '#!/bin/sh\nexit 0\n' > /tmp/noexec-canary
chmod 700 /tmp/noexec-canary
if /tmp/noexec-canary 2>/dev/null; then exit 34; fi
if touch /sys/pysec-write 2>/dev/null; then exit 35; fi
if printf pysec > /proc/sys/kernel/hostname 2>/dev/null; then exit 36; fi
[ ! -e /dev/sda ]
touch /tmp/allowed
""".strip()
    completed = subprocess.run(  # noqa: S603 - explicit opt-in runtime path
        [
            str(runtime),
            "run",
            "--rm",
            "--pull=never",
            "--log-driver=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--network=none",
            "--pids-limit=32",
            "--memory=64m",
            "--cpus=0.25",
            "--user=65532:65532",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=8m",
            image,
            "/bin/sh",
            "-ec",
            script,
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
