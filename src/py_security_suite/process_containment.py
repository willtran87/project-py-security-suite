"""Shared Windows process-tree containment, assigned before launching work."""

from __future__ import annotations

import subprocess


def apply_windows_job_limits(  # pragma: no cover - exercised on Windows CI
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: int,
) -> tuple[tuple[str, ...], tuple[str, ...], int]:
    """Contain a Windows scanner in a kill-on-close, quota-limited Job Object."""
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_ulonglong)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class BASIC_LIMITS(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED_LIMITS(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC_LIMITS),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class CPU_RATE_CONTROL(ctypes.Structure):
        _fields_ = [("ControlFlags", wintypes.DWORD), ("CpuRate", wintypes.DWORD)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        error_code = ctypes.get_last_error()  # type: ignore[attr-defined]
        raise OSError(error_code, "CreateJobObjectW failed")
    limits = EXTENDED_LIMITS()
    limits.BasicLimitInformation.LimitFlags = 0x2000 | 0x200 | 0x100 | 0x8 | 0x4
    limits.BasicLimitInformation.PerJobUserTimeLimit = (
        max(1, timeout_seconds) * 10_000_000
    )
    limits.BasicLimitInformation.ActiveProcessLimit = 256
    limits.ProcessMemoryLimit = 8 * 1024**3
    limits.JobMemoryLimit = 16 * 1024**3
    if not kernel32.SetInformationJobObject(
        job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
    ):
        error = ctypes.get_last_error()  # type: ignore[attr-defined]
        kernel32.CloseHandle(job)
        raise OSError(error, "SetInformationJobObject failed")
    cpu = CPU_RATE_CONTROL(ControlFlags=0x1 | 0x4, CpuRate=8000)
    if not kernel32.SetInformationJobObject(
        job, 15, ctypes.byref(cpu), ctypes.sizeof(cpu)
    ):
        error = ctypes.get_last_error()  # type: ignore[attr-defined]
        kernel32.CloseHandle(job)
        raise OSError(error, "CPU rate control could not be applied")
    process_handle = getattr(process, "_handle", None)
    if not process_handle or not kernel32.AssignProcessToJobObject(job, process_handle):
        error = ctypes.get_last_error()  # type: ignore[attr-defined]
        kernel32.CloseHandle(job)
        raise OSError(error, "AssignProcessToJobObject failed")
    return (
        (
            "kill-on-close",
            "process-count",
            "process-memory",
            "job-memory",
            "cpu-time",
            "cpu-rate",
            "pre-execution-assignment",
        ),
        (),
        int(ctypes.cast(job, ctypes.c_void_p).value or 0),
    )


def close_windows_handle(handle: int) -> None:  # pragma: no cover
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.CloseHandle(handle)
