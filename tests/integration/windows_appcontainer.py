from __future__ import annotations

import ctypes
import subprocess
import uuid
from ctypes import wintypes
from dataclasses import dataclass


PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NO_WINDOW = 0x08000000
STARTF_USESTDHANDLES = 0x00000100
INFINITE = 0xFFFFFFFF
TOKEN_QUERY = 0x0008
TOKEN_IS_APPCONTAINER = 29
TOKEN_CAPABILITIES = 30


@dataclass(frozen=True, slots=True)
class AppContainerExecution:
    exit_code: int
    token_is_appcontainer: bool
    capability_count: int


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", ctypes.c_void_p),
        ("Capabilities", ctypes.c_void_p),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


def run_in_empty_appcontainer(command: list[str]) -> int:
    """Launch a process with an AppContainer SID and no network capabilities."""
    return run_in_empty_appcontainer_verified(command).exit_code


def run_in_empty_appcontainer_verified(command: list[str]) -> AppContainerExecution:
    """Launch and independently inspect the restricted child access token."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    sid = ctypes.c_void_p()
    profile_name = f"PySec.{uuid.uuid4().hex}"
    create_profile = userenv.CreateAppContainerProfile
    create_profile.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    create_profile.restype = ctypes.c_long
    profile_result = create_profile(
        profile_name,
        "Project Py Security Suite Integration",
        "Ephemeral AppContainer isolation qualification",
        None,
        0,
        ctypes.byref(sid),
    )
    derive = userenv.DeriveAppContainerSidFromAppContainerName
    derive.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    derive.restype = ctypes.c_long
    if profile_result != 0:
        sid = ctypes.c_void_p()
        result = derive(profile_name, ctypes.byref(sid))
        if result != 0:
            raise OSError(result, "DeriveAppContainerSidFromAppContainerName failed")

    size = ctypes.c_size_t()
    initialize = kernel32.InitializeProcThreadAttributeList
    initialize.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    initialize.restype = wintypes.BOOL
    initialize(None, 1, 0, ctypes.byref(size))
    storage = ctypes.create_string_buffer(size.value)
    attribute_list = ctypes.cast(storage, ctypes.c_void_p)
    if not initialize(attribute_list, 1, 0, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    capabilities = SECURITY_CAPABILITIES(sid, None, 0, 0)
    update = kernel32.UpdateProcThreadAttribute
    update.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    update.restype = wintypes.BOOL
    if not update(
        attribute_list,
        0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        ctypes.byref(capabilities),
        ctypes.sizeof(capabilities),
        None,
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    startup = STARTUPINFOEXW()
    startup.StartupInfo.cb = ctypes.sizeof(startup)
    startup.lpAttributeList = attribute_list
    process = PROCESS_INFORMATION()
    command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
    create = kernel32.CreateProcessW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOEXW),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    create.restype = wintypes.BOOL
    try:
        if not create(
            command[0],
            command_line,
            None,
            None,
            False,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            None,
            None,
            ctypes.byref(startup),
            ctypes.byref(process),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        token = wintypes.HANDLE()
        open_token = advapi32.OpenProcessToken
        open_token.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        open_token.restype = wintypes.BOOL
        if not open_token(process.hProcess, TOKEN_QUERY, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            is_appcontainer = wintypes.DWORD()
            returned = wintypes.DWORD()
            get_token = advapi32.GetTokenInformation
            get_token.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            get_token.restype = wintypes.BOOL
            if not get_token(
                token,
                TOKEN_IS_APPCONTAINER,
                ctypes.byref(is_appcontainer),
                ctypes.sizeof(is_appcontainer),
                ctypes.byref(returned),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            required = wintypes.DWORD()
            get_token(token, TOKEN_CAPABILITIES, None, 0, ctypes.byref(required))
            if required.value < ctypes.sizeof(wintypes.DWORD):
                raise OSError(
                    "AppContainer token capability information is unavailable"
                )
            capability_storage = ctypes.create_string_buffer(required.value)
            if not get_token(
                token,
                TOKEN_CAPABILITIES,
                capability_storage,
                required.value,
                ctypes.byref(returned),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            capability_count = ctypes.cast(
                capability_storage, ctypes.POINTER(wintypes.DWORD)
            ).contents.value
        finally:
            kernel32.CloseHandle(token)
        kernel32.WaitForSingleObject(process.hProcess, INFINITE)
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(process.hProcess, ctypes.byref(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return AppContainerExecution(
            exit_code=int(exit_code.value),
            token_is_appcontainer=bool(is_appcontainer.value),
            capability_count=int(capability_count),
        )
    finally:
        if process.hThread:
            kernel32.CloseHandle(process.hThread)
        if process.hProcess:
            kernel32.CloseHandle(process.hProcess)
        kernel32.DeleteProcThreadAttributeList(attribute_list)
        advapi32.FreeSid(sid)
        delete_profile = userenv.DeleteAppContainerProfile
        delete_profile.argtypes = [wintypes.LPCWSTR]
        delete_profile.restype = ctypes.c_long
        delete_profile(profile_name)
