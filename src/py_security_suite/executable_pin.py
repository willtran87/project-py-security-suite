"""Hold an approved executable stable from digest verification through launch.

Windows: the image is opened without ``FILE_SHARE_WRITE``/``FILE_SHARE_DELETE``
so it cannot be modified, renamed, replaced or deleted (nor its directories
renamed) while the pin is held; the digest is computed through that handle.

POSIX: there are no mandatory locks. The digest is computed through a held
descriptor and the pin records the inode identity and change time. Any
replacement (new inode) or in-place write (new ctime) between verification and
the post-run check is detected and fails the run closed. An in-place write that
is reverted within the same ctime granularity remains a documented residual
risk; deployments that need prevention must keep scanner installs read-only to
the scanning identity.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

_BATCH_SUFFIXES = frozenset({".bat", ".cmd"})


def windows_image_error(path: Path, header: bytes | None = None) -> str | None:
    """Return why ``path`` cannot be launched without a command interpreter."""
    if os.name != "nt":
        return None
    if path.suffix.casefold() in _BATCH_SUFFIXES:
        return (
            "Windows batch-file scanners are rejected because cmd.exe re-parses "
            "their arguments; configure the native executable instead"
        )
    if header is None:
        try:
            with path.open("rb") as handle:
                header = handle.read(2)
        except OSError:
            return "scanner executable could not be read"
    if header[:2] != b"MZ":
        return "Windows scanner executable is not a native PE image"
    return None


def require_windows_image(executable: str) -> None:
    """Reject an existing non-PE launch target before process creation."""
    if os.name != "nt":
        return
    path = Path(executable)
    if not path.is_absolute() or not path.is_file():
        return
    error = windows_image_error(path)
    if error:
        raise ValueError(error)


@dataclass(slots=True)
class PinnedExecutable:
    path: Path
    sha256: str
    _descriptor: int
    _identity: tuple[int, int, int, int, int]

    def unchanged(self) -> bool:
        """Return whether the pinned path still names the hashed, unmodified file."""
        try:
            held = os.fstat(self._descriptor)
            current = os.stat(self.path)
        except OSError:
            return False
        return _identity(held) == self._identity == _identity(current)


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    # Windows reports different "ctime" semantics for fstat and stat; writes
    # there are already denied by the held share mode.
    change = value.st_ctime_ns if os.name != "nt" else 0
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, change)


@contextmanager
def pin_executable(path: Path) -> Iterator[PinnedExecutable]:
    """Open, hash and hold an executable until the caller's launch completes."""
    descriptor = _open_shared_read_only(path)
    try:
        digest = hashlib.sha256()
        header = b""
        os.lseek(descriptor, 0, os.SEEK_SET)
        while chunk := os.read(descriptor, 1024 * 1024):
            if not header:
                header = chunk[:2]
            digest.update(chunk)
        error = windows_image_error(path, header)
        if error:
            raise ValueError(error)
        yield PinnedExecutable(
            path, digest.hexdigest(), descriptor, _identity(os.fstat(descriptor))
        )
    finally:
        os.close(descriptor)


def _open_shared_read_only(path: Path) -> int:
    if os.name != "nt":
        return os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    return _open_windows_deny_write(path)  # pragma: no cover - Windows only


def _open_windows_deny_write(path: Path) -> int:  # pragma: no cover - Windows only
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    generic_read, file_share_read, open_existing, attribute_normal = (
        0x80000000,
        0x1,
        3,
        0x80,
    )
    handle = kernel32.CreateFileW(
        str(path),
        generic_read,
        file_share_read,
        None,
        open_existing,
        attribute_normal,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if not handle or handle == invalid:
        error = ctypes.get_last_error()  # type: ignore[attr-defined]
        raise OSError(error, "scanner executable could not be pinned", str(path))
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))  # type: ignore[attr-defined]
    except OSError:
        kernel32.CloseHandle(handle)
        raise
