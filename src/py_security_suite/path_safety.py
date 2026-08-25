from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(slots=True)
class HeldParentDirectory:
    path: Path
    descriptor: int | None

    def rename(self, source: Path, destination: Path) -> None:
        if (
            source.parent.absolute() != self.path
            or destination.parent.absolute() != self.path
        ):
            raise ValueError(
                "held-parent rename must remain within the pinned directory"
            )
        if self.descriptor is not None and os.name != "nt":
            os.rename(
                source.name,
                destination.name,
                src_dir_fd=self.descriptor,
                dst_dir_fd=self.descriptor,
            )
        else:
            source.rename(destination)

    def remove_tree(self, path: Path) -> None:
        import shutil

        if path.parent.absolute() != self.path:
            raise ValueError(
                "held-parent deletion must remain within the pinned directory"
            )
        if self.descriptor is not None and os.name != "nt":
            shutil.rmtree(path.name, dir_fd=self.descriptor)
        else:
            shutil.rmtree(path)


@contextmanager
def hold_parent_directory(path: Path, label: str) -> Iterator[HeldParentDirectory]:
    """Pin a mutation target's parent and ancestors through rename/delete."""
    requested = path.expanduser().absolute()
    parent = requested.parent
    resolve_regular_directory(parent, f"{label} parent")
    if os.name == "nt":
        handles = _hold_windows_components(parent)
        try:
            yield HeldParentDirectory(parent, None)
        finally:
            _close_windows_handles(handles)
        return
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(parent, os.O_RDONLY | directory_flag | no_follow)
    try:
        before = os.fstat(descriptor)
        observed = os.stat(parent, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino):
            raise ValueError(f"{label} parent changed while it was pinned")
        yield HeldParentDirectory(parent, descriptor)
    finally:
        os.close(descriptor)


def is_link_like(path: Path) -> bool:
    """Return whether the requested path is a symbolic link or junction."""
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(is_junction) and bool(is_junction()))


def resolve_unlinked_path(
    path: Path,
    label: str,
    *,
    boundary: Path | None = None,
) -> Path:
    """Resolve a path after validating its governed filesystem components."""
    requested = path.expanduser().absolute()
    components = [*reversed(requested.parents), requested]
    if boundary is not None:
        governed_root = boundary.expanduser().absolute()
        try:
            relative = requested.relative_to(governed_root)
        except ValueError:
            # Explicit absolute paths outside a repository boundary are a
            # supported organization-owned input namespace. Validate the
            # requested object, but do not apply repository ancestry policy to
            # unrelated host directories.
            components = [requested]
        else:
            if ".." in relative.parts:
                raise ValueError(f"{label} cannot traverse outside its boundary")
            components = [governed_root]
            current = governed_root
            for part in relative.parts:
                current /= part
                components.append(current)
    for component in components:
        if is_link_like(component):
            if component == requested:
                raise ValueError(
                    f"{label} cannot be a symbolic link or junction: {component}"
                )
            raise ValueError(
                f"{label} cannot be safely resolved; it cannot contain a symbolic "
                f"link or junction: {component}"
            )
    return requested.resolve()


def resolve_regular_file(path: Path, label: str) -> Path:
    resolved = resolve_unlinked_path(path, label)
    if not resolved.is_file():
        raise ValueError(f"{label} is not a regular file: {resolved}")
    return resolved


def read_regular_file(
    path: Path,
    label: str,
    *,
    maximum_bytes: int,
    boundary: Path | None = None,
) -> tuple[Path, bytes]:
    """Read a bounded regular file from one race-resistant open handle.

    The pre-open link checks provide useful diagnostics and cover junctions on
    Windows. ``O_NOFOLLOW`` closes the final-component symlink race where the
    platform supports it, while the before/after descriptor identity check
    rejects files changed during the read.
    """
    if maximum_bytes < 1:
        raise ValueError("maximum_bytes must be positive")
    requested = path.expanduser().absolute()
    resolved = resolve_unlinked_path(path, label, boundary=boundary)
    components_before = _component_identities(requested)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        # Open the spelling the caller supplied. On POSIX the descriptor walk
        # below refuses links in every component, closing the race that would
        # be reintroduced by opening the already-resolved path.
        descriptor = _open_component_safe(requested, flags)
    except FileNotFoundError as exc:
        raise ValueError(f"{label} is not a regular file: {resolved}") from exc
    except OSError as exc:
        raise ValueError(f"{label} could not be opened safely: {resolved}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file: {resolved}")
        if before.st_size > maximum_bytes:
            raise ValueError(f"{label} exceeds {maximum_bytes} bytes")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(maximum_bytes + 1)
        after = os.fstat(descriptor)
        components_after = _component_identities(requested)
        if components_before != components_after:
            raise ValueError(f"{label} path components changed while it was being read")
        final_path = os.stat(requested, follow_symlinks=False)
        if (after.st_dev, after.st_ino) != (final_path.st_dev, final_path.st_ino):
            raise ValueError(f"{label} path was replaced while it was being read")
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after:
            raise ValueError(f"{label} changed while it was being read")
        if len(payload) > maximum_bytes:
            raise ValueError(f"{label} exceeds {maximum_bytes} bytes")
        return resolved, payload
    finally:
        os.close(descriptor)


def _component_identities(path: Path) -> tuple[tuple[str, int, int, int], ...]:
    identities: list[tuple[str, int, int, int]] = []
    for component in [*reversed(path.parents), path]:
        try:
            observed = os.stat(component, follow_symlinks=False)
        except FileNotFoundError:
            continue
        attributes = int(getattr(observed, "st_file_attributes", 0))
        if attributes & 0x400:
            raise ValueError(f"path contains a Windows reparse point: {component}")
        identities.append(
            (str(component), observed.st_dev, observed.st_ino, attributes)
        )
    return tuple(identities)


def _open_component_safe(path: Path, flags: int) -> int:
    """Open a file while pinning every path component against replacement."""
    if os.name == "nt":
        return _open_windows_component_safe(path, flags)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory_flag:
        return os.open(path, flags)
    anchor = Path(path.anchor)
    descriptor = os.open(anchor, os.O_RDONLY | directory_flag)
    try:
        relative_parts = path.relative_to(anchor).parts
        for part in relative_parts[:-1]:
            child = os.open(
                part,
                os.O_RDONLY | directory_flag | no_follow,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        final = os.open(relative_parts[-1], flags | no_follow, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    return final


def _open_windows_component_safe(path: Path, flags: int) -> int:
    """Pin all Windows components with non-delete-sharing reparse-point handles.

    Keeping these handles open prevents an attacker from renaming or replacing
    an ancestor between validation and the final open. Opening reparse points
    themselves, then inspecting their attributes, avoids traversing one before
    it can be rejected.
    """
    import ctypes
    from ctypes import wintypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("last_access_time", wintypes.FILETIME),
            ("last_write_time", wintypes.FILETIME),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    )
    get_information.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    file_read_attributes = 0x80
    file_share_read = 0x1
    open_existing = 3
    open_reparse_point = 0x00200000
    backup_semantics = 0x02000000
    reparse_attribute = 0x400
    invalid_handle = ctypes.c_void_p(-1).value
    held: list[int] = []
    try:
        for component in [*reversed(path.parents), path]:
            handle = create_file(
                str(component),
                file_read_attributes,
                file_share_read,
                None,
                open_existing,
                open_reparse_point | backup_semantics,
                None,
            )
            handle_value = ctypes.cast(handle, ctypes.c_void_p).value
            if handle_value is None or handle_value == invalid_handle:
                raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
            held.append(handle_value)
            information = _ByHandleFileInformation()
            if not get_information(handle, ctypes.byref(information)):
                raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
            if information.file_attributes & reparse_attribute:
                raise OSError(f"path contains a Windows reparse point: {component}")
        return os.open(path, flags)
    finally:
        for handle_value in reversed(held):
            close_handle(wintypes.HANDLE(handle_value))


def _hold_windows_components(path: Path) -> list[int]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    get_attributes = kernel32.GetFileAttributesW
    get_attributes.argtypes = (wintypes.LPCWSTR,)
    get_attributes.restype = wintypes.DWORD
    invalid_handle = ctypes.c_void_p(-1).value
    held: list[int] = []
    try:
        for component in [*reversed(path.parents), path]:
            attributes = get_attributes(str(component))
            if attributes == 0xFFFFFFFF or attributes & 0x400:
                raise OSError(
                    f"path contains an unavailable reparse point: {component}"
                )
            handle = create_file(
                str(component),
                0x80,
                0x1,
                None,
                3,
                0x00200000 | 0x02000000,
                None,
            )
            handle_value = ctypes.cast(handle, ctypes.c_void_p).value
            if handle_value is None or handle_value == invalid_handle:
                raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
            held.append(handle_value)
        return held
    except BaseException:
        _close_windows_handles(held)
        raise


def _close_windows_handles(handles: list[int]) -> None:
    if not handles:
        return
    import ctypes
    from ctypes import wintypes

    close_handle = ctypes.WinDLL(  # type: ignore[attr-defined]
        "kernel32", use_last_error=True
    ).CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    for handle in reversed(handles):
        close_handle(wintypes.HANDLE(handle))


def resolve_regular_directory(path: Path, label: str) -> Path:
    resolved = resolve_unlinked_path(path, label)
    if not resolved.is_dir():
        raise ValueError(f"{label} is not a regular directory: {resolved}")
    return resolved
