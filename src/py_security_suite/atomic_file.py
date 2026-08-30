from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .path_safety import hold_parent_directory, resolve_unlinked_path


_POSIX_DURABILITY = os.name != "nt"


def atomic_write_bytes(
    destination: Path,
    payload: bytes,
    *,
    label: str,
    mode: int = 0o600,
) -> None:
    """Durably replace one regular file without exposing partial content."""

    target = resolve_unlinked_path(destination, label)
    target.parent.mkdir(parents=True, exist_ok=True)
    with hold_parent_directory(target, label) as held:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
        temporary = Path(temporary_name)
        try:
            if _POSIX_DURABILITY:
                os.chmod(temporary, mode)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            held.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
