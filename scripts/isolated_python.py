"""Fresh bytecode locations for validation subprocesses (stdlib only)."""

from contextlib import contextmanager
import tempfile


@contextmanager
def isolated_python(python: str, arguments: list[str]):
    # -B prevents writes; the fresh prefix prevents reads of existing caches.
    # Keep paths short for native Windows IPC used by scanner subprocesses.
    with tempfile.TemporaryDirectory(prefix="") as cache:
        yield [python, "-I", "-B", "-X", f"pycache_prefix={cache}", *arguments]
