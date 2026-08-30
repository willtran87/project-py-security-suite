from __future__ import annotations

from collections.abc import Mapping, Sequence


def validate_governed_command_input(
    command: Sequence[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
    environment: Mapping[str, str] | None,
) -> None:
    """Reject resource-amplifying process inputs before any host interaction."""

    if (
        not command
        or len(command) > 1024
        or any(
            not isinstance(item, str) or not item or "\x00" in item for item in command
        )
        or sum(len(item.encode("utf-8")) + 1 for item in command) > 1024 * 1024
    ):
        raise ValueError("scanner command exceeds the governed argument boundary")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= 24 * 60 * 60
    ):
        raise ValueError("scanner timeout must be between 1 second and 24 hours")
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or not 1 <= max_output_bytes <= 1024 * 1024**2
    ):
        raise ValueError("scanner output limit must be between 1 byte and 1 GiB")
    if environment is not None:
        encoded_size = sum(
            len(str(name).encode("utf-8")) + len(str(value).encode("utf-8")) + 2
            for name, value in environment.items()
        )
        if len(environment) > 256 or encoded_size > 1024 * 1024:
            raise ValueError("scanner environment exceeds the governed input boundary")
