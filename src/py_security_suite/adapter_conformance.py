from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any, cast

from .adapters import ADAPTER_TYPES
from .adapters.base import ScannerAdapter
from .config import SUPPORTED_TOOLS, ToolConfig, load_config


def assess_adapter_conformance() -> dict[str, Any]:
    """Validate the static adapter registry contract without executing scanners."""
    registered = set(ADAPTER_TYPES)
    supported = set(SUPPORTED_TOOLS)
    missing = sorted(supported - registered)
    unexpected = sorted(registered - supported)
    config = load_config(profile_override="comprehensive")
    rows: list[dict[str, Any]] = []
    for name, adapter_type in sorted(ADAPTER_TYPES.items()):
        checks: list[dict[str, Any]] = []
        _record(checks, "concrete", not inspect.isabstract(adapter_type))
        tool_config = config.tools.get(name)
        _record(checks, "configuration", tool_config is not None)
        # The heterogeneous registry is inferred as the abstract common base even
        # though the runtime check above proves that every registered class is
        # concrete. Keep that proof visible and narrow the constructor type here.
        factory = cast(Callable[[ToolConfig, int], ScannerAdapter], adapter_type)
        instance = factory(tool_config, 4096) if tool_config is not None else None
        _record(checks, "identity", instance is not None and instance.name == name)
        exit_codes = (
            instance.accepted_exit_codes if instance is not None else frozenset()
        )
        _record(
            checks,
            "accepted_exit_codes",
            bool(exit_codes)
            and all(
                isinstance(value, int) and 0 <= value <= 255 for value in exit_codes
            ),
        )
        _record(
            checks,
            "bounded_environment",
            _bounded_environment_contract(instance),
        )
        rows.append(
            {
                "adapter": name,
                "class": f"{adapter_type.__module__}.{adapter_type.__qualname__}",
                "status": "pass" if all(item["passed"] for item in checks) else "fail",
                "checks": checks,
                "limitations": (
                    "Static registry contract only; parser fixtures, scanner execution, "
                    "effectiveness, and upgrade qualification remain separate gates."
                ),
            }
        )
    registry_ok = not missing and not unexpected
    passed = sum(row["status"] == "pass" for row in rows)
    return {
        "schema_version": "1.0",
        "schema_id": "urn:project-py-security-suite:schema:adapter-conformance:1.0",
        "authoritative": False,
        "status": "pass" if registry_ok and passed == len(rows) else "fail",
        "registry": {
            "supported": len(supported),
            "registered": len(registered),
            "missing": missing,
            "unexpected": unexpected,
        },
        "summary": {
            "adapters": len(rows),
            "passed": passed,
            "failed": len(rows) - passed,
            "checks": sum(len(row["checks"]) for row in rows),
        },
        "adapters": rows,
        "scope": (
            "Non-executing adapter SDK conformance. This receipt does not establish "
            "scanner availability, detection accuracy, publisher trust, or release approval."
        ),
    }


def render_adapter_conformance(document: dict[str, Any]) -> str:
    """Render the qualification result for terminal and job summaries."""
    summary = document["summary"]
    registry = document["registry"]
    lines = [
        f"{document['status'].upper()}: adapter conformance",
        f"Adapters: {summary['passed']}/{summary['adapters']} passed; {summary['checks']} checks",
        (
            f"Registry: {registry['registered']} registered / {registry['supported']} supported; "
            f"missing {len(registry['missing'])}; unexpected {len(registry['unexpected'])}"
        ),
    ]
    for row in document["adapters"]:
        if row["status"] == "fail":
            failed = ", ".join(
                item["check"] for item in row["checks"] if not item["passed"]
            )
            lines.append(f"- {row['adapter']}: FAIL ({failed})")
    lines.append(f"Scope: {document['scope']}")
    return "\n".join(lines)


def _record(checks: list[dict[str, Any]], name: str, passed: bool) -> None:
    checks.append({"check": name, "passed": bool(passed)})


def _bounded_environment_contract(instance: Any) -> bool:
    if instance is None:
        return False
    try:
        environment = instance.environment()
    except ValueError as exc:
        # An adapter may require a configured offline asset before it can
        # construct its environment. Refusing that missing state is conformant.
        return bool(str(exc).strip())
    return all(
        isinstance(key, str)
        and bool(key)
        and isinstance(value, str)
        and "\x00" not in key + value
        for key, value in environment.extra.items()
    )
