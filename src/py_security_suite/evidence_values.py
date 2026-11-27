"""Strict numeric and coverage-summary normalization for ingested evidence."""

from __future__ import annotations

import math
import re
from typing import Any


# ASCII-only numerals: ``int()``/``float()`` would otherwise accept Unicode
# digits (for example Arabic-Indic or full-width) and ``_`` separators.
_ASCII_INTEGER = re.compile(r"[+-]?[0-9]{1,18}", re.ASCII)
_ASCII_NUMBER = re.compile(
    r"[+-]?(?:[0-9]{1,18}(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?",
    re.ASCII,
)


def _integer(value: object) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        raise TypeError(f"expected an integer, received {value!r}")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not _ASCII_INTEGER.fullmatch(text):
        raise TypeError(f"expected an integer, received {value!r}")
    return int(text)


def _optional_integer(value: object) -> int | None:
    return None if value in (None, "") else _integer(value)


def _number(value: object) -> float:
    if value is None or value == "":
        return 0.0
    if isinstance(value, bool):
        raise TypeError(f"expected a number, received {value!r}")
    if isinstance(value, (int, float)):
        result = float(value)
    else:
        text = str(value).strip()
        if not _ASCII_NUMBER.fullmatch(text):
            raise TypeError(f"expected a number, received {value!r}")
        result = float(text)
    if not math.isfinite(result):
        raise TypeError(f"expected a finite number, received {value!r}")
    return round(result, 6)


def _finite_total(value: float) -> float:
    if not math.isfinite(value):
        raise TypeError("JUnit total time is not a finite number")
    return round(value, 6)


def _coverage_summary(value: dict[str, Any]) -> dict[str, int | float]:
    summary = _raw_coverage_summary(value)
    statements = int(summary["num_statements"])
    branches = int(summary["num_branches"])
    covered = int(summary["covered_lines"]) + int(summary["covered_branches"])
    if (
        min(summary.values()) < 0
        or summary["covered_lines"] > statements
        or summary["covered_branches"] > branches
        or summary["percent_covered"] > 100
    ):
        raise ValueError("coverage summary counts are inconsistent")
    # coverage.py derives percent_covered from the counts; a producer-supplied
    # percentage that disagrees with them must not be trusted.
    total = statements + branches
    expected = 100.0 if total == 0 else 100.0 * covered / total
    if (
        "percent_covered" in value
        and abs(float(summary["percent_covered"]) - expected) > 0.01
    ):
        raise ValueError(
            "coverage percent_covered does not match its covered and total counts"
        )
    return summary


def _raw_coverage_summary(value: dict[str, Any]) -> dict[str, int | float]:
    return {
        "covered_lines": _integer(value.get("covered_lines")),
        "num_statements": _integer(value.get("num_statements")),
        "percent_covered": _number(value.get("percent_covered")),
        "missing_lines": _integer(value.get("missing_lines")),
        "num_branches": _integer(value.get("num_branches")),
        "covered_branches": _integer(value.get("covered_branches")),
        "missing_branches": _integer(value.get("missing_branches")),
        "num_partial_branches": _integer(value.get("num_partial_branches")),
    }
