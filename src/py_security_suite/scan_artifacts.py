"""Explicit producer ownership for adapter-stage outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ArtifactRegistry:
    values: dict[str, Any] = field(default_factory=dict)
    producers: dict[str, str] = field(default_factory=dict)

    def add(self, producer: str, artifacts: dict[str, Any]) -> None:
        for name in artifacts:
            if name in self.producers:
                raise ValueError(
                    f"artifact collision for {name}: {self.producers[name]} and {producer}"
                )
        self.values.update(artifacts)
        self.producers.update(dict.fromkeys(artifacts, producer))
