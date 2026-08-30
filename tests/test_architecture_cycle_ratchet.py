from __future__ import annotations

from scripts.validate_architecture_cycles import _cyclic_components, main


def test_cycle_detection_finds_only_strongly_connected_groups() -> None:
    graph = {
        "a": {"b"},
        "b": {"a", "leaf"},
        "leaf": set(),
        "self": {"self"},
    }
    assert _cyclic_components(graph) == {frozenset({"a", "b"}), frozenset({"self"})}


def test_checked_in_architecture_cycle_debt_is_exact() -> None:
    assert main() == 0
