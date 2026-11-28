from __future__ import annotations

import json
from typing import Any

import pytest

from py_security_suite import catalog_data
from py_security_suite.catalog_data import CatalogDataError, load_catalog


CATALOG_MODULES = (
    "industry_emerging_assurance_catalog",
    "industry_interoperability_sector_catalog",
    "industry_maturity_product_catalog",
    "industry_open_source_catalog",
    "industry_resilience_catalog",
    "industry_standards_catalog",
    "industry_benchmark_catalog",
    "industry_profile_catalog",
)


def _install(monkeypatch: pytest.MonkeyPatch, document: dict[str, Any]) -> None:
    original = catalog_data._read_json

    def fake(name: str) -> Any:
        if name == "industry_test_catalog.json":
            return json.loads(json.dumps(document))
        return original(name)

    monkeypatch.setattr(catalog_data, "_read_json", fake)


def _document(*operations: dict[str, Any], **containers: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "catalog": "industry_test_catalog",
        "containers": containers,
        "operations": list(operations),
    }


@pytest.mark.parametrize("module", CATALOG_MODULES)
def test_packaged_catalogs_are_valid_json_data(module: str) -> None:
    document = catalog_data._read_json(f"{module}.json")
    assert document["catalog"] == module
    assert not list(catalog_data._validator().iter_errors(document))


def test_catalog_rebuilds_tuples_sets_paths_and_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared = {"x": {"items": ["a"]}}
    _install(
        monkeypatch,
        _document(
            {"op": "assign", "target": "ROWS", "value": [["a", ["b"]], ["c", []]]},
            {"op": "extend", "target": "ROWS", "value": [["d", ["e"]]]},
            {"op": "assign", "target": "IDS", "value": ["b", "a"]},
            {"op": "assign", "target": "PROFILES", "value": {"p": {"items": []}}},
            {"op": "update", "target": "PROFILES", "references": ["SHARED"]},
            {
                "op": "append",
                "target": "PROFILES",
                "path": ["x", "items"],
                "value": ["z", True],
            },
            ROWS={"": "tuple", "[]": "tuple"},
            IDS={"": "frozenset"},
            PROFILES={"{}{}[]": "tuple"},
        ),
    )

    names = load_catalog("industry_test_catalog", {"SHARED": shared})

    assert names["ROWS"] == (("a", ["b"]), ("c", []), ("d", ["e"]))
    assert names["IDS"] == frozenset({"a", "b"})
    assert names["PROFILES"]["x"] is shared["x"]
    assert shared["x"]["items"] == ["a", ("z", True)]


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (_document({"op": "assign", "target": "A", "value": [1]}), "only strings"),
        (_document({"op": "assign", "target": "A", "value": None}), "invalid"),
        (_document({"op": "extend", "target": "A", "value": []}), "unbound"),
        (
            _document(
                {"op": "assign", "target": "A", "value": []},
                {"op": "extend", "target": "A", "references": ["MISSING"]},
            ),
            "unknown name",
        ),
        (
            _document(
                {"op": "assign", "target": "A", "value": {}},
                {"op": "append", "target": "A", "path": ["k"], "value": "v"},
            ),
            "does not resolve",
        ),
        (
            _document(
                {"op": "assign", "target": "A", "value": ["x", "x"]}, A={"": "set"}
            ),
            "duplicates",
        ),
        (
            _document({"op": "assign", "target": "A", "value": []}, A={"": "deque"}),
            "invalid",
        ),
        (
            _document(
                {"op": "assign", "target": "A", "value": []},
                {"op": "assign", "target": "A", "value": []},
            ),
            "rebinds",
        ),
        (
            {**_document({"op": "assign", "target": "A", "value": []}), "extra": 1},
            "invalid",
        ),
        (
            {
                **_document({"op": "assign", "target": "A", "value": []}),
                "catalog": "industry_x_catalog",
            },
            "different module",
        ),
    ],
)
def test_catalog_loader_fails_closed(
    monkeypatch: pytest.MonkeyPatch, document: dict[str, Any], message: str
) -> None:
    _install(monkeypatch, document)

    with pytest.raises(CatalogDataError, match=message):
        load_catalog("industry_test_catalog")


def test_missing_catalog_data_fails_closed() -> None:
    with pytest.raises(CatalogDataError, match="unavailable"):
        load_catalog("industry_absent_catalog")
