"""Load the built-in industry catalogs from validated JSON package data.

Each ``catalogs/<module>.json`` document is an ordered list of operations that
rebuild the module-level data names of ``py_security_suite.<module>`` exactly
as the former Python literals did: ``assign`` binds a name, ``extend`` grows a
sequence, ``update`` merges a mapping and ``append`` adds one item. Operations
may address a nested list through ``path`` (a sequence of mapping keys) and may
draw items from names exported by other catalog modules through
``references``, which preserves object sharing between composed catalogs.

JSON has no tuple or set types, so ``containers`` declares, per name, which
nested positions hold a ``tuple``, ``set`` or ``frozenset`` instead of a list.
A position is written as one ``{}`` per mapping level and one ``[]`` per
sequence level below the name (``""`` is the name itself).

The JSON schema governs the document envelope and every operation; the nested
data values are checked while they are rebuilt (only objects, arrays, strings
and booleans are accepted), which keeps import-time validation linear and fast.
Any schema, reference, container, value or path inconsistency raises
``CatalogDataError`` so a corrupt installation fails closed at import time.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from .strict_json import loads as strict_loads


_SCHEMA_NAME = "industry-catalog-1.0.schema.json"
_SCHEMA_ID = "py-security-suite/industry-catalog/1.0"
_CONTAINER_TYPES: dict[str, type] = {
    "tuple": tuple,
    "set": set,
    "frozenset": frozenset,
}
_MAXIMUM_CATALOG_BYTES = 8 * 1024 * 1024


class CatalogDataError(ValueError):
    """Raised when packaged catalog data is missing, malformed or inconsistent."""


def load_catalog(
    module: str, references: Mapping[str, object] | None = None
) -> dict[str, Any]:
    """Return the data names of ``module`` rebuilt from its packaged JSON."""

    document = _read_json(f"{module}.json")
    error = next(iter(_validator().iter_errors(document)), None)
    if error is not None:
        location = "/".join(str(part) for part in error.absolute_path) or "/"
        raise CatalogDataError(
            f"catalog {module} is invalid at {location}: {error.message}"
        )
    if document["catalog"] != module:
        raise CatalogDataError(
            f"catalog {module} declares a different module: {document['catalog']}"
        )
    return _apply(module, document, dict(references or {}))


def _read_json(name: str) -> Any:
    try:
        raw = files("py_security_suite").joinpath("catalogs", name).read_bytes()
    except OSError as exc:
        raise CatalogDataError(f"catalog data {name} is unavailable") from exc
    try:
        return strict_loads(
            raw, maximum_nodes=1_000_000, maximum_bytes=_MAXIMUM_CATALOG_BYTES
        )
    except ValueError as exc:
        raise CatalogDataError(f"catalog data {name} is not strict JSON") from exc


@cache
def _validator() -> Draft202012Validator:
    schema = _read_json(_SCHEMA_NAME)
    if not isinstance(schema, dict) or schema.get("$id") != _SCHEMA_ID:
        raise CatalogDataError("catalog schema identity is invalid")
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _apply(
    module: str, document: dict[str, Any], references: dict[str, object]
) -> dict[str, Any]:
    containers: dict[str, dict[str, str]] = document["containers"]
    names: dict[str, Any] = {}
    for index, operation in enumerate(document["operations"]):
        where = f"catalog {module} operation {index}"
        target = operation["target"]
        kind = operation["op"]
        layout = containers.get(target, {})
        if kind == "assign":
            if target in names or target in references:
                raise CatalogDataError(f"{where} rebinds {target}")
            if "references" in operation:
                raise CatalogDataError(f"{where} assigns from references")
            names[target] = _build(operation["value"], layout, "", where)
            continue
        if target not in names:
            raise CatalogDataError(f"{where} targets unbound name {target}")
        path: list[str] = operation.get("path", [])
        position = "{}" * len(path)
        holder: Any = names[target]
        for key in path:
            if not isinstance(holder, dict) or key not in holder:
                raise CatalogDataError(f"{where} path {path!r} does not resolve")
            holder = holder[key]
        if kind == "update":
            if path or not isinstance(holder, dict):
                raise CatalogDataError(f"{where} update target is not a mapping")
            for source in _sources(operation, references, where):
                if not isinstance(source, dict):
                    raise CatalogDataError(f"{where} update source is not a mapping")
                holder.update(source)
            if "value" in operation:
                value = _build(operation["value"], layout, position, where)
                if not isinstance(value, dict):
                    raise CatalogDataError(f"{where} update value is not a mapping")
                holder.update(value)
            continue
        if kind == "append":
            if not isinstance(holder, list) or "value" not in operation:
                raise CatalogDataError(f"{where} append target is not a list")
            holder.append(_build(operation["value"], layout, position + "[]", where))
            continue
        items: list[Any] = []
        for source in _sources(operation, references, where):
            if not isinstance(source, (list, tuple)):
                raise CatalogDataError(f"{where} extend source is not a sequence")
            items.extend(source)
        if "value" in operation:
            value = operation["value"]
            if not isinstance(value, list):
                raise CatalogDataError(f"{where} extend value is not a list")
            items.extend(_build(item, layout, position + "[]", where) for item in value)
        if isinstance(holder, tuple) and not path:
            names[target] = holder + tuple(items)
        elif isinstance(holder, list):
            holder.extend(items)
        else:
            raise CatalogDataError(f"{where} extend target is not a sequence")
    return names


def _sources(
    operation: dict[str, Any], references: dict[str, object], where: str
) -> list[object]:
    sources: list[object] = []
    for name in operation.get("references", []):
        if name not in references:
            raise CatalogDataError(f"{where} references unknown name {name}")
        sources.append(references[name])
    return sources


def _build(value: Any, layout: dict[str, str], position: str, where: str) -> Any:
    if isinstance(value, dict):
        return {
            key: _build(item, layout, position + "{}", where)
            for key, item in value.items()
        }
    if isinstance(value, list):
        items = [_build(item, layout, position + "[]", where) for item in value]
        container = layout.get(position)
        if container is None:
            return items
        factory = _CONTAINER_TYPES.get(container)
        if factory is None:
            raise CatalogDataError(f"{where} declares unknown container {container}")
        if factory is not tuple and len(set(items)) != len(items):
            raise CatalogDataError(f"{where} declares a {container} with duplicates")
        return factory(items)
    if not isinstance(value, (str, bool)):
        raise CatalogDataError(
            f"{where} holds a {type(value).__name__} where only strings, "
            "booleans, lists and objects are allowed"
        )
    return value
