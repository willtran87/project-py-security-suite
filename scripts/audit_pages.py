"""Fail closed on broken or unsafe generated GitHub Pages artifacts."""

from __future__ import annotations

import argparse
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

_SITE_HOST = "willtran87.github.io"
_SITE_PREFIX = "/project-py-security-suite/"


class _Document(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.canonical = ""
        self.html_lang = ""
        self.ids: Counter[str] = Counter()
        self.images: list[dict[str, str]] = []
        self.links: list[dict[str, str]] = []
        self.meta_names: dict[str, str] = {}
        self.meta_properties: dict[str, str] = {}
        self.scripts: list[dict[str, str]] = []
        self.table_headers: list[dict[str, str]] = []
        self.title_parts: list[str] = []
        self._inside_title = False

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = {key: value or "" for key, value in attrs}
        identifier = values.get("id")
        if identifier:
            self.ids[identifier] += 1
        if tag == "html":
            self.html_lang = values.get("lang", "").strip()
        elif tag == "title":
            self._inside_title = True
        elif tag == "meta":
            content = values.get("content", "").strip()
            name = values.get("name", "").lower()
            property_name = values.get("property", "").lower()
            if name:
                self.meta_names[name] = content
            if property_name:
                self.meta_properties[property_name] = content
        elif tag == "link":
            rel = values.get("rel", "").lower().split()
            if "canonical" in rel:
                self.canonical = values.get("href", "").strip()
        elif tag == "a":
            self.links.append(values)
        elif tag == "img":
            self.images.append(values)
        elif tag == "script":
            self.scripts.append(values)
        elif tag == "th":
            self.table_headers.append(values)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._inside_title = False

    def handle_data(self, data: str) -> None:
        if self._inside_title:
            self.title_parts.append(data)

    @property
    def title(self) -> str:
        return "".join(self.title_parts).strip()


def _read_document(path: Path) -> _Document:
    document = _Document()
    document.feed(path.read_text(encoding="utf-8"))
    return document


def _internal_target(root: Path, source: Path, href: str) -> tuple[Path, str] | None:
    parsed = urlsplit(href)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return None
    if parsed.netloc and parsed.netloc.lower() != _SITE_HOST:
        return None

    path = unquote(parsed.path)
    if parsed.netloc:
        if not path.startswith(_SITE_PREFIX):
            return None
        path = path.removeprefix(_SITE_PREFIX)
        target = root / path
    elif path.startswith("/"):
        if not path.startswith(_SITE_PREFIX):
            return None
        target = root / path.removeprefix(_SITE_PREFIX)
    elif path:
        target = source.parent / path
    else:
        target = source

    if path.endswith("/") or target.is_dir() or not target.suffix:
        target = target / "index.html"
    resolved_target = target.resolve()
    if not resolved_target.is_relative_to(root.resolve()):
        resolved_target = root.resolve() / "__outside_site__"
    return resolved_target, unquote(parsed.fragment)


def audit_site(root: Path) -> list[str]:
    """Return deterministic publication defects for a generated site."""

    root = root.resolve()
    html_files = sorted(root.rglob("*.html"))
    errors: list[str] = []
    if not html_files:
        return ["site: no HTML pages were generated"]
    for required in ("404.html", "robots.txt", "sitemap.xml"):
        if not (root / required).is_file():
            errors.append(f"site: missing {required}")

    documents = {path.resolve(): _read_document(path) for path in html_files}
    for path, document in documents.items():
        label = path.relative_to(root).as_posix()
        if not document.html_lang:
            errors.append(f"{label}: missing html lang")
        if not document.title:
            errors.append(f"{label}: missing title")
        for name in ("description", "viewport", "referrer"):
            if not document.meta_names.get(name):
                errors.append(f"{label}: missing {name} metadata")
        for property_name in (
            "og:type",
            "og:site_name",
            "og:title",
            "og:description",
            "og:url",
        ):
            if not document.meta_properties.get(property_name):
                errors.append(f"{label}: missing {property_name} metadata")
        if not document.canonical.startswith(f"https://{_SITE_HOST}{_SITE_PREFIX}"):
            errors.append(f"{label}: invalid canonical URL {document.canonical!r}")
        if document.meta_properties.get("og:url") != document.canonical:
            errors.append(f"{label}: Open Graph URL does not match canonical URL")
        for identifier, count in document.ids.items():
            if count > 1:
                errors.append(f"{label}: duplicate id {identifier!r}")
        for header in document.table_headers:
            if header.get("scope") not in {"col", "row"}:
                errors.append(f"{label}: table header is missing a valid scope")
        for image in document.images:
            if "alt" not in image:
                errors.append(f"{label}: image is missing alt text")
            if image.get("alt") and not {"width", "height"} <= image.keys():
                errors.append(f"{label}: meaningful image is missing dimensions")
        for script in document.scripts:
            source_url = script.get("src", "")
            parsed_source = urlsplit(source_url)
            if parsed_source.scheme == "http":
                errors.append(f"{label}: script uses insecure HTTP")
            if parsed_source.netloc and parsed_source.netloc.lower() != _SITE_HOST:
                if not script.get("integrity"):
                    errors.append(f"{label}: third-party script lacks integrity")
                if script.get("crossorigin") != "anonymous":
                    errors.append(f"{label}: third-party script lacks anonymous CORS")
        for link in document.links:
            href = link.get("href", "").strip()
            if not href:
                continue
            if link.get("target", "").lower() == "_blank":
                rel = set(link.get("rel", "").lower().split())
                if not {"noopener", "noreferrer"} <= rel:
                    errors.append(f"{label}: new-window link lacks noopener noreferrer")
            target = _internal_target(root, path, href)
            if target is None:
                continue
            target_path, fragment = target
            if not target_path.is_file():
                errors.append(f"{label}: broken internal link {href!r}")
                continue
            if fragment and target_path.suffix == ".html":
                target_document = documents.get(target_path)
                if target_document is None or fragment not in target_document.ids:
                    errors.append(f"{label}: missing internal anchor {href!r}")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site", type=Path, help="generated MkDocs site directory")
    args = parser.parse_args()
    errors = audit_site(args.site)
    if errors:
        for error in errors:
            print(error)
        return 1
    print("Pages artifact audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
