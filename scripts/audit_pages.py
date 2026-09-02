"""Fail closed on broken or unsafe generated GitHub Pages artifacts."""

from __future__ import annotations

import argparse
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

_SITE_HOST = "willtran87.github.io"
_SITE_PREFIX = "/project-py-security-suite/"
_MERMAID_SOURCE = "https://unpkg.com/mermaid@11.12.0/dist/mermaid.min.js"
_MERMAID_INTEGRITY = "sha384-o+g/BxPwhi0C3RK7oQBxQuNimeafQ3GE/ST4iT2BxVI4Wzt60SH4pq9iXVYujjaS"  # pragma: allowlist secret
_MERMAID_LOADER = """const diagrams = [...document.querySelectorAll(".pysec-mermaid > code")];
const mermaidSource = "https://unpkg.com/mermaid@11.12.0/dist/mermaid.min.js";
const mermaidIntegrity =
  "sha384-o+g/BxPwhi0C3RK7oQBxQuNimeafQ3GE/ST4iT2BxVI4Wzt60SH4pq9iXVYujjaS"; // pragma: allowlist secret

if (diagrams.length) {
  let started = false;
  const loadMermaid = () =>
    new Promise((resolve, reject) => {
      if (window.mermaid) {
        resolve(window.mermaid);
        return;
      }
      const script = document.createElement("script");
      script.src = mermaidSource;
      script.integrity = mermaidIntegrity;
      script.crossOrigin = "anonymous";
      script.referrerPolicy = "no-referrer";
      script.addEventListener("load", () => resolve(window.mermaid), { once: true });
      script.addEventListener(
        "error",
        () => reject(new Error("The integrity-checked Mermaid bundle failed to load")),
        { once: true },
      );
      document.head.append(script);
    });
  const render = async () => {
    if (started) return;
    started = true;
    const mermaid = await loadMermaid();
    if (!mermaid) throw new Error("The Mermaid bundle did not expose its API");
    mermaid.initialize({ startOnLoad: false });
    await mermaid.run({ nodes: diagrams });
  };
  const start = () => {
    void render().catch((error) => {
      document.documentElement.dataset.mermaidError = JSON.stringify(
        error,
        Object.getOwnPropertyNames(error),
      );
    });
  };

  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          observer.disconnect();
          start();
        }
      },
      { rootMargin: "200px" },
    );
    for (const diagram of diagrams) observer.observe(diagram);
  } else {
    start();
  }
}
"""


class _Document(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.canonical = ""
        self.dialogs: list[dict[str, str]] = []
        self.external_stylesheets: list[dict[str, str]] = []
        self.html_lang = ""
        self.ids: Counter[str] = Counter()
        self.images: list[dict[str, str]] = []
        self.links: list[dict[str, str]] = []
        self.meta_names: dict[str, str] = {}
        self.meta_properties: dict[str, str] = {}
        self.scripts: list[dict[str, str]] = []
        self.table_headers: list[dict[str, str]] = []
        self.title_parts: list[str] = []
        self.source = ""
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
            if "stylesheet" in rel and urlsplit(values.get("href", "")).netloc:
                self.external_stylesheets.append(values)
        elif tag == "a":
            self.links.append(values)
        elif tag == "img":
            self.images.append(values)
        elif tag == "script":
            self.scripts.append(values)
        elif tag == "th":
            self.table_headers.append(values)
        if values.get("role") in {"dialog", "alertdialog"}:
            self.dialogs.append(values)

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
    document.source = path.read_text(encoding="utf-8")
    document.feed(document.source)
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
    for required in (
        "404.html",
        "javascripts/mermaid-init.js",
        "robots.txt",
        "sitemap.xml",
    ):
        if not (root / required).is_file():
            errors.append(f"site: missing {required}")
    loader_path = root / "javascripts/mermaid-init.js"
    if loader_path.is_file():
        loader_source = loader_path.read_text(encoding="utf-8")
        if loader_source != _MERMAID_LOADER:
            errors.append("site: Mermaid loader does not match its reviewed source")
        if _MERMAID_SOURCE not in loader_source:
            errors.append("site: Mermaid loader does not pin the reviewed source")
        if _MERMAID_INTEGRITY not in loader_source:
            errors.append("site: Mermaid loader lacks reviewed integrity metadata")

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
        if "javascripts/mermaid-init.js" not in document.source:
            errors.append(f"{label}: Mermaid module loader is missing")
        if "pysec-mermaid" not in document.source and label != "404.html":
            errors.append(f"{label}: lazy Mermaid markup is missing")
        for identifier, count in document.ids.items():
            if count > 1:
                errors.append(f"{label}: duplicate id {identifier!r}")
        for dialog in document.dialogs:
            if not dialog.get("aria-label") and not dialog.get("aria-labelledby"):
                errors.append(f"{label}: dialog is missing an accessible name")
        if document.external_stylesheets:
            errors.append(f"{label}: page loads a third-party stylesheet")
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
                errors.append(
                    f"{label}: unexpected direct third-party script {source_url!r}"
                )
        material_bundles = [
            script
            for script in document.scripts
            if "assets/javascripts/bundle." in script.get("src", "")
        ]
        if not material_bundles:
            errors.append(f"{label}: Material bundle is missing")
        elif any("defer" not in script for script in material_bundles):
            errors.append(f"{label}: Material bundle is render blocking")
        if any(link.get("data-md-component") == "source" for link in document.links):
            errors.append(f"{label}: repository link enables remote API probes")
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
