from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from urllib.parse import unquote

from py_security_suite.assurance_catalog import export_assurance_catalog
from py_security_suite.config import PROFILE_TOOLS, SUPPORTED_TOOLS

_ROOT = Path(__file__).resolve().parents[1]
_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


class DocumentationQualityTests(unittest.TestCase):
    def test_local_markdown_links_resolve(self) -> None:
        failures: list[str] = []
        for document in _documents():
            text = document.read_text(encoding="utf-8")
            for raw_target in _LINK.findall(text):
                target = raw_target.strip().strip("<>").split("#", 1)[0]
                if (
                    not target
                    or "://" in target
                    or target.startswith(("mailto:", "data:"))
                ):
                    continue
                candidate = (document.parent / unquote(target)).resolve()
                if not candidate.exists():
                    failures.append(f"{document.relative_to(_ROOT)} -> {raw_target}")
        self.assertEqual(
            failures, [], "broken local Markdown links:\n" + "\n".join(failures)
        )

    def test_mermaid_fences_are_balanced_and_nonempty(self) -> None:
        failures: list[str] = []
        for document in _documents():
            text = document.read_text(encoding="utf-8")
            starts = [match.end() for match in re.finditer(r"```mermaid\s*\n", text)]
            for start in starts:
                end = text.find("```", start)
                if end < 0 or not text[start:end].strip():
                    failures.append(str(document.relative_to(_ROOT)))
        self.assertEqual(failures, [], "invalid Mermaid fences: " + ", ".join(failures))

    def test_documented_portfolio_count_matches_registry(self) -> None:
        expected = len(SUPPORTED_TOOLS)
        documents = (_ROOT / "README.md", _ROOT / "docs" / "design.md")
        for document in documents:
            text = document.read_text(encoding="utf-8")
            counts = {
                int(value) for value in re.findall(r"\b(\d+) governed adapters\b", text)
            }
            self.assertEqual(
                counts,
                {expected},
                f"{document.relative_to(_ROOT)} has a stale adapter count",
            )

    def test_documented_profile_snapshot_matches_configuration(self) -> None:
        index = (_ROOT / "docs" / "index.md").read_text(encoding="utf-8")
        self.assertIn(f"{len(PROFILE_TOOLS)} profiles", index)
        for profile in ("comprehensive", "release", "production", "audit"):
            self.assertIn(
                f"`{profile}`"
                if profile not in {"comprehensive", "release"}
                else profile,
                index,
            )
            self.assertIn(str(len(PROFILE_TOOLS[profile])), index)

    def test_industry_catalog_counts_and_new_domains_are_documented(self) -> None:
        counts = export_assurance_catalog()["counts"]
        expectations = {
            _ROOT / "README.md": (
                f"{counts['standards']} versioned references",
                f"{counts['standards_watchlist']} quarantined watch items",
                f"{counts['profiles']} selectable profiles",
                f"{counts['benchmarks']} governed benchmark families",
                f"{counts['adapter_specs']} maintained adapters",
                f"{counts['execution_contracts']} maintained benchmark adapters",
            ),
            _ROOT / "docs" / "design.md": (
                f"{counts['standards']} versioned standards references",
                f"{counts['profiles']} assurance packs",
                f"{counts['benchmarks']} governed benchmark families",
                f"{counts['adapter_specs']} maintained adapters",
            ),
            _ROOT / "docs" / "index.md": (
                f"{counts['standards']} standards references",
                f"{counts['standards_watchlist']} quarantined watch items",
                f"{counts['profiles']} assurance packs",
                f"{counts['benchmarks']} benchmark families",
                f"{counts['adapter_specs']} maintained adapters",
            ),
            _ROOT / "docs" / "industry-standards-benchmarks.md": (
                f"{counts['standards']} version-explicit references",
                f"{counts['standards_watchlist']} non-normative watch items",
                f"{counts['profiles']} built-in packs",
                f"{counts['adapter_specs']}-adapter catalog",
            ),
        }
        for path, phrases in expectations.items():
            content = path.read_text(encoding="utf-8")
            for phrase in phrases:
                self.assertIn(phrase, content, f"{path.relative_to(_ROOT)} is stale")

        profiles = {
            "ransomware-resilience",
            "media-sanitization",
            "ot-backup-and-remote-access",
            "iec-62443-provider-evaluation",
            "crisis-leadership-and-exercises",
            "enterprise-ict-risk-portfolio",
            "standards-crosswalk-governance",
            "lng-and-ev-infrastructure",
        }
        benchmarks = {
            "ransomware-resilience-exercise",
            "media-sanitization-verification",
            "ot-backup-remote-access-recovery",
            "iec-62443-service-provider-evaluation",
            "crisis-exercise-assurance",
            "enterprise-ict-risk-aggregation",
            "standards-crosswalk-semantic-conformance",
            "lng-ev-charging-sector-resilience",
        }
        industry = (_ROOT / "docs" / "industry-standards-benchmarks.md").read_text(
            encoding="utf-8"
        )
        for identifier in profiles | benchmarks:
            self.assertIn(identifier, industry)

        example = json.loads(
            (
                _ROOT / "examples" / "industry-assurance-policy-1.3.example.json"
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(profiles <= {item["id"] for item in example["profiles"]})
        self.assertTrue(benchmarks <= {item["id"] for item in example["benchmarks"]})

    def test_industry_diagrams_show_the_new_assurance_lanes(self) -> None:
        documents = {
            "README.md": (_ROOT / "README.md").read_text(encoding="utf-8"),
            "docs/design.md": (_ROOT / "docs" / "design.md").read_text(
                encoding="utf-8"
            ),
            "docs/index.md": (_ROOT / "docs" / "index.md").read_text(encoding="utf-8"),
            "docs/benchmark-operations.md": (
                _ROOT / "docs" / "benchmark-operations.md"
            ).read_text(encoding="utf-8"),
        }
        required = {
            "README.md": (
                "Recovery + sanitization + OT + crisis",
                "crosswalk + LNG/EV",
            ),
            "docs/design.md": ("IEC-provider", "crosswalk/LNG-EV"),
            "docs/index.md": ("ransomware | sanitization | OT recovery", "LNG/EV"),
            "docs/benchmark-operations.md": (
                "Ransomware + sanitization + OT backup/remote access",
                "IEC 62443 provider + ICT risk + crosswalk + LNG/EV",
            ),
        }
        for name, phrases in required.items():
            for phrase in phrases:
                self.assertIn(phrase, documents[name])

    def test_new_contextual_artifacts_are_documented(self) -> None:
        readme = (_ROOT / "README.md").read_text(encoding="utf-8")
        accuracy = (_ROOT / "docs" / "analysis-accuracy.md").read_text(encoding="utf-8")
        for artifact in (
            "finding-validation.json",
            "framework-model-coverage.json",
            "application-contract-analysis.json",
            "capability-manifest.json",
            "code-health.json",
            "static-architecture.json",
            "architecture-history.json",
        ):
            self.assertIn(artifact, readme)
            self.assertIn(artifact, accuracy)

    def test_contextual_analysis_diagrams_cover_current_semantics(self) -> None:
        accuracy = (_ROOT / "docs" / "analysis-accuracy.md").read_text(encoding="utf-8")
        design = (_ROOT / "docs" / "design.md").read_text(encoding="utf-8")
        configuration = (_ROOT / "docs" / "configuration.md").read_text(
            encoding="utf-8"
        )
        for phrase in (
            "semantic anchor",
            "native flow sink",
            "Machine-actionable scenarios + argv-safe tasks",
            "architecture-policy.json",
            "tach.toml",
            "code-health-policy.json",
        ):
            self.assertIn(phrase, accuracy)
        for phrase in (
            "Consumer capability",
            "Authorization tasks",
            "Property tasks",
            "Ranked bounded detail",
            "Tach fallback policy",
            "Separate authorized execution lane",
        ):
            self.assertIn(phrase, design)
        self.assertIn("Conservative finding correlation", design)
        self.assertIn("static-architecture.json 1.4", configuration)
        self.assertIn("code-health.json 1.4", configuration)
        self.assertIn("typed/framework semantic graph", configuration)
        self.assertIn("root-cause review queue", design)

    def test_governed_effectiveness_examples_use_production_floors(self) -> None:
        documents = (
            _ROOT / "README.md",
            _ROOT / "docs" / "release-readiness.md",
        )
        for document in documents:
            text = document.read_text(encoding="utf-8")
            for expected in (
                "--minimum-effectiveness-labels 500",
                "--minimum-effectiveness-positive-labels 200",
                "--minimum-effectiveness-negative-labels 200",
                "--minimum-effectiveness-tools 3",
                "--minimum-effectiveness-labels-per-tool 50",
                "--required-effectiveness-tool codeql",
            ):
                self.assertIn(expected, text)


def _documents() -> list[Path]:
    return sorted(
        [path for path in _ROOT.glob("*.md") if path.is_file()]
        + [path for path in (_ROOT / "docs").rglob("*.md") if path.is_file()]
    )
