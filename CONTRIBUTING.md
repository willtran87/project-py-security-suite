# Contributing

Contributions should preserve the suite's offline-first, fail-closed trust
model and stable normalized report contract.

## Before changing code

- Open an issue for a new scanner, profile contract, report schema change, or
  security-boundary change.
- Never make scanning install packages, resolve dependencies, update databases,
  import the target project, or contact an external service.
- Keep connected acquisition in preparation scripts and isolated execution in
  the scanner adapters.
- Add a compatibility-matrix entry and selection rationale for every new tool.

## Local validation

Use the locked development environment and run the same core gates as the CI
`quality` and `test` jobs (see `.github/workflows/ci.yml` for the full list,
including the additional strict-surface and script type checks):

```text
uv sync --locked --all-groups
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy src companion scripts/audit_pages.py
uv run --frozen mypy --config-file src/py_security_suite/rules/mypy.ini src
uv run --frozen pyright
uv run --frozen pytest -n auto
uv run --frozen python -m scripts.validate_documentation_metrics
uv run --frozen check-manifest --no-build-isolation
uv build --no-sources --out-dir .artifacts/quality-dist
uv run --frozen python scripts/validate_distribution_metadata.py .artifacts/quality-dist
uv run --frozen zizmor --pedantic --no-progress --color never .github
pysec doctor . --config APPROVED_CONFIG --profile comprehensive
```

Changing `containers/scanner/pyproject.toml` requires regenerating its uv lock
and both hash-locked exports:

```text
uv lock --project containers/scanner
uv export --frozen --project containers/scanner --no-emit-project --no-emit-local --no-header --no-annotate --output-file containers/scanner/requirements.lock
uv export --frozen --project containers/scanner --only-group build --no-emit-project --no-emit-local --no-header --no-annotate --output-file containers/scanner/build-requirements.lock
```

Record user-visible changes under `## [Unreleased]` in
[CHANGELOG.md](CHANGELOG.md).

Adapter changes require positive, negative, malformed-output, applicability,
and unavailable-tool tests. Report changes require Markdown, HTML, SARIF, JSON,
checksum, and redaction coverage as applicable. Scanner discovery must prune
generated, tool-owned, build, virtual-environment, and symlinked trees.

## Pull requests

Keep commits reviewable, describe trust-boundary effects, and include the exact
commands used for validation. Do not commit real secrets, private keys, licensed
query packs, vulnerability databases, native tool bundles, or generated scan
artifacts. Security-sensitive findings belong in a private advisory as described
in [SECURITY.md](SECURITY.md).

Protected branches require an approval from someone other than the last pusher.
Repository administrators must therefore retain at least two independent people
or teams with review authority and CODEOWNERS coverage. A single eligible owner
is an explicit fail-closed governance state, not a reason to weaken required
checks or silently bypass review; emergency overrides must be time-bounded,
recorded, and followed by restoration and independent retrospective review.
