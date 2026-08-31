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

Use approved local dependencies and run:

```text
python -m ruff format --check src tests
python -m ruff check src tests
python -m mypy src tests
python -m pytest
pysec doctor . --config APPROVED_CONFIG --profile comprehensive
```

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
