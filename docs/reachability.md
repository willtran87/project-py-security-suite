# Python reachability and code islands

Last reviewed: 2026-08-06

The `reachability` scanner maps production Python modules and symbols from
application entry points without importing or executing target code. It complements
Vulture's individual dead-code findings, Radon's complexity measurements, and
Tach's declared module boundaries.

## What it provides

- Discovers roots from `[project.scripts]`, `[project.gui-scripts]`, arbitrary
  `[project.entry-points.*]` groups, Poetry scripts, `__main__.py`, guarded Python
  mains, configured roots, and common decorated framework handlers.
- Parses target source with Python's AST and builds bounded import, definition,
  reference, direct-call, class-member, framework-dispatch, polymorphic-dispatch,
  ownership, and package-initialization edges.
- Assigns every node one of three explicit states: `executable`, `load-only`, or
  `disconnected`; every assignment records its predecessor, edge kind, reason,
  and confidence.
- Traces representative direct-call and bounded dispatch sequences from each
  entry point.
- Groups disconnected modules and connected load-only symbol subgraphs into code
  islands without claiming that load-only code is dead.
- Ranks islands by physical source lines, module count, and symbol count.
- Optionally correlates bounded coverage.py JSON so reviewers can distinguish
  statically reachable code that was observed, not observed, or not measured.
- Emits normalized, cited findings only when an island meets the configured size
  threshold. The complete graph and all candidates remain in `reachability.json`.

```mermaid
flowchart LR
    Sources["Python source and pyproject.toml"] --> Parse["Bounded AST parsing"]
    Parse --> Graph["Typed edges with confidence and reasons"]
    Roots["Scripts, mains, handlers, configured roots"] --> Walk["Reachability traversal"]
    Graph --> Walk
    Walk --> Execute["Executable<br/>direct call or explicit dispatch"]
    Walk --> Load["Load-only<br/>imported, defined, or referenced"]
    Walk --> Disconnected["Disconnected<br/>no known path"]
    Execute --> Paths["Representative execution sequences"]
    Load --> Islands["Load-only review candidates"]
    Disconnected --> Islands["Disconnected code islands"]
    Coverage["Optional coverage.py JSON"] --> Observe["Observed | not observed | not measured"]
    Observe --> Execute
    Observe --> Load
    Observe --> Disconnected
    Islands --> Rank["Rank by LOC, modules, and symbols"]
    Rank --> Findings["State-appropriate findings with file, source, classification, and action"]
    Graph --> Artifact["reachability.json"]
    Paths --> Artifact
    Islands --> Artifact
```

## Entry-point discovery

Automatic discovery is conservative. Framework handlers are recognized through
common decorators such as `route`, `get`, `post`, `command`, `task`, `receiver`,
and `subscribe`. Applications using reflection, dependency injection, generated
registries, custom decorators, or plugin loading must declare those roots:

```toml
[tools.reachability]
enabled = true
executable = "pysec"
timeout_seconds = 600
minimum_island_loc = 100
discover_framework_roots = true
entry_points = [
  "acme.plugins:load_plugins",
  "acme.public:Client",
]
source_roots = ["src"]
coverage_path = ".artifacts/test-evidence/coverage.json"
```

Each entry uses `module:function`, `module:Class`, or a module name. Organization
policy can require roots and source scopes. Repository configuration cannot remove
organization-required roots, disable required framework discovery, or raise the
organization's reporting threshold.

For direct inspection without a full portfolio scan:

```powershell
pysec reachability . --minimum-island-loc 100 --pretty
```

To add runtime corroboration from a separately generated test lane:

```powershell
pysec reachability . --coverage .artifacts/test-evidence/coverage.json --pretty
```

Both commands write schema `1.1` JSON to standard output and perform no network
operations. The analyzer reads coverage evidence but never runs tests itself.

## Reachability states

| State | Evidence required | Interpretation | Default action |
|---|---|---|---|
| `executable` | Entry point, direct call, bounded callback reference, recognized framework hook, or bounded polymorphic dispatch | A static execution path exists; medium-confidence dispatch edges remain clearly labeled | Review the representative sequence and edge explanations |
| `load-only` | Import, definition, member creation, or reference, with no executable path | The code is available at runtime but invocation is unproven | Confirm callbacks/plugins and coverage before removal |
| `disconnected` | No load or executable path from any discovered root | Strongest unused-island candidate, subject to dynamic-language caveats | Validate missing roots, then test and remove or explicitly retain |

An observed `load-only` or `disconnected` node is reported as a static/runtime
model gap, not dead code. It may be a test-only path, indirect dispatch, or missing
production root. The distinction preserves runtime evidence without silently
promoting every imported symbol to executable.

## Reading the artifact

`reachability.json` contains:

| Section | Meaning |
|---|---|
| `analysis` | Mode, three-state model, confidence, completeness, limits, graph digest, coverage binding, and target-execution statement |
| `scope` | Inferred source roots and analyzed Python volume |
| `summary` | Executable, load-only, disconnected, runtime-observed, entry-point, edge, and island counts |
| `entry_points` | Every root, its discovery source, declaration, file, and line |
| `representative_sequences` | Bounded paths showing how roots reach internal behavior |
| `islands` | All disconnected components, including candidates below the finding threshold |
| `nodes` / `edges` | Machine-readable graph with node state, runtime observation, predecessor explanation, typed edge, confidence, reason, and source location |
| `dynamic_features` | Observed wildcard imports, dynamic imports, `eval`, `exec`, or bounded polymorphic dispatch |
| `warnings` / `errors` | Confidence qualifications and incomplete-analysis conditions |

Large islands become standard findings with the `PYREACH` classification family.
Only disconnected candidates cite
[CWE-561](https://cwe.mitre.org/data/definitions/561.html); load-only candidates
do not assert dead code. Runtime-observed static candidates are informational
model-gap findings. Findings include
the tool, native rule, confidence, affected files, source excerpts, component size,
symbols, citations, impact, and a concrete next action.

## Limits and confidence

Static reachability is an approximation. Python reflection, monkey patching,
dependency injection, generated modules, native extensions, externally loaded
plugins, and data-driven dispatch can create runtime paths that are not visible in
an AST. The analyzer therefore:

- never labels a candidate as proven runtime-dead;
- uses medium-confidence, bounded method-name dispatch only when multiple internal
  implementations make an unresolved receiver plausibly polymorphic;
- recognizes `ast.NodeVisitor` hooks as framework dispatch and exposes the exact
  convention on the edge;
- lowers confidence when dynamic loading, execution, or polymorphic dispatch is
  observed;
- disables island conclusions when no root resolves;
- turns parse, scope, duplicate-module, and resource-limit gaps into actionable
  medium-severity findings;
- includes every caveat in the sealed report artifact.

Treat an island as a review candidate. Confirm registrations and deployment entry
points, add missing roots, rerun, then remove code with regression tests. Runtime
coverage is corroboration: observation proves a path ran in that test lane, while
non-observation alone never proves production deadness.

## Resource and trust boundaries

The analyzer is bundled with the suite and invoked through the `pysec` entry point,
so the existing executable digest and post-execution integrity controls apply. It
does not need Docker, network access, a database, or target dependencies. Parsing
is bounded to 20,000 files, 5 MiB per file, 250 MiB of Python source, 50,000 graph
nodes, 50,000 graph edges, 64 MiB of coverage JSON, and five million executed-line
observations. Entry points and displayed sequences are separately
bounded; exceeding a conclusion-affecting limit produces incomplete-analysis
evidence instead of a silent partial conclusion.
