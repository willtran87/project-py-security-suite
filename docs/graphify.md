# Graphify code-graph integration

Last reviewed: 2026-08-12

Graphify adds a deterministic code-property graph to the suite's finding,
architecture, complexity, coverage, and reachability perspectives. The adapter
uses the `graphifyy` package and runs only this bounded command:

```text
graphify extract TARGET --code-only --no-cluster --out TEMP --max-workers 1
```

The scan supplies no LLM backend and does not enable document, URL, hook,
Postgres, or live-input analysis. It rejects nonzero model tokens, non-AST
origins, hyperedges, unknown edge endpoints, escaping paths, and oversized
graphs. API-key variables are excluded by the suite's reduced environment.

## Evidence flow

```mermaid
flowchart LR
    Python["Python source"] --> Graphify["Graphify code-only AST pass"]
    Graphify --> Guard["Token, origin, path, edge, and size validation"]
    Guard --> Graph["graphify.json<br/>nodes, edges, confidence, hubs"]
    Findings["Normalized findings<br/>all scanners"] --> Join["Graph-aware correlation"]
    Reach["Reachability and coverage evidence"] --> Join
    Graph --> Join
    Join --> Context["Finding context<br/>upstream, downstream, related findings"]
    Join --> Hotspots["graph-analysis.json<br/>cross-tool clusters and hotspots"]
    Hotspots --> Synthesis["structural-synthesis.json<br/>dead code, islands, import cycles"]
    Graph --> Synthesis
    Context --> Reports["Markdown, HTML, JSON, SARIF"]
    Synthesis --> Reports
```

## Interpretation

- `graphify.json` is normalized supporting evidence, not a vulnerability list.
- `graph-analysis.json` lists structural hubs and nearby findings from multiple
  tools.
- `structural-synthesis.json` cross-validates symbol/file references against
  reachability islands, Vulture, runtime coverage, Radon, Tach, ownership, and
  findings. See [Structural synthesis](structural-synthesis.md).
- Each located finding receives concise upstream, downstream, centrality, and
  related-finding context in Markdown, HTML, and JSON.
- Static connectivity does not prove runtime reachability, exploitability, or
  safety. The built-in reachability analyzer and test evidence remain separate.
- Graph centrality alone never raises or lowers a finding's native severity.

Graphify edge confidence (`EXTRACTED`, `INFERRED`, or `AMBIGUOUS`) is retained.
The connected preparation script pins the package and dependencies; the
disconnected installer creates a dedicated `graphify-env`, hashes its entry
point, and writes the exact path and SHA-256 to `pysec.native.toml`. Docker is
not required.

References: [Graphify CLI](https://graphify.com/docs/cli),
[security model](https://graphify.com/security), and
[source repository](https://github.com/Graphify-Labs/graphify).
