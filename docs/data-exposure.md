# Sensitive-data exposure analysis

The suite detects implementation paths that can disclose credentials or private
data through logs, telemetry, analytics, metrics, error reporting, or outbound
SDKs. Analysis remains offline and does not import or execute the target.

## Security basis

This control is grounded in established weakness definitions and defensive
practice:

- [CWE-532](https://cwe.mitre.org/data/definitions/532.html) covers sensitive
  information written to logs. Logs are commonly replicated, retained, and
  accessible to a broader operator population than production data stores.
- [CWE-201](https://cwe.mitre.org/data/definitions/201.html) covers sensitive
  information inserted into data sent outside its intended boundary.
- [CWE-200](https://cwe.mitre.org/data/definitions/200.html),
  [CWE-209](https://cwe.mitre.org/data/definitions/209.html), and
  [CWE-359](https://cwe.mitre.org/data/definitions/359.html) cover unauthorized
  disclosure, sensitive error details, and private personal information.
- [CWE-598](https://cwe.mitre.org/data/definitions/598.html) covers credentials,
  tokens, PII, and other sensitive values placed in URL query strings, which
  routinely propagate into histories, access logs, proxies, caches, monitoring,
  and Referer headers.
- The [OWASP Logging Cheat
  Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
  recommends excluding, masking, sanitizing, hashing, or encrypting sensitive
  fields as appropriate; testing logging behavior; protecting transport and
  storage; and reviewing third-party transmission.
- [OpenTelemetry sensitive-data guidance](https://opentelemetry.io/docs/security/handling-sensitive-data/)
  recommends deleting, hashing, filtering, transforming, or allowlisting
  attributes before export. Its URL conventions require user information to be
  omitted and known-sensitive query parameters to be scrubbed.

These classifications do not turn every logger or telemetry call into a
vulnerability. The suite explicitly separates confirmed scanner traces from
review surfaces.

## Evidence model

```mermaid
flowchart LR
    Sources["Sensitive sources<br/>credentials, private fields, request collections"]
    Taint["Semgrep, Pysa, and CodeQL<br/>source-to-sink evidence"]
    Sinks["Logs, telemetry, URL queries,<br/>client errors, process streams"]
    SDK["AST and dependency inventory<br/>SDK, sink, and local alias context"]
    Triage["Bounded triage context<br/>data class, trust boundary, protection, priority"]
    Graph["Graphify and reachability<br/>structural relevance"]
    Tests["Coverage and diff-cover<br/>runtime and change context"]
    Finding["Normalized exposure finding<br/>source, sink, SDK, CWE, action"]

    Sources --> Taint --> Sinks --> Finding
    SDK --> Triage --> Finding
    Graph --> Finding
    Tests --> Finding
```

The bundled Semgrep rules identify credential-bearing values obtained from:

- credential-named environment variables;
- authorization, cookie, session, and token headers;
- request cookies; and
- common cloud secret-manager result APIs; and
- credential-named object attributes and mapping entries, such as
  `settings.api_key` and `config["auth_token"]`.

A separate medium-confidence privacy lane recognizes explicit fields commonly
associated with contact and account data, IP addresses, government identifiers,
payment cards, birth data, and patient/health records. These matches carry
CWE-359 plus a sink-specific CWE. Field-name modeling is intentionally bounded
and does not replace an organization's authoritative data classification catalog.

They trace those values to standard and structured logging, bound logger
context, stdout/stderr (commonly collected as container logs), Sentry and other
error SDKs, OpenTelemetry-style spans, Datadog/New Relic events, metric labels,
and common analytics calls. Additional rules detect:

- whole request bodies, JSON, forms, POST/GET collections, and query-parameter
  mappings sent to logs or telemetry;
- credentials or private fields serialized into HTTP query strings, plus
  credential-bearing values interpolated directly into outbound URLs;
- raw exception text returned through FastAPI, Starlette, Flask, or Django
  response primitives; and
- Sentry `send_default_pii=True` as a high-confidence configuration review;
- broad `locals()`, `vars(...)`, `__dict__`, or process-environment snapshots
  written to logs or exported to telemetry;
- OpenTelemetry GenAI message-content capture in `.env`, TOML, YAML, INI,
  properties, and Python environment assignments; and
- wildcard OpenTelemetry request/response header capture in those configuration
  formats.

Request payload matching distinguishes request-like receivers from generic SDK
response objects. For example, `request.data` remains a review source while
`embedding_response.data` does not become request taint merely because its
attribute is named `data`.

Only explicitly named minimization, allowlisting, redaction, removal, sanitizing,
or scrubbing boundaries suppress bundled taint rules. Generic hashing, HMAC,
masking, filtering, or tokenization no longer suppresses a finding by name
alone: those transformations may be reversible, linkable, brute-forceable,
partial, or applied to the wrong field. Review evidence still records a visible
candidate transform, but organizational approval and tests determine adequacy.

## SDK and sink inventory

`data-exposure.json` inventories relevant imports, declared dependencies, and
sink calls for:

- Sentry, Rollbar, Bugsnag, OpenTelemetry, OpenCensus, Datadog/ddtrace,
  Elastic APM, New Relic, Honeycomb, Pydantic Logfire, Raygun, and AWS X-Ray;
- structlog and Loguru;
- Prometheus and StatsD clients;
- Segment/Analytics, Mixpanel, Amplitude, and PostHog; and
- Requests, HTTPX, and aiohttp egress surfaces.

The catalog also covers Azure Monitor OpenTelemetry, Google Cloud Logging and
Error Reporting, Splunk OpenTelemetry, Langfuse, OpenInference, Arize Phoenix,
and MLflow. Dependency discovery walks nested `pyproject.toml` files, PEP 621
optional dependencies, Poetry dependency groups, and requirements/constraints
files so monorepo packages do not disappear behind the root manifest.

The inventory also highlights custom logger variables, bound log context,
process output, risky Sentry PII settings, broad OpenTelemetry HTTP-header
capture, sensitive query parameters, and exception-bearing client responses.
These remain review surfaces until a scanner supplies source-to-sink or exact
configuration evidence.

Within each file, the AST inventory conservatively propagates named data-class
context through simple assignments. Surfaces record credential, personal,
financial, health, and request-content hints; operational, client, or external
trust boundaries; broad-state, serialization, URL-retention, and exception
risk factors; and the visible protection kind. Minimization/allowlisting,
redaction/masking, configured SDK hooks, and pseudonymization remain distinct so
reviewers do not mistake a hash or token for removal. High/medium/low review
priority only orders inventory work—it is not a vulnerability severity or a
regulatory classification.

An inventory item is **not a finding**. It tells reviewers where disclosure
controls should exist and activates SDK-specific context when a scanner reports
a supported flow. Vendored SDK code remains visible to source scanners; a
dependency declaration alone cannot prove how application data is used.

## Correlation and output

For supported findings, the suite adds:

- concern and sink family;
- SDK identity when uniquely supported by import or call evidence;
- production versus test scope;
- structural relevance such as changed, connected, runtime-observed, or
  disconnected-review;
- visible sanitizer evidence without claiming sanitizer correctness;
- bounded data classes, trust boundary, protection kind, risk factors, and
  review priority;
- source scanner attribution and CWE/OWASP citations; and
- a remediation specific to logging, telemetry, URL propagation, exception
  responses, or external disclosure.

The context is retained in normalized JSON, Markdown, HTML, SARIF, SonarQube,
and evidence-fusion review reasons. Raw sensitive values are never added to the
derived artifact.

## Required review practice

For every confirmed path:

1. Verify the source data classification and intended recipients.
2. Remove unnecessary fields; data minimization is preferred to filtering.
3. Prefer an approved allowlist or removal boundary. Treat hashing, masking,
   tokenization, and pseudonymization as still sensitive until the data owner
   approves the construction and re-identification risk.
4. Disable automatic PII collection and request/body capture in SDK settings
   where applicable.
5. Test structured serialization, exception capture, breadcrumbs, trace
   attributes, metric labels, and retry/error paths with synthetic canary data.
6. Verify transport protection, access controls, retention, deletion, and the
   third party's approved purpose.
7. Rerun the isolated suite and preserve the sealed evidence artifact.

## Limitations

- Static analysis may miss reflection, generated code, framework middleware,
  custom wrappers, and runtime object serialization.
- Variable names alone do not reliably establish PII, PHI, PCI, or proprietary
  data. Organization-specific Pysa/CodeQL/Semgrep models remain necessary.
- Static request-collection rules intentionally favor review sensitivity and
  may report benign schemas; an allowlisted event DTO is the preferred closure.
- A clean result does not prove that production logs or telemetry contain no
  sensitive data. A separate, explicitly authorized dynamic companion can send
  synthetic canary values to local exporters and inspect captured output.
- The suite inventories generic HTTP egress but does not flag it without
  source-to-sink evidence; sending credentials to an approved endpoint can be
  intentional.

## Artifact contract

The current contract is bundled as
[`data-exposure-1.2.schema.json`](../src/py_security_suite/schemas/data-exposure-1.2.schema.json);
[1.1](../src/py_security_suite/schemas/data-exposure-1.1.schema.json) and
[1.0](../src/py_security_suite/schemas/data-exposure-1.0.schema.json) remain
available for existing consumers. Analysis is bounded to 5,000 Python files,
1,000 configuration files of at most 2 MiB each, 500 sink surfaces, and 500 SDK
observations. Omitted counts and parse failures remain explicit.
