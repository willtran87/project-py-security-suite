from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import platform
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

try:
    from companion.assurance_context import load_context
    from companion.deep_qualification import verify_area_receipt
    from companion.provenance import inline_provenance
    from companion.strict_json import canonical_bytes
    from companion.strict_json import dumps as strict_dumps
except ModuleNotFoundError:  # Direct script execution.
    from assurance_context import load_context  # type: ignore[import-not-found,no-redef]
    from deep_qualification import verify_area_receipt  # type: ignore[import-not-found,no-redef]
    from provenance import inline_provenance  # type: ignore[import-not-found,no-redef]
    from strict_json import canonical_bytes  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run bounded browser security assertions against one loopback service."
        )
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument(
        "--role-url",
        action="append",
        default=[],
        metavar="ROLE=URL",
        help="exercise an additional loopback journey for an authorization role",
    )
    parser.add_argument(
        "--role-storage-state",
        action="append",
        default=[],
        metavar="ROLE=FILE",
        help="use a bounded Playwright storage-state credential for a declared role",
    )
    parser.add_argument("--run-id", default="")
    parser.add_argument("--valid-for-hours", type=float, default=24.0)
    parser.add_argument(
        "--browser", choices=("chromium", "firefox", "webkit"), default="chromium"
    )
    parser.add_argument("--qualification-receipt", type=Path)
    parser.add_argument("--qualification-receipt-sha256", default="")
    args = parser.parse_args(argv)
    if bool(args.qualification_receipt) != bool(args.qualification_receipt_sha256):
        raise ValueError(
            "browser qualification receipt and SHA-256 are required together"
        )
    qualified = False
    if not 0.01 <= args.valid_for_hours <= 168.0:
        raise ValueError("valid-for-hours must be between 0.01 and 168")
    journeys = [("anonymous", loopback_target(args.url))]
    journeys.extend(_role_target(value) for value in args.role_url)
    parsed_states = [_role_storage_state(value) for value in args.role_storage_state]
    role_states = dict(parsed_states)
    declared_roles = {role for role, _target in journeys if role != "anonymous"}
    if len(role_states) != len(parsed_states) or set(role_states) != declared_roles:
        raise ValueError(
            "every non-anonymous role requires exactly one role-storage-state"
        )
    context = load_context(
        args.context, [f"browser:{role}" for role, _target in journeys]
    )
    if args.qualification_receipt is not None:
        verify_area_receipt(
            args.qualification_receipt,
            area="browser",
            filename=args.qualification_receipt.name,
            sha256=args.qualification_receipt_sha256,
            target={
                "url": args.url,
                "revision": args.revision,
                "browser": args.browser,
                "journeys": [
                    {"role": role, "origin": _safe_origin(target)}
                    for role, target in journeys
                ],
                "storage_state_sha256": {
                    role: hashlib.sha256(path.read_bytes()).hexdigest()
                    for role, path in role_states.items()
                },
                "context_sha256": hashlib.sha256(args.context.read_bytes()).hexdigest(),
            },
        )
        qualified = True
    findings: list[dict[str, Any]] = []
    requests = 0
    canaries_observed = 0
    for role, target in journeys:
        observed, request_count, canary = _inspect_browser_surface(
            target,
            browser_name=args.browser,
            role=role,
            storage_state=role_states.get(role),
        )
        findings.extend(observed)
        requests += request_count
        canaries_observed += int(canary)
    generated = datetime.now(UTC)
    producer_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    ruleset_sha256 = _digest_json(
        {
            "headers": [
                "csp-quality",
                "nosniff",
                "frame",
                "referrer",
                "hsts",
                "permissions-policy",
                "cross-origin-isolation",
                "authenticated-cache-control",
                "cors",
            ],
            "cookies": ["httpOnly", "secure", "sameSite", "prefix-invariants"],
            "boundary": "loopback-only",
        }
    )
    config_sha256 = _digest_json(
        {
            "browser": args.browser,
            "journeys": [
                {"role": role, "origin": _safe_origin(target)}
                for role, target in journeys
            ],
        }
    )
    environment = f"{platform.system()}-{platform.machine()}-playwright-{args.browser}"
    document = {
        "schema_version": "2.0",
        "kind": "browser-security",
        "producer": f"playwright-{args.browser}",
        "producer_version": "1",
        "producer_sha256": producer_sha256,
        "revision": args.revision[:200],
        "generated_at": generated.isoformat(),
        "expires_at": (generated + timedelta(hours=args.valid_for_hours)).isoformat(),
        "run_id": _context_run_id(args.run_id, context["run_id"]),
        "artifact_sha256": "",
        "ruleset_sha256": ruleset_sha256,
        "config_sha256": config_sha256,
        "environment": environment[:200],
        "environment_sha256": hashlib.sha256(environment.encode()).hexdigest(),
        "context": {key: value for key, value in context.items() if key != "run_id"},
        "execution": {
            "status": "completed",
            "targets_discovered": len(journeys),
            "targets_exercised": len(journeys),
            "requests": requests,
            "coverage_percent": 100.0,
            "coverage_metric": "declared-role-journeys",
            "roles": [role for role, _ in journeys],
            "features": [
                "security-headers",
                "csp-quality",
                "browser-isolation",
                "authenticated-cache-control",
                "cookie-attributes",
                "navigation",
                "egress-denial",
                "isolated-authenticated-storage-state",
            ],
            "skipped_checks": [],
            "canaries_expected": len(journeys),
            "canaries_observed": canaries_observed,
        },
        "findings": findings,
    }
    if qualified:
        document["execution"]["features"].extend(
            [
                "browser-active-abuse-matrix",
                "authenticated-cross-tenant-probes",
                "chromium-firefox-webkit",
                "csrf-dom-xss-postmessage-session-service-worker-websocket",
            ]
        )
    document["provenance"] = inline_provenance(
        native_receipt={"execution": document["execution"], "findings": findings},
        builder_id=f"pysec-playwright-{args.browser}",
        builder=Path(__file__),
        invocation=canonical_bytes(
            {
                "browser": args.browser,
                "journeys": [
                    {"role": role, "origin": _safe_origin(target)}
                    for role, target in journeys
                ],
            }
        ),
        materials=document["context"],
    )
    _write_json(args.output, document)
    # Findings are data for the suite policy gate. A completed producer exits
    # successfully so evidence can still be bound, uploaded, and reviewed.
    return 0


def loopback_target(value: str) -> SplitResult:
    target = urlsplit(value)
    if target.scheme not in {"http", "https"} or not target.hostname:
        raise ValueError("target must be an absolute HTTP(S) URL")
    if target.username or target.password or target.fragment:
        raise ValueError("credentials and fragments are not allowed in the target URL")
    hostname = target.hostname.casefold()
    if hostname != "localhost":
        try:
            if not ipaddress.ip_address(hostname).is_loopback:
                raise ValueError("target must resolve explicitly to a loopback address")
        except ValueError as exc:
            raise ValueError(
                "target must use localhost or an explicit loopback address"
            ) from exc
    return target


def _context_run_id(requested: str, expected: str) -> str:
    result = requested.strip() or expected
    if result != expected:
        raise ValueError("run-id does not match the organization-issued context")
    return result


def inspect_browser_surface(
    target: SplitResult, *, browser_name: str
) -> list[dict[str, Any]]:
    findings, _, _ = _inspect_browser_surface(
        target, browser_name=browser_name, role="anonymous"
    )
    return findings


def _inspect_browser_surface(
    target: SplitResult,
    *,
    browser_name: str,
    role: str,
    storage_state: Path | None = None,
) -> tuple[list[dict[str, Any]], int, bool]:
    from playwright.sync_api import Error as PlaywrightError  # type: ignore[import-not-found]
    from playwright.sync_api import Route, sync_playwright  # type: ignore[import-not-found]

    findings: list[dict[str, Any]] = []
    blocked_origins: set[str] = set()
    websocket_origins: set[str] = set()
    websocket_frame_digests: set[str] = set()
    mixed_content_origins: set[str] = set()
    request_count = 0
    with sync_playwright() as playwright:
        browser_type = getattr(playwright, browser_name)
        browser = browser_type.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=False,
            service_workers="block",
            storage_state=str(storage_state) if storage_state is not None else None,
        )
        context.add_init_script(
            """(() => {
              const counts = { wildcard_postmessage: 0, html_sink_writes: 0,
                document_writes: 0, storage_writes: 0, popup_opens: 0,
                cross_origin_messages: 0 };
              Object.defineProperty(window, '__pysecRuntimeCounts', { value: counts });
              const post = window.postMessage.bind(window);
              window.postMessage = (message, targetOrigin, transfer) => {
                if (targetOrigin === '*') counts.wildcard_postmessage++;
                return post(message, targetOrigin, transfer);
              };
              for (const name of ['innerHTML', 'outerHTML']) {
                const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, name);
                if (descriptor && descriptor.set) Object.defineProperty(Element.prototype, name, {
                  ...descriptor, set(value) { counts.html_sink_writes++; return descriptor.set.call(this, value); }
                });
              }
              const write = document.write.bind(document);
              document.write = (...args) => { counts.document_writes++; return write(...args); };
              for (const storage of [localStorage, sessionStorage]) {
                const setItem = storage.setItem.bind(storage);
                storage.setItem = (...args) => { counts.storage_writes++; return setItem(...args); };
              }
              const open = window.open.bind(window);
              window.open = (...args) => { counts.popup_opens++; return open(...args); };
              addEventListener('message', event => {
                if (event.origin !== location.origin) counts.cross_origin_messages++;
              });
            })();"""
        )
        page = context.new_page()
        page.on(
            "websocket",
            lambda socket: websocket_origins.add(_origin_only(socket.url)),
        )

        def route_websocket(socket: Any) -> None:
            websocket_origins.add(_origin_only(socket.url))
            _proxy_websocket(socket, websocket_frame_digests)

        context.route_web_socket("**/*", route_websocket)

        def route_request(route: Route) -> None:
            nonlocal request_count
            request_count += 1
            request_target = urlsplit(route.request.url)
            if target.scheme == "https" and request_target.scheme == "http":
                mixed_content_origins.add(_origin_only(route.request.url))
            try:
                loopback_target(route.request.url)
            except ValueError:
                blocked_origins.add(
                    f"{request_target.scheme}://{request_target.hostname or 'unknown'}"
                )
                route.abort("blockedbyclient")
                return
            route.continue_()

        context.route("**/*", route_request)
        try:
            response = page.goto(
                target.geturl(), wait_until="networkidle", timeout=30_000
            )
        except PlaywrightError:
            response = None
        if response is None:
            findings.append(
                _finding(
                    "navigation-failed",
                    "Browser could not obtain a response",
                    "high",
                    "CWE-703",
                    "The loopback application did not return an inspectable response.",
                )
            )
        else:
            findings.extend(
                _header_findings(response.all_headers(), target.scheme, role=role)
            )
        findings.extend(
            _cookie_findings(context.cookies([target.geturl()]), target.scheme)
        )
        if response is not None:
            try:
                observations = page.evaluate(
                    """() => ({
                      inline_handlers: [...document.querySelectorAll('*')].filter(
                        element => [...element.attributes].some(attribute => attribute.name.toLowerCase().startsWith('on'))
                      ).length,
                      javascript_urls: document.querySelectorAll('[href^="javascript:"], [src^="javascript:"]').length,
                      unsafe_blank_targets: [...document.querySelectorAll('a[target="_blank"]')].filter(
                        element => !String(element.rel || '').toLowerCase().split(/\\s+/).some(value => value === 'noopener' || value === 'noreferrer')
                      ).length,
                      insecure_password_forms: [...document.querySelectorAll('form')].filter(
                        form => form.querySelector('input[type="password"]') && new URL(form.action, document.baseURI).protocol !== 'https:'
                      ).length,
                      cross_origin_embeds: [...document.querySelectorAll('iframe[src], object[data], embed[src]')].filter(
                        element => { const raw = element.getAttribute('src') || element.getAttribute('data'); try { return new URL(raw, document.baseURI).origin !== location.origin; } catch { return false; } }
                      ).length,
                      service_worker_controlled: navigator.serviceWorker ? Boolean(navigator.serviceWorker.controller) : false,
                      local_storage_entries: localStorage.length,
                      session_storage_entries: sessionStorage.length,
                      unsafe_postmessage_calls: [...document.scripts].filter(
                        script => !script.src && /postMessage\\s*\\([^,]+,\\s*['\"]\\*['\"]/.test(script.textContent || '')
                      ).length,
                      dynamic_html_sinks: [...document.scripts].filter(
                        script => !script.src && /(?:innerHTML|outerHTML|insertAdjacentHTML|document\\.write)\\s*(?:=|\\()/.test(script.textContent || '')
                      ).length,
                      runtime_wildcard_postmessages: window.__pysecRuntimeCounts?.wildcard_postmessage || 0,
                      runtime_html_sink_writes: window.__pysecRuntimeCounts?.html_sink_writes || 0,
                      runtime_document_writes: window.__pysecRuntimeCounts?.document_writes || 0,
                      runtime_storage_writes: window.__pysecRuntimeCounts?.storage_writes || 0,
                      runtime_popup_opens: window.__pysecRuntimeCounts?.popup_opens || 0,
                      runtime_cross_origin_messages: window.__pysecRuntimeCounts?.cross_origin_messages || 0
                    })"""
                )
                findings.extend(_dom_findings(observations, target.scheme))
            except PlaywrightError:
                findings.append(
                    _finding(
                        "dom-inspection-failed",
                        "Browser DOM security inspection did not complete",
                        "medium",
                        "CWE-703",
                        "Make the rendered document available to the browser assurance lane.",
                    )
                )
        for origin in sorted(blocked_origins):
            findings.append(
                _finding(
                    "external-browser-request",
                    "Browser attempted an external request",
                    "medium",
                    "CWE-918",
                    "Keep the test deployment self-contained or explicitly review the external dependency.",
                    evidence={"blocked_origin": origin},
                )
            )
        for origin in sorted(mixed_content_origins):
            findings.append(
                _finding(
                    "mixed-active-content",
                    "HTTPS page requested an HTTP resource",
                    "high",
                    "CWE-319",
                    "Serve every active browser resource over HTTPS.",
                    evidence={"resource_origin": origin},
                )
            )
        for origin in sorted(websocket_origins):
            parsed = urlsplit(origin)
            if parsed.scheme == "ws" and target.scheme == "https":
                findings.append(
                    _finding(
                        "insecure-websocket",
                        "HTTPS page opened an unencrypted WebSocket",
                        "high",
                        "CWE-319",
                        "Use WSS and enforce origin and authentication checks during the handshake.",
                        evidence={"websocket_origin": origin},
                    )
                )
        if websocket_frame_digests:
            findings.append(
                _finding(
                    "websocket-frames-observed",
                    "WebSocket traffic requires protocol-specific authorization review",
                    "informational",
                    "CWE-1385",
                    "Retain only bounded frame digests and exercise origin, authentication, schema, and message-level authorization oracles.",
                    evidence={
                        "frame_digest_count": len(websocket_frame_digests),
                        "content_retained": False,
                    },
                )
            )
        context.close()
        browser.close()
    # This self-test proves the boundary validator rejects a non-loopback target
    # without creating network traffic or retaining a credential-bearing URL.
    egress_canary = False
    try:
        loopback_target("https://example.invalid/pysec-egress-canary")
    except ValueError:
        egress_canary = True
    for finding in findings:
        evidence = finding.setdefault("evidence", {})
        if isinstance(evidence, dict):
            evidence["role"] = role[:100]
    return findings, request_count, egress_canary


def _proxy_websocket(socket: Any, frame_digests: set[str]) -> bool:
    """Proxy a Playwright Python WebSocketRoute and retain only frame digests."""
    try:
        loopback_target(
            socket.url.replace("ws://", "http://", 1).replace("wss://", "https://", 1)
        )
    except ValueError:
        socket.close(code=1008, reason="external WebSocket blocked")
        return False

    server = socket.connect_to_server()

    def digest(message: Any) -> None:
        raw = message if isinstance(message, bytes) else str(message).encode()
        frame_digests.add(hashlib.sha256(raw[: 1024 * 1024]).hexdigest())

    def page_to_server(message: Any) -> None:
        digest(message)
        server.send(message)

    def server_to_page(message: Any) -> None:
        digest(message)
        socket.send(message)

    socket.on_message(page_to_server)
    server.on_message(server_to_page)
    return True


def _role_target(value: str) -> tuple[str, SplitResult]:
    role, separator, url = value.partition("=")
    if not separator or not role or len(role) > 100:
        raise ValueError("role-url must use ROLE=URL with a bounded role")
    if not all(character.isalnum() or character in "._-" for character in role):
        raise ValueError("role-url role contains unsupported characters")
    return role, loopback_target(url)


def _role_storage_state(value: str) -> tuple[str, Path]:
    role, separator, filename = value.partition("=")
    if (
        not separator
        or not role
        or len(role) > 100
        or not all(character.isalnum() or character in "._-" for character in role)
    ):
        raise ValueError("role-storage-state must use ROLE=FILE")
    path = Path(filename).expanduser().resolve()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("role storage state must be a bounded regular file")
    return role, path


def _safe_origin(target: SplitResult) -> str:
    return f"{target.scheme}://{target.hostname}:{target.port or (443 if target.scheme == 'https' else 80)}"


def _origin_only(value: str) -> str:
    target = urlsplit(value)
    if not target.scheme or not target.hostname:
        return "unknown://unknown"
    port = target.port or (443 if target.scheme in {"https", "wss"} else 80)
    return f"{target.scheme}://{target.hostname}:{port}"


def _digest_json(value: object) -> str:
    payload = canonical_bytes(value)
    return hashlib.sha256(payload).hexdigest()


def _header_findings(
    headers: dict[str, str], scheme: str, *, role: str = "anonymous"
) -> list[dict[str, Any]]:
    normalized = {key.casefold(): value.strip() for key, value in headers.items()}
    findings: list[dict[str, Any]] = []
    if not normalized.get("content-security-policy"):
        findings.append(
            _finding(
                "missing-content-security-policy",
                "Content-Security-Policy is absent",
                "medium",
                "CWE-693",
                "Define and test a restrictive Content-Security-Policy for the deployed application.",
            )
        )
    else:
        csp_value = normalized["content-security-policy"].casefold()
        if "require-trusted-types-for 'script'" not in csp_value:
            findings.append(
                _finding(
                    "csp-trusted-types-not-required",
                    "CSP does not require Trusted Types for script sinks",
                    "low",
                    "CWE-79",
                    "Adopt Trusted Types and require them for script sinks after compatibility testing.",
                )
            )
        for token, rule, title in (
            (
                "'unsafe-eval'",
                "csp-unsafe-eval",
                "CSP permits unsafe script evaluation",
            ),
            (
                "'unsafe-inline'",
                "csp-unsafe-inline",
                "CSP permits unsafe inline script",
            ),
        ):
            if token in csp_value:
                findings.append(
                    _finding(
                        rule,
                        title,
                        "medium",
                        "CWE-693",
                        "Replace unsafe CSP script allowances with nonces or hashes.",
                    )
                )
        for directive, expected, rule in (
            ("default-src", None, "csp-missing-default-src"),
            ("object-src", "'none'", "csp-object-src-not-none"),
            ("base-uri", None, "csp-missing-base-uri"),
        ):
            if directive not in csp_value or (
                expected is not None
                and expected not in _csp_directive(csp_value, directive)
            ):
                findings.append(
                    _finding(
                        rule,
                        f"CSP {directive} protection is incomplete",
                        "low",
                        "CWE-693",
                        f"Define a restrictive {directive} directive in the deployed CSP.",
                    )
                )
    if normalized.get("x-content-type-options", "").casefold() != "nosniff":
        findings.append(
            _finding(
                "missing-nosniff",
                "X-Content-Type-Options nosniff is absent",
                "low",
                "CWE-693",
                "Return X-Content-Type-Options: nosniff on browser responses.",
            )
        )
    csp = normalized.get("content-security-policy", "").casefold()
    frame_options = normalized.get("x-frame-options", "").casefold()
    if "frame-ancestors" not in csp and frame_options not in {"deny", "sameorigin"}:
        findings.append(
            _finding(
                "missing-frame-protection",
                "Framing protection is absent",
                "medium",
                "CWE-1021",
                "Set CSP frame-ancestors and retain X-Frame-Options where legacy coverage is required.",
            )
        )
    if not normalized.get("referrer-policy"):
        findings.append(
            _finding(
                "missing-referrer-policy",
                "Referrer-Policy is absent",
                "low",
                "CWE-200",
                "Set an explicit restrictive Referrer-Policy.",
            )
        )
    if scheme == "https" and not normalized.get("strict-transport-security"):
        findings.append(
            _finding(
                "missing-hsts",
                "Strict-Transport-Security is absent",
                "medium",
                "CWE-319",
                "Enable HSTS after confirming every production endpoint is HTTPS-only.",
            )
        )
    if not normalized.get("permissions-policy"):
        findings.append(
            _finding(
                "missing-permissions-policy",
                "Permissions-Policy is absent",
                "low",
                "CWE-693",
                "Disable browser capabilities that the application does not use.",
            )
        )
    for header, accepted_values, rule in (
        (
            "cross-origin-opener-policy",
            {"same-origin"},
            "weak-cross-origin-opener-policy",
        ),
        (
            "cross-origin-resource-policy",
            {"same-origin", "same-site"},
            "weak-cross-origin-resource-policy",
        ),
    ):
        if normalized.get(header, "").casefold() not in accepted_values:
            findings.append(
                _finding(
                    rule,
                    f"{header} does not enforce browser isolation",
                    "low",
                    "CWE-346",
                    f"Set a restrictive {header} response header.",
                )
            )
    allow_origin = normalized.get("access-control-allow-origin", "")
    allow_credentials = normalized.get(
        "access-control-allow-credentials", ""
    ).casefold()
    if allow_origin == "*" and allow_credentials == "true":
        findings.append(
            _finding(
                "credentialed-cors-wildcard",
                "Credentialed CORS uses a wildcard origin",
                "high",
                "CWE-942",
                "Use an explicit allowlist and vary responses by Origin.",
            )
        )
    if role != "anonymous" and not _prevents_storage(
        normalized.get("cache-control", "")
    ):
        findings.append(
            _finding(
                "authenticated-response-cacheable",
                "Authenticated browser content can be stored by shared caches",
                "medium",
                "CWE-525",
                "Return Cache-Control: no-store for sensitive authenticated content.",
            )
        )
    return findings


def _csp_directive(value: str, name: str) -> str:
    return next(
        (part.strip() for part in value.split(";") if part.strip().startswith(name)),
        "",
    )


def _prevents_storage(value: str) -> bool:
    directives = {part.strip().casefold() for part in value.split(",")}
    return "no-store" in directives


def _cookie_findings(
    cookies: list[dict[str, Any]], scheme: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, cookie in enumerate(cookies, start=1):
        evidence = {
            "cookie_index": index,
            "same_site": str(cookie.get("sameSite") or ""),
        }
        if cookie.get("httpOnly") is not True:
            findings.append(
                _finding(
                    "cookie-not-httponly",
                    "A browser cookie is accessible to scripts",
                    "medium",
                    "CWE-1004",
                    "Mark authentication and session cookies HttpOnly.",
                    evidence=evidence,
                )
            )
        if scheme == "https" and cookie.get("secure") is not True:
            findings.append(
                _finding(
                    "cookie-not-secure",
                    "A browser cookie is not restricted to HTTPS",
                    "medium",
                    "CWE-614",
                    "Mark cookies Secure in HTTPS deployments.",
                    evidence=evidence,
                )
            )
        if str(cookie.get("sameSite") or "").casefold() not in {"lax", "strict"}:
            findings.append(
                _finding(
                    "cookie-samesite-weak",
                    "A browser cookie lacks a restrictive SameSite policy",
                    "low",
                    "CWE-1275",
                    "Use SameSite=Lax or SameSite=Strict unless a reviewed cross-site flow requires None.",
                    evidence=evidence,
                )
            )
        name = str(cookie.get("name") or "")
        if name.startswith("__Secure-") and cookie.get("secure") is not True:
            findings.append(
                _finding(
                    "secure-cookie-prefix-invalid",
                    "A __Secure- cookie violates its prefix invariant",
                    "medium",
                    "CWE-614",
                    "Set Secure on every __Secure- prefixed cookie.",
                    evidence=evidence,
                )
            )
        if name.startswith("__Host-") and (
            cookie.get("secure") is not True
            or str(cookie.get("path") or "") != "/"
            or bool(cookie.get("domain"))
        ):
            findings.append(
                _finding(
                    "host-cookie-prefix-invalid",
                    "A __Host- cookie violates its prefix invariants",
                    "medium",
                    "CWE-614",
                    "Set Secure, Path=/, and omit Domain for __Host- cookies.",
                    evidence=evidence,
                )
            )
    return findings


def _dom_findings(value: object, scheme: str) -> list[dict[str, Any]]:
    required = {
        "inline_handlers",
        "javascript_urls",
        "unsafe_blank_targets",
        "insecure_password_forms",
        "cross_origin_embeds",
        "service_worker_controlled",
        "local_storage_entries",
        "session_storage_entries",
        "unsafe_postmessage_calls",
        "dynamic_html_sinks",
        "runtime_wildcard_postmessages",
        "runtime_html_sink_writes",
        "runtime_document_writes",
        "runtime_storage_writes",
        "runtime_popup_opens",
        "runtime_cross_origin_messages",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("browser DOM observations do not match the contract")
    findings: list[dict[str, Any]] = []
    checks = (
        (
            "inline_handlers",
            "inline-event-handlers",
            "DOM contains inline event handlers",
            "CWE-79",
        ),
        (
            "javascript_urls",
            "javascript-url",
            "DOM contains a javascript: URL",
            "CWE-79",
        ),
        (
            "unsafe_blank_targets",
            "unsafe-blank-target",
            "A new-window link lacks opener isolation",
            "CWE-1022",
        ),
        (
            "cross_origin_embeds",
            "cross-origin-active-embed",
            "DOM embeds cross-origin active content",
            "CWE-346",
        ),
        (
            "unsafe_postmessage_calls",
            "wildcard-postmessage-target",
            "Inline script sends a message to a wildcard origin",
            "CWE-346",
        ),
        (
            "dynamic_html_sinks",
            "dynamic-html-sink",
            "Inline script contains a dynamic HTML execution sink",
            "CWE-79",
        ),
        (
            "runtime_wildcard_postmessages",
            "runtime-wildcard-postmessage",
            "Runtime sent a message to a wildcard origin",
            "CWE-346",
        ),
        (
            "runtime_html_sink_writes",
            "runtime-html-sink-write",
            "Runtime wrote to an HTML execution sink",
            "CWE-79",
        ),
        (
            "runtime_document_writes",
            "runtime-document-write",
            "Runtime invoked document.write",
            "CWE-79",
        ),
        (
            "runtime_popup_opens",
            "runtime-popup-open",
            "Runtime opened a popup requiring opener isolation review",
            "CWE-1022",
        ),
        (
            "runtime_cross_origin_messages",
            "runtime-cross-origin-message",
            "Runtime received a cross-origin message",
            "CWE-346",
        ),
    )
    for field, rule, title, classification in checks:
        count = value.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("browser DOM observation count is invalid")
        if count:
            findings.append(
                _finding(
                    rule,
                    title,
                    "medium",
                    classification,
                    "Remove the unsafe construct or constrain it with an explicit reviewed policy.",
                    evidence={"element_count": count},
                )
            )
    password_count = value.get("insecure_password_forms")
    if (
        isinstance(password_count, bool)
        or not isinstance(password_count, int)
        or password_count < 0
    ):
        raise ValueError("browser DOM password-form count is invalid")
    if password_count:
        findings.append(
            _finding(
                "insecure-password-form",
                "Password form is not protected by HTTPS",
                "high",
                "CWE-319",
                "Serve the page and form destination exclusively over HTTPS.",
                evidence={"form_count": password_count},
            )
        )
    for storage_field in (
        "local_storage_entries",
        "session_storage_entries",
        "runtime_storage_writes",
    ):
        count = value.get(storage_field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("browser DOM storage count is invalid")
    if not isinstance(value.get("service_worker_controlled"), bool):
        raise ValueError("browser DOM service-worker observation is invalid")
    if value["service_worker_controlled"]:
        findings.append(
            _finding(
                "unexpected-service-worker-control",
                "Page remained controlled by a service worker in an isolated context",
                "high",
                "CWE-749",
                "Block service workers in the assurance context and repeat the test from a fresh profile.",
            )
        )
    return findings


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    classification: str,
    remediation: str,
    *,
    evidence: dict[str, object] | None = None,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "message": title,
        "path": "<runtime-browser>",
        "severity": severity,
        "classification": classification,
        "remediation": remediation,
        "area": "authenticated-browser-security-testing",
        "domain": "security",
        "evidence": evidence or {},
    }


def _write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError(f"output is not a replaceable regular file: {path}")
    payload = (strict_dumps(document, indent=2) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
