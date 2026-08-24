from __future__ import annotations

import secrets
import threading
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit

import pytest

from companion.browser_security import inspect_browser_surface, loopback_target


class _HardenedHandler(BaseHTTPRequestHandler):
    sessions: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        target = urlsplit(self.path)
        query = parse_qs(target.query)
        if target.path == "/login":
            role = query.get("role", [""])[0]
            if role not in {"tenant-a", "tenant-b"}:
                self.send_error(400)
                return
            token = secrets.token_urlsafe(32)
            self.sessions[token] = role
            self._page(
                f"<!doctype html><title>signed in</title><p>{role}</p>".encode(),
                cookie=f"session={token}; Path=/; HttpOnly; SameSite=Strict",
            )
            return
        if target.path == "/public":
            self._page(b"<!doctype html><title>public</title><p>ready</p>")
            return
        role = self._authenticated_role()
        requested_tenant = query.get("tenant", [role or ""])[0]
        if role is None:
            self.send_error(401)
            return
        if requested_tenant != role:
            self.send_error(403)
            return
        self._page(
            f"<!doctype html><title>browser canary</title><p data-tenant='{role}'>ready</p>".encode()
        )

    def _authenticated_role(self) -> str | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        session = cookie.get("session")
        return self.sessions.get(session.value) if session else None

    def _page(self, body: bytes, *, cookie: str = "") -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; require-trusted-types-for 'script'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("PYSEC_RUN_LIVE_INTEGRATION") != "1",
    reason="live integration lane is opt-in",
)
@pytest.mark.parametrize("browser_name", ["chromium", "firefox", "webkit"])
@pytest.mark.parametrize("role", ["anonymous", "tenant-a", "tenant-b"])
def test_real_browser_security_matrix(
    socket_enabled: None,
    tmp_path: Path,
    browser_name: str,
    role: str,
) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HardenedHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        if role == "anonymous":
            target = loopback_target(f"{origin}/public")
            findings = inspect_browser_surface(target, browser_name=browser_name)
        else:
            from companion.browser_security import _inspect_browser_surface
            from playwright.sync_api import sync_playwright

            state = tmp_path / f"{role}.json"
            with sync_playwright() as playwright:
                browser = getattr(playwright, browser_name).launch(headless=True)
                authenticated = browser.new_context(service_workers="block")
                response = authenticated.new_page().goto(
                    f"{origin}/login?role={role}", wait_until="networkidle"
                )
                assert response is not None and response.status == 200
                authenticated.storage_state(path=state)
                cross_tenant = "tenant-b" if role == "tenant-a" else "tenant-a"
                denied = authenticated.new_page().goto(
                    f"{origin}/?tenant={cross_tenant}", wait_until="domcontentloaded"
                )
                assert denied is not None and denied.status == 403
                browser.close()
            target = loopback_target(f"{origin}/?tenant={role}")
            findings, _, canary = _inspect_browser_surface(
                target,
                browser_name=browser_name,
                role=role,
                storage_state=state,
            )
            assert canary is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert findings == []
