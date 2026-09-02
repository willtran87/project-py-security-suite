from __future__ import annotations

import unittest

from companion.browser_security import (
    _cookie_findings,
    _header_findings,
    _proxy_websocket,
    loopback_target,
)


class CompanionBrowserSecurityTests(unittest.TestCase):
    def test_target_is_restricted_to_explicit_loopback_http(self) -> None:
        for value in (
            "http://localhost:8000/",
            "http://127.0.0.1:8000/",
            "https://[::1]:8443/",
        ):
            with self.subTest(value=value):
                self.assertEqual(loopback_target(value).scheme, value.split(":", 1)[0])
        for value in (
            "https://example.com/",
            "file:///tmp/app",
            "http://user:password@localhost/",  # pragma: allowlist secret
            "http://localhost/#fragment",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    loopback_target(value)

    def test_header_assertions_are_independent_and_security_classified(self) -> None:
        findings = _header_findings({}, "https")
        rules = {item["rule_id"] for item in findings}
        self.assertEqual(
            rules,
            {
                "missing-content-security-policy",
                "missing-frame-protection",
                "missing-hsts",
                "missing-nosniff",
                "missing-permissions-policy",
                "missing-referrer-policy",
                "weak-cross-origin-opener-policy",
                "weak-cross-origin-resource-policy",
            },
        )
        hardened = _header_findings(
            {
                "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "strict-transport-security": "max-age=31536000",
                "permissions-policy": "camera=(), microphone=(), geolocation=()",
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-resource-policy": "same-origin",
            },
            "https",
        )
        self.assertEqual(hardened, [])

    def test_cookie_assertions_never_retain_cookie_names_or_values(self) -> None:
        findings = _cookie_findings(
            [
                {
                    "name": "named-cookie-sentinel",
                    "value": "must-not-survive",
                    "httpOnly": False,
                    "secure": False,
                    "sameSite": "None",
                }
            ],
            "https",
        )
        rendered = repr(findings)
        self.assertNotIn("named-cookie-sentinel", rendered)
        self.assertNotIn("must-not-survive", rendered)
        self.assertEqual(len(findings), 3)

    def test_websocket_proxy_uses_playwright_python_route_api(self) -> None:
        class Route:
            def __init__(self, url: str = "ws://127.0.0.1:8000/socket") -> None:
                self.url = url
                self.handler: object | None = None
                self.sent: list[object] = []
                self.closed = False
                self.server: Route | None = None

            def connect_to_server(self) -> Route:
                self.server = Route()
                return self.server

            def on_message(self, handler: object) -> None:
                self.handler = handler

            def send(self, message: object) -> None:
                self.sent.append(message)

            def close(self, **_kwargs: object) -> None:
                self.closed = True

        page = Route()
        digests: set[str] = set()
        self.assertTrue(_proxy_websocket(page, digests))
        self.assertIsNotNone(page.server)
        assert page.server is not None
        assert callable(page.handler)
        assert callable(page.server.handler)
        page.handler("client")
        page.server.handler(b"server")
        self.assertEqual(page.server.sent, ["client"])
        self.assertEqual(page.sent, [b"server"])
        self.assertEqual(len(digests), 2)

        external = Route("wss://example.invalid/socket")
        self.assertFalse(_proxy_websocket(external, set()))
        self.assertTrue(external.closed)


if __name__ == "__main__":
    unittest.main()
