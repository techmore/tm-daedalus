"""Regression tests for the remaining 2026-10-19 review findings (docs/CODE-REVIEW-20261019.md items 5-8, 10)."""
import asyncio
import itertools
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from sqlalchemy import select

from daedalus import server, site_icon
from daedalus.models import Agent, ScanEvent
from daedalus.request_limits import BoundedBodyMiddleware

try:
    from . import test_cis_pdf_flow as fixtures
    from .test_production_deployment import ProductionConfigStartupTests
except ImportError:
    import test_cis_pdf_flow as fixtures
    from test_production_deployment import ProductionConfigStartupTests


class DemoLoginProxyTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown

    def test_proxied_requests_cannot_use_the_demo_accounts(self):
        self.client.cookies.clear()
        for header in ("X-Forwarded-For", "Forwarded", "X-Real-IP"):
            for path in ("/dev/login", "/dev/login/member"):
                with self.subTest(header=header, path=path):
                    response = self.client.post(path, headers={header: "203.0.113.9"}, follow_redirects=False)
                    self.assertEqual(response.status_code, 404, response.text)
                    self.assertNotIn("daedalus_session", response.headers.get("set-cookie", ""))
        # A direct loopback request still works.
        self.assertEqual(self.client.post("/dev/login", follow_redirects=False).status_code, 303)

    def test_demo_login_is_hidden_when_demo_mode_is_off(self):
        self.client.cookies.clear()
        with patch.object(server, "DEMO_MODE", False):
            self.assertEqual(self.client.post("/dev/login", follow_redirects=False).status_code, 404)


class PlaceholderSecretTests(unittest.TestCase):
    run_config_import = ProductionConfigStartupTests.run_config_import

    def test_placeholder_session_secret_never_boots_production(self):
        for secret in ("replace-with-at-least-32-random-characters", "change-me-" + "x" * 40, "local-only-" + "y" * 40):
            with self.subTest(secret=secret):
                result = self.run_config_import({
                    "DAEDALUS_SESSION_SECRET": secret,
                    "GOOGLE_CLIENT_ID": "client.apps.googleusercontent.com",
                    "GOOGLE_CLIENT_SECRET": "test-oauth-secret",
                    "DAEDALUS_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii"),
                })
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Set a long, random DAEDALUS_SESSION_SECRET in production", result.stderr)

    def test_placeholder_encryption_key_never_boots_production(self):
        result = self.run_config_import({
            "GOOGLE_CLIENT_ID": "client.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "test-oauth-secret",
            "DAEDALUS_ENCRYPTION_KEY": "replace-with-a-generated-fernet-key=",
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Set DAEDALUS_ENCRYPTION_KEY to a Fernet key in production", result.stderr)

    # ProductionConfigStartupTests keeps proving that a real secret still boots.


class BoundedScannerBodyTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown
    create_scanner = fixtures.CISReportPDFFlowTests.create_scanner
    headers = {"Authorization": "Bearer test-scanner-token", "Content-Type": "application/json"}

    def test_rules_match_only_the_scanner_json_routes(self):
        middleware = BoundedBodyMiddleware(None, (("POST", r"/api/agents/\d+/events", 10),))
        self.assertEqual(middleware.limit_for("POST", "/api/agents/7/events"), 10)
        self.assertIsNone(middleware.limit_for("GET", "/api/agents/7/events"))
        self.assertIsNone(middleware.limit_for("POST", "/api/agents/7/event-artifacts"))
        self.assertIsNone(middleware.limit_for("POST", "/api/agents/x/events"))

    def test_chunked_event_body_is_rejected(self):
        agent_id, _ = self.create_scanner()

        def body():
            for _ in range(8):
                yield b" " * 100_000

        response = self.client.post(f"/api/agents/{agent_id}/events", headers=self.headers, content=body())
        self.assertEqual(response.status_code, 413, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        with self.session_factory() as db:
            self.assertEqual(db.scalars(select(ScanEvent).where(ScanEvent.agent_id == agent_id)).all(), [])

    def test_streaming_stops_at_the_cap_before_the_app_sees_the_body(self):
        # The test client buffers request bodies, so prove the early stop at the ASGI level.
        delivered = []
        seen_by_app = []

        async def app(scope, receive, send):
            while True:
                message = await receive()
                seen_by_app.append(len(message.get("body", b"")))
                if not message.get("more_body"):
                    break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        async def receive():
            delivered.append(1)
            return {"type": "http.request", "body": b"x" * 100, "more_body": True}

        sent = []

        async def send(message):
            sent.append(message)

        middleware = BoundedBodyMiddleware(app, (("POST", r"/events", 250),))
        scope = {"type": "http", "method": "POST", "path": "/events", "headers": []}
        asyncio.run(middleware(scope, receive, send))
        self.assertEqual(len(delivered), 3)  # 300 bytes read, the third chunk crossed the cap
        self.assertEqual(seen_by_app, [100, 100])
        self.assertEqual(sent[0]["status"], 413)
        self.assertIn(b"exceeds 0 KB", sent[1]["body"])

    def test_declared_oversize_body_is_rejected_without_reading(self):
        agent_id, _ = self.create_scanner()
        response = self.client.post(f"/api/agents/{agent_id}/heartbeat", headers={**self.headers, "Content-Length": "9000000"}, content=b"")
        self.assertEqual(response.status_code, 413, response.text)

    def test_normal_heartbeat_and_event_still_succeed(self):
        agent_id, _ = self.create_scanner()
        heartbeat = self.client.post(f"/api/agents/{agent_id}/heartbeat", headers=self.headers, json={"detected_networks": ["192.168.1.0/24"]})
        self.assertEqual(heartbeat.status_code, 200, heartbeat.text)
        event = self.client.post(f"/api/agents/{agent_id}/events", headers=self.headers,
                                 json={"event_name": "scan.completed", "payload": {"hosts": ["x" * 1000] * 100}})
        self.assertEqual(event.status_code, 200, event.text)

    def test_handler_payload_limit_still_applies_inside_the_envelope(self):
        agent_id, _ = self.create_scanner()
        response = self.client.post(f"/api/agents/{agent_id}/events", headers=self.headers,
                                    json={"event_name": "scan.completed", "payload": "p" * 520_000})
        self.assertEqual(response.status_code, 413, response.text)
        self.assertIn("512 KB", response.text)


class HeartbeatDetectedNetworkTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown
    create_scanner = fixtures.CISReportPDFFlowTests.create_scanner

    def test_unsupported_detected_networks_are_dropped_not_fatal(self):
        agent_id, _ = self.create_scanner()
        headers = {"Authorization": "Bearer test-scanner-token"}
        response = self.client.post(f"/api/agents/{agent_id}/heartbeat", headers=headers, json={
            "detected_networks": ["198.18.5.0/24", "10.20.0.111/24", "8.8.8.0/24", "not a network", "192.0.2.0/24", "fe80::1/64"],
        })
        self.assertEqual(response.status_code, 200, response.text)
        with self.session_factory() as db:
            agent = db.get(Agent, agent_id)
            # Link-local ranges are no longer accepted as detected networks (review finding 8).
            self.assertEqual(agent.detected_networks, ["10.20.0.0/24"])
            self.assertEqual(agent.authorized_networks, ["127.0.0.1/32", "192.168.1.0/24"])

    def test_more_than_thirty_two_entries_are_still_rejected(self):
        agent_id, _ = self.create_scanner()
        response = self.client.post(f"/api/agents/{agent_id}/heartbeat", headers={"Authorization": "Bearer test-scanner-token"},
                                    json={"detected_networks": [f"10.{index}.0.0/24" for index in range(33)]})
        self.assertEqual(response.status_code, 422, response.text)

    def test_authorized_scope_validation_is_unchanged(self):
        with self.assertRaises(ValueError):
            server.validate_scanner_network_scopes(["198.18.0.0/15"])
        self.assertEqual(server.accepted_detected_networks(["198.18.0.0/15"]), [])


class SiteIconDeadlineTests(unittest.TestCase):
    def test_candidates_stop_once_the_overall_deadline_passes(self):
        html = b'<link rel="icon" href="/a.png"><link rel="icon" href="/b.png"><link rel="icon" href="/c.png">'
        requested = []
        clock = itertools.chain([100.0], itertools.repeat(200.0))

        def _get(url, allowed, limit, deadline=None):
            requested.append(url)
            self.assertAlmostEqual(deadline, 100.0 + site_icon.OVERALL_DEADLINE_SECONDS)
            return (200, {}, html, url) if url.endswith("/") else (404, {}, b"", url)

        with patch.object(site_icon, "_get", _get), patch.object(site_icon.time, "monotonic", lambda: next(clock)):
            self.assertIsNone(site_icon.fetch_site_icon("example.test"))
        # Only the page was fetched: the clock jumped past the deadline before the first candidate.
        self.assertEqual(requested, ["https://example.test/"])

    def test_remaining_time_bounds_each_socket_timeout(self):
        with patch.object(site_icon.time, "monotonic", lambda: 50.0):
            self.assertEqual(site_icon._remaining(None), site_icon.SOCKET_TIMEOUT_SECONDS)
            self.assertEqual(site_icon._remaining(53.0), 3.0)
            self.assertEqual(site_icon._remaining(500.0), site_icon.SOCKET_TIMEOUT_SECONDS)
            with self.assertRaises(site_icon.ExternalCheckFailure):
                site_icon._remaining(49.0)


if __name__ == "__main__":
    unittest.main()
