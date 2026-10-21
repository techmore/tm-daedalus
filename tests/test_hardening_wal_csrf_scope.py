"""WAL/busy timeout, cross-site mutation guard, and bridge scope enforcement."""
import importlib.util
import os
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
from sqlalchemy import event

from daedalus import db as daedalus_db
from daedalus import server
from daedalus.agent import enroll, local_scan_target_refusal, parse_authorized_networks

try:
    from . import test_agent_bridge as bridge_fixtures
    from . import test_cis_pdf_flow as fixtures
except ImportError:
    import test_agent_bridge as bridge_fixtures
    import test_cis_pdf_flow as fixtures

ROOT = Path(__file__).resolve().parents[1]


class SQLiteConfigurationTests(unittest.TestCase):
    def test_connection_gets_wal_busy_timeout_and_foreign_keys(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(daedalus_db, "DATABASE_URL", "sqlite:///" + directory + "/x.db"):
            connection = sqlite3.connect(Path(directory) / "x.db")
            daedalus_db.configure_sqlite_connection(connection)
            pragma = lambda name: connection.execute("PRAGMA " + name).fetchone()[0]
            self.assertEqual(pragma("journal_mode"), "wal")
            self.assertEqual(pragma("busy_timeout"), daedalus_db.SQLITE_BUSY_TIMEOUT_MS)
            self.assertEqual(pragma("foreign_keys"), 1)
            connection.close()

    def test_application_engine_uses_the_listener(self):
        if daedalus_db.engine.dialect.name == "sqlite":
            self.assertTrue(event.contains(daedalus_db.engine, "connect", daedalus_db.configure_sqlite_connection))

    def test_backup_of_a_wal_database_is_one_self_contained_file(self):
        spec = importlib.util.spec_from_file_location("backup_data_under_test", ROOT / "scripts" / "backup_data.py")
        backup = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(backup)
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            live = sqlite3.connect(data / "daedalus.db")
            live.execute("PRAGMA journal_mode=WAL")
            live.execute("CREATE TABLE t (v TEXT)")
            live.execute("INSERT INTO t VALUES ('kept')")
            live.commit()  # still held open: rows live in the -wal file
            with patch.object(backup, "DATA_DIR", data), patch.object(backup, "BACKUP_DIR", data / "backups"), \
                    patch.object(backup, "DATABASE", data / "daedalus.db"), patch.object(backup, "REPORTS", data / "reports"):
                self.assertEqual(backup.main(), 0)
            live.close()
            archive = next((data / "backups").glob("daedalus-data-*.tar.gz"))
            with tarfile.open(archive) as bundle:
                names = bundle.getnames()
                bundle.extract("daedalus.db", data / "out", filter="data")
            self.assertFalse([name for name in names if name.endswith(("-wal", "-shm"))])
            restored = sqlite3.connect(data / "out" / "daedalus.db")
            self.assertEqual(restored.execute("SELECT v FROM t").fetchall(), [("kept",)])
            self.assertEqual(restored.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            restored.close()


class CrossSiteMutationTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown

    def test_cross_site_cookie_session_writes_are_blocked_including_put(self):
        self.assertIn("daedalus_session", "; ".join(c.name for c in self.client.cookies.jar))
        for method, path in (("post", "/api/cis/api-key"), ("delete", "/api/cis/api-key"),
                             ("put", "/api/external-checks/dns/schedule")):
            for headers in ({"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"},
                            {"Origin": "https://evil.example"}, {"Origin": "null"}):
                with self.subTest(method=method, headers=headers):
                    kwargs = {"json": {"enabled": True, "interval_hours": 24}} if method == "put" else {}
                    response = getattr(self.client, method)(path, headers=headers, **kwargs)
                    self.assertEqual(response.status_code, 403, response.text)

    def test_blocked_request_has_no_side_effect(self):
        self.client.post("/api/cis/api-key", headers={"Origin": "https://evil.example"})
        self.assertFalse(self.client.get("/api/cis/status").json()["key_configured"])

    def test_same_origin_and_plain_clients_keep_working(self):
        host = self.client.base_url.host
        for headers in ({}, {"Sec-Fetch-Site": "same-origin"}, {"Sec-Fetch-Site": "none"},
                        {"Origin": "http://" + host}, {"Origin": "http://" + host, "Sec-Fetch-Site": "same-origin"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.client.post("/api/cis/api-key", headers=headers).status_code, 200)

    def test_bearer_and_keyed_requests_without_session_are_not_blocked(self):
        key = self.client.post("/api/cis/api-key").json()["api_key"]
        self.client.cookies.clear()
        response = self.client.post("/api/cis/client/heartbeat", json={"device_identifier": "d"},
                                    headers={"X-API-Key": key, "Origin": "https://elsewhere.example", "Sec-Fetch-Site": "cross-site"})
        self.assertNotEqual(response.status_code, 403, response.text)  # 404: no device yet, not a CSRF block
        scanner = self.client.post("/api/agents/1/heartbeat", json={},
                                   headers={"Authorization": "Bearer nope", "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(scanner.status_code, 401)


class BridgeScopeTests(unittest.TestCase):
    setUp = bridge_fixtures.NmapUIBridgeTelemetryTests.setUp

    def bridge(self, config_extra=None):
        bridge = bridge_fixtures.NmapUIBridgeTelemetryTests.make_bridge(self)
        return bridge

    def run_scan(self, bridge, target):
        self.command_id = getattr(self, "command_id", 50) + 1
        bridge.nmapui_connected.set()
        request = httpx.Request("GET", "https://fixture.example.org/next")
        bridge._request = Mock(return_value=httpx.Response(200, request=request, json={
            "command": {"id": self.command_id, "action": "start_scan", "target": target}}))
        bridge.sio.emit = Mock()
        bridge._send_command_result = Mock()
        bridge._run_one_command()
        return bridge

    def test_scope_function(self):
        scope = parse_authorized_networks(["10.20.0.0/24", "fd00::/112"])
        self.assertIsNone(local_scan_target_refusal("10.20.0.5", scope))
        self.assertIsNone(local_scan_target_refusal("10.20.0.0/25", scope))
        self.assertIsNotNone(local_scan_target_refusal("10.21.0.5", scope))
        self.assertIsNotNone(local_scan_target_refusal("10.20.0.0/16", scope))
        self.assertIsNotNone(local_scan_target_refusal("192.168.1.1", []))
        self.assertIsNotNone(local_scan_target_refusal("8.8.8.8", scope))
        self.assertIsNotNone(local_scan_target_refusal("192.168.1.1", None))
        self.assertIsNone(parse_authorized_networks("10.0.0.0/8"))
        self.assertIsNone(parse_authorized_networks(["not-a-network"]))

    def test_out_of_scope_target_is_not_forwarded(self):
        bridge = self.bridge()
        bridge.authorized_networks = parse_authorized_networks(["10.20.0.0/24"])
        self.run_scan(bridge, "10.99.0.5")
        bridge.sio.emit.assert_not_called()
        self.assertEqual(bridge._send_command_result.call_args.args[:2], (51, "failed"))

    def test_in_scope_target_is_forwarded(self):
        bridge = self.bridge()
        bridge.authorized_networks = parse_authorized_networks(["10.20.0.0/24"])
        def refreshed():
            bridge.authorized_networks = parse_authorized_networks(["10.20.0.0/24"])
        bridge._heartbeat = Mock(side_effect=refreshed)
        self.run_scan(bridge, "10.20.0.7")
        bridge.sio.emit.assert_called_once()

    def test_scope_widened_after_enrollment_is_picked_up_before_refusing(self):
        bridge = self.bridge()
        bridge.authorized_networks = parse_authorized_networks([])  # enrolled without a scope

        def widened():
            bridge.authorized_networks = parse_authorized_networks(["127.0.0.1/32"])

        bridge._heartbeat = Mock(side_effect=widened)
        self.run_scan(bridge, "127.0.0.1")
        bridge._heartbeat.assert_called_once()
        bridge.sio.emit.assert_called_once()

    def test_still_refused_after_refresh_when_portal_scope_excludes_target(self):
        bridge = self.bridge()
        bridge.authorized_networks = parse_authorized_networks([])
        bridge._heartbeat = Mock()
        self.run_scan(bridge, "10.5.5.5")
        bridge.sio.emit.assert_not_called()
        self.assertEqual(bridge._send_command_result.call_args.args[:2], (51, "failed"))

    def test_public_target_does_not_trigger_a_refresh(self):
        bridge = self.bridge()
        bridge.authorized_networks = parse_authorized_networks([])
        bridge._heartbeat = Mock()
        self.run_scan(bridge, "8.8.8.8")
        bridge._heartbeat.assert_not_called()

    def test_scope_is_read_from_enrollment_config_and_refreshed_by_heartbeat(self):
        bridge = self.bridge()
        self.assertIsNone(bridge.authorized_networks)  # legacy configuration is not authorization
        bridge.config["authorized_networks"] = ["10.20.0.0/24"]
        bridge._read_nmapui_health = Mock(return_value={})
        bridge._read_nmapui_activity = Mock(return_value=None)
        bridge._read_delivery = Mock(return_value=None)
        bridge._request = Mock(return_value=httpx.Response(200, request=httpx.Request("POST", "https://x.example/h"),
                               json={"ok": True, "authorized_networks": ["172.16.4.0/24"]}))
        bridge._heartbeat()
        self.assertEqual([str(n) for n in bridge.authorized_networks], ["172.16.4.0/24"])
        bridge._request = Mock(return_value=httpx.Response(200, request=httpx.Request("POST", "https://x.example/h"), json={"ok": True}))
        bridge._heartbeat()  # an older portal cannot establish current authorization
        self.assertIsNone(bridge.authorized_networks)

    def test_unknown_scope_requires_successful_current_authorization(self):
        for response in (None, [], ["10.99.0.0/24"]):
            with self.subTest(scope=response):
                bridge = self.bridge()
                bridge._heartbeat = Mock(side_effect=lambda: setattr(bridge, "authorized_networks", parse_authorized_networks(response)))
                self.run_scan(bridge, "10.20.0.1")
                bridge._heartbeat.assert_called_once()
                bridge.sio.emit.assert_not_called()
                self.assertEqual(bridge._send_command_result.call_args.args[:2], (self.command_id, "failed"))

    def test_cached_grant_cannot_survive_offline_portal_or_revocation(self):
        for refresh in (httpx.ConnectError("offline"), OSError("offline"), None):
            with self.subTest(refresh=refresh):
                bridge = self.bridge()
                bridge.authorized_networks = parse_authorized_networks(["10.20.0.0/24"])
                bridge._heartbeat = Mock(side_effect=refresh)
                self.run_scan(bridge, "10.20.0.1")
                bridge.sio.emit.assert_not_called()

    def test_legacy_enrollment_can_scan_after_authorized_refresh(self):
        bridge = self.bridge()
        self.assertIsNone(bridge.authorized_networks)
        bridge._heartbeat = Mock(side_effect=lambda: setattr(bridge, "authorized_networks", parse_authorized_networks(["127.0.0.1/32"])))
        self.run_scan(bridge, "127.0.0.1")
        bridge.sio.emit.assert_called_once()

    def test_malformed_heartbeat_scope_invalidates_old_grant(self):
        for body in ({}, {"authorized_networks": "10.20.0.0/24"}, {"authorized_networks": ["broken"]}, []):
            with self.subTest(body=body):
                bridge = self.bridge()
                bridge.authorized_networks = parse_authorized_networks(["10.20.0.0/24"])
                bridge._read_nmapui_health = Mock(return_value={})
                bridge._read_nmapui_activity = Mock(return_value=None)
                bridge._read_delivery = Mock(return_value=None)
                bridge._request = Mock(return_value=httpx.Response(200, request=httpx.Request("POST", "https://x.example/h"), json=body))
                bridge._heartbeat()
                self.assertIsNone(bridge.authorized_networks)

    def test_enroll_persists_authorized_networks(self):
        body = {"agent_id": 3, "agent_name": "n", "organization": "o", "agent_token": "t" * 20,
                "authorized_networks": ["10.1.0.0/24"]}
        with patch("daedalus.agent.httpx.post", return_value=httpx.Response(200, json=body, request=httpx.Request("POST", "https://p.example"))):
            saved = enroll("https://p.example", "n", "c" * 16)
        self.assertEqual(saved["authorized_networks"], ["10.1.0.0/24"])


class PortalHeartbeatScopeTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown
    create_scanner = fixtures.CISReportPDFFlowTests.create_scanner

    def test_heartbeat_returns_current_authorized_networks(self):
        agent_id, _ = self.create_scanner()
        self.client.put(f"/api/agents/{agent_id}/network-scope", json={"authorized_networks": ["10.30.0.0/24"]})
        body = self.client.post(f"/api/agents/{agent_id}/heartbeat", headers={"Authorization": "Bearer test-scanner-token"}, json={}).json()
        self.assertEqual(body["authorized_networks"], ["10.30.0.0/24"])


if __name__ == "__main__":
    unittest.main()
