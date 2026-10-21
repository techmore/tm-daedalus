"""Review follow-up: link-local scan ranges and CIS upload key expiry / last use."""
import unittest
from datetime import timedelta

from sqlalchemy import create_engine, text

from daedalus import server
from daedalus.agent import private_scan_target_refusal
from daedalus.models import CISAPIKey

try:
    from . import test_cis_pdf_flow as fixtures
except ImportError:
    import test_cis_pdf_flow as fixtures


class ScanRangeTests(unittest.TestCase):
    def test_link_local_is_not_a_scan_target_or_scope_but_loopback_and_private_are(self):
        for value in ("169.254.169.254", "169.254.0.0/16", "fe80::1", "fe80::/10"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    server.validate_internal_scan_target(value)
                with self.assertRaises(ValueError):
                    server.validate_scanner_network_scopes([value])
                self.assertIsNotNone(private_scan_target_refusal(value))
        for value in ("127.0.0.1", "127.0.0.0/30", "10.1.2.0/24", "192.168.1.5", "fd00::/112"):
            with self.subTest(value=value):
                self.assertEqual(server.validate_internal_scan_target(value), value)
                self.assertIsNone(private_scan_target_refusal(value))


class CISKeyLifecycleTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown

    def heartbeat(self, key):
        return self.client.post("/api/cis/client/heartbeat", json={"device_identifier": "d"}, headers={"X-API-Key": key})

    def stored(self):
        with self.session_factory() as db:
            return db.query(CISAPIKey).one()

    def test_default_key_never_expires_and_records_last_use(self):
        issued = self.client.post("/api/cis/api-key").json()
        self.assertIsNone(issued["expires_at"])
        self.assertIsNone(self.client.get("/api/cis/status").json()["key_last_used_at"])
        self.assertEqual(self.heartbeat(issued["api_key"]).status_code, 404)  # authenticated; no device yet
        status = self.client.get("/api/cis/status").json()
        self.assertTrue(status["key_last_used_at"].endswith("Z"))
        self.assertIsNone(status["key_expires_at"])
        self.assertFalse(status["key_expired"])

    def test_last_use_is_written_at_most_once_a_minute(self):
        key = self.client.post("/api/cis/api-key").json()["api_key"]
        self.heartbeat(key)
        first = self.stored().last_used_at
        self.heartbeat(key)
        self.assertEqual(self.stored().last_used_at, first)
        with self.session_factory() as db:
            row = db.query(CISAPIKey).one()
            row.last_used_at = server.utcnow() - timedelta(minutes=2)
            db.commit()
        self.heartbeat(key)
        self.assertGreater(self.stored().last_used_at, server.utcnow() - timedelta(minutes=1))

    def test_optional_expiry_is_enforced_and_rotation_resets_it(self):
        issued = self.client.post("/api/cis/api-key", json={"expires_in_days": 30}).json()
        self.assertTrue(issued["expires_at"].endswith("Z"))
        self.assertEqual(self.heartbeat(issued["api_key"]).status_code, 404)
        with self.session_factory() as db:
            row = db.query(CISAPIKey).one()
            row.expires_at = server.utcnow() - timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.heartbeat(issued["api_key"]).status_code, 401)
        self.assertTrue(self.client.get("/api/cis/status").json()["key_expired"])
        rotated = self.client.post("/api/cis/api-key").json()
        self.assertTrue(rotated["rotated"])
        self.assertIsNone(rotated["expires_at"])
        self.assertIsNone(self.stored().last_used_at)
        self.assertEqual(self.heartbeat(rotated["api_key"]).status_code, 404)

    def test_invalid_expiry_is_rejected(self):
        for body in ({"expires_in_days": 0}, {"expires_in_days": 366}, {"expires_in_days": "soon"}, {"other": 1}):
            with self.subTest(body=body):
                self.assertEqual(self.client.post("/api/cis/api-key", json=body).status_code, 422)

    def test_existing_database_gains_the_columns_without_losing_keys(self):
        engine = create_engine("sqlite://")
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE cis_api_keys (id INTEGER PRIMARY KEY, token_hash TEXT)"))
            connection.execute(text("INSERT INTO cis_api_keys VALUES (1, 'h')"))
            server.ensure_cis_key_columns(connection)
            server.ensure_cis_key_columns(connection)  # idempotent
            row = connection.execute(text("SELECT token_hash, expires_at, last_used_at FROM cis_api_keys")).one()
        self.assertEqual(tuple(row), ("h", None, None))


if __name__ == "__main__":
    unittest.main()
