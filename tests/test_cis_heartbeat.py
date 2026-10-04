import unittest
from datetime import timedelta
from sqlalchemy import select, func, create_engine, text, inspect
from daedalus import server
from daedalus.models import CISDevice, CISReport, Organization, CISAPIKey
try:
    from . import test_cis_pdf_flow as fixtures
except ImportError:
    import test_cis_pdf_flow as fixtures


class CISHeartbeatTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown

    def enroll(self):
        key = self.client.post('/api/cis/api-key').json()['api_key']
        headers = {'X-API-Key': key}
        payload = {'device_uuid': 'heartbeat-fixture', 'report_id': 'heartbeat-report-1',
                   'timestamp': '2026-09-29T12:00:00Z',
                   'system_info': {'hostname': 'Heartbeat fixture', 'os_version': '27.0'},
                   'results': [{'id': 'one', 'category': 'macos', 'description': 'Fixture', 'status': 'pass'}]}
        response = self.client.post('/api/cis/report', headers=headers, json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        return headers

    def test_heartbeat_updates_presence_without_new_report_or_score(self):
        headers = self.enroll()
        before = self.client.get('/api/cis/status').json()['devices'][0]
        self.assertEqual(before['client_state'], 'unknown')
        response = self.client.post('/api/cis/client/heartbeat', headers=headers, json={'device_identifier': 'heartbeat-fixture'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        after = self.client.get('/api/cis/status').json()['devices'][0]
        self.assertEqual(after['client_state'], 'online')
        self.assertEqual(after['last_seen_at'], before['last_seen_at'])
        with self.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count(CISReport.id))), 1)
            report = db.scalar(select(CISReport))
            self.assertEqual(report.summary['pass'], 1)
            device = db.scalar(select(CISDevice))
            device.last_client_heartbeat_at = server.utcnow() - timedelta(minutes=16)
            db.commit()
        self.assertEqual(self.client.get('/api/cis/status').json()['devices'][0]['client_state'], 'offline')

    def test_unknown_endpoint_and_revoked_key_cannot_check_in(self):
        headers = self.enroll()
        unknown = self.client.post('/api/cis/client/heartbeat', headers=headers, json={'device_identifier': 'other-device'})
        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(self.client.post('/api/cis/client/heartbeat', headers=headers, json={'device_identifier': ' ', 'score': 100}).status_code, 422)
        self.client.delete('/api/cis/api-key')
        self.assertEqual(self.client.post('/api/cis/client/heartbeat', headers=headers, json={'device_identifier': 'heartbeat-fixture'}).status_code, 401)
        with self.session_factory() as db:
            self.assertIsNone(db.scalar(select(CISDevice)).last_client_heartbeat_at)

    def test_other_workspace_key_cannot_update_existing_device(self):
        self.enroll()
        now = server.utcnow()
        key = 'other-workspace-heartbeat-fixture-key'
        with self.session_factory() as db:
            org = Organization(name='Other', slug='other-presence', domain='other-presence.example', verification_status='verified', created_at=now)
            db.add(org); db.flush()
            db.add(CISAPIKey(organization_id=org.id, token_hash=server.token_digest(key), key_hint=key[-4:], created_at=now))
            db.commit()
        response = self.client.post('/api/cis/client/heartbeat', headers={'X-API-Key': key}, json={'device_identifier': 'heartbeat-fixture'})
        self.assertEqual(response.status_code, 404)
        with self.session_factory() as db:
            self.assertIsNone(db.scalar(select(CISDevice)).last_client_heartbeat_at)

    def test_presence_migration_is_additive_and_idempotent(self):
        engine = create_engine('sqlite://')
        with engine.begin() as connection:
            connection.execute(text('CREATE TABLE cis_devices (id INTEGER PRIMARY KEY, last_seen_at TIMESTAMP)'))
            server.ensure_cis_presence_columns(connection)
            server.ensure_cis_presence_columns(connection)
            self.assertIn('last_client_heartbeat_at', {c['name'] for c in inspect(connection).get_columns('cis_devices')})
        engine.dispose()
