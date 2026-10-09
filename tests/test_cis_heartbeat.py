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

    def test_saved_endpoint_reads_identify_workspace_and_observation_time(self):
        self.enroll()
        with self.session_factory() as db:
            organization_id = db.scalar(select(Organization.id))
        for suffix in ("status", "profiles", "reports", "changes"):
            with self.subTest(endpoint=suffix):
                response = self.client.get("/api/cis/" + suffix)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertEqual(response.json()["organization_id"], organization_id)
                if suffix == "status":
                    self.assertTrue(response.json()["observed_at"].endswith("Z"))
        self.client.cookies.clear()
        for suffix in ("status", "profiles", "reports", "changes"):
            self.assertEqual(self.client.get("/api/cis/" + suffix).status_code, 401)

    def test_saved_endpoint_reads_change_scope_without_exposing_previous_workspace(self):
        self.enroll()
        before = self.client.get("/api/cis/status").json()
        profiles = self.client.get("/api/cis/profiles").json()["profiles"]
        report_id = self.client.get("/api/cis/reports").json()["reports"][0]["id"]
        created = self.client.post("/api/workspaces", json={"name": "Other endpoint fixture", "domain": "other-endpoint.example"})
        self.assertEqual(created.status_code, 200, created.text)
        status = self.client.get("/api/cis/status").json()
        self.assertNotEqual(status["organization_id"], before["organization_id"])
        self.assertEqual(status["devices"], [])
        self.assertFalse(status["key_configured"])
        for endpoint, field in (("profiles", "profiles"), ("reports", "reports"), ("changes", "changes")):
            body = self.client.get("/api/cis/" + endpoint).json()
            self.assertEqual(body["organization_id"], status["organization_id"])
            self.assertEqual(body[field], [])
        self.assertEqual(self.client.get(f"/api/cis/reports/{report_id}").status_code, 404)
        for profile in profiles:
            self.assertEqual(self.client.get(profile["download_url"]).status_code, 404)

    def test_heartbeat_updates_presence_without_new_report_or_score(self):
        headers = self.enroll()
        before = self.client.get('/api/cis/status').json()['devices'][0]
        self.assertEqual(before['client_state'], 'unknown')
        self.assertEqual(before['latest_assessment_summary']['pass'], 1)
        response = self.client.post('/api/cis/client/heartbeat', headers=headers, json={'device_identifier': 'heartbeat-fixture'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        after = self.client.get('/api/cis/status').json()['devices'][0]
        self.assertEqual(after['client_state'], 'online')
        self.assertEqual(self.client.get('/api/cis/status').json()['online_client_count'], 1)
        self.assertEqual(after['last_seen_at'], before['last_seen_at'])
        with self.session_factory() as db:
            self.assertEqual(db.scalar(select(func.count(CISReport.id))), 1)
            report = db.scalar(select(CISReport))
            self.assertEqual(report.summary['pass'], 1)
            device = db.scalar(select(CISDevice))
            device.last_client_heartbeat_at = server.utcnow() - timedelta(minutes=16)
            db.commit()
        self.assertEqual(self.client.get('/api/cis/status').json()['devices'][0]['client_state'], 'offline')
        self.assertEqual(self.client.get('/api/cis/status').json()['online_client_count'], 0)

    def test_fresh_checkin_does_not_make_old_collection_current(self):
        headers = self.enroll()
        with self.session_factory() as db:
            db.scalar(select(CISReport)).collected_at = server.utcnow() - timedelta(days=3)
            db.commit()
        self.client.post('/api/cis/client/heartbeat', headers=headers, json={'device_identifier':'heartbeat-fixture'})
        status = self.client.get('/api/cis/status').json()
        self.assertEqual(status['devices'][0]['client_state'], 'online')
        self.assertEqual(status['devices'][0]['assessment_state'], 'stale')
        self.assertEqual(status['assessment_counts'], {'current':0, 'stale':1, 'unknown':0, 'missing':0})

    def test_collection_recency_handles_current_future_and_missing_evidence(self):
        self.enroll()
        for offset, expected in [(timedelta(hours=-1), 'current'), (timedelta(days=1), 'unknown')]:
            with self.session_factory() as db:
                db.scalar(select(CISReport)).collected_at = server.utcnow() + offset
                db.commit()
            status = self.client.get('/api/cis/status').json()
            self.assertEqual(status['devices'][0]['assessment_state'], expected)
            self.assertEqual(status['assessment_counts'][expected], 1)
        with self.session_factory() as db:
            db.delete(db.scalar(select(CISReport)))
            db.commit()
        status = self.client.get('/api/cis/status').json()
        self.assertEqual(status['devices'][0]['assessment_state'], 'missing')
        self.assertIsNone(status['devices'][0]['latest_report_id'])
        self.assertIsNone(status['devices'][0]['latest_assessment_summary'])
        self.assertEqual(status['assessment_counts']['missing'], 1)

    def test_late_upload_does_not_replace_more_recent_collection(self):
        self.enroll()
        with self.session_factory() as db:
            first = db.scalar(select(CISReport))
            first.collected_at = server.utcnow() - timedelta(hours=1)
            first_id = first.id
            db.add(CISReport(organization_id=first.organization_id, device_id=first.device_id,
                client_report_hash='f'*64, profile_slug=first.profile_slug, profile_version=first.profile_version,
                collected_at=server.utcnow()-timedelta(days=3), summary=first.summary, results=first.results, created_at=server.utcnow()))
            db.commit()
        status = self.client.get('/api/cis/status').json()
        self.assertEqual(status['devices'][0]['latest_report_id'], first_id)
        self.assertEqual(status['devices'][0]['assessment_state'], 'current')
        self.assertEqual(status['assessment_counts']['current'], 1)

    def test_coverage_counts_include_devices_beyond_visible_list(self):
        self.enroll()
        with self.session_factory() as db:
            existing = db.scalar(select(CISDevice))
            now = server.utcnow()
            for index in range(250):
                db.add(CISDevice(organization_id=existing.organization_id, device_fingerprint=f'{index:064x}',
                    name=f'Unassessed fixture {index}', first_seen_at=now, last_seen_at=now))
            db.commit()
        status = self.client.get('/api/cis/status').json()
        self.assertEqual(status['device_count'], 251)
        self.assertEqual(len(status['devices']), 250)
        self.assertTrue(status['devices_truncated'])
        self.assertEqual(status['assessment_counts']['missing'], 250)
        self.assertEqual(sum(status['assessment_counts'].values()), 251)

    def test_future_checkin_is_unknown_and_excluded_from_online_count(self):
        self.enroll()
        with self.session_factory() as db:
            db.scalar(select(CISDevice)).last_client_heartbeat_at = server.utcnow() + timedelta(days=1)
            db.commit()
        status = self.client.get('/api/cis/status').json()
        self.assertEqual(status['devices'][0]['client_state'], 'unknown')
        self.assertEqual(status['online_client_count'], 0)

    def test_missing_summary_keeps_device_status_available(self):
        self.enroll()
        with self.session_factory() as db:
            db.scalar(select(CISReport)).summary = None
            db.commit()
        response = self.client.get('/api/cis/status')
        self.assertEqual(response.status_code, 200)
        device = response.json()['devices'][0]
        self.assertTrue(device['latest_report_id'])
        self.assertTrue(all(value is None for value in device['latest_assessment_summary'].values()))

    def test_each_device_exposes_its_own_latest_assessment(self):
        self.enroll()
        second_summary = {'total': 4, 'pass': 1, 'fail': 1, 'manual': 2, 'error': 0, 'score': 25.0}
        with self.session_factory() as db:
            first = db.scalar(select(CISReport))
            now = server.utcnow()
            second = CISDevice(organization_id=first.organization_id, device_fingerprint='a'*64,
                name='Second endpoint', first_seen_at=now, last_seen_at=now)
            db.add(second)
            db.flush()
            second_id = second.id
            first_device_id = first.device_id
            db.add(CISReport(organization_id=first.organization_id, device_id=second.id,
                client_report_hash='b'*64, profile_slug=first.profile_slug, profile_version=first.profile_version,
                collected_at=now, summary=second_summary, results=[], created_at=now))
            db.commit()
        devices = {device['id']: device for device in self.client.get('/api/cis/status').json()['devices']}
        self.assertEqual(devices[second_id]['latest_assessment_summary'], second_summary)
        self.assertEqual(devices[first_device_id]['latest_assessment_summary']['pass'], 1)
        self.assertEqual(devices[first_device_id]['latest_assessment_summary']['fail'], 0)
        self.assertNotIn('results', devices[second_id])

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
