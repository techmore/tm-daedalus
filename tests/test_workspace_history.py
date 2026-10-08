"""Retained report/inbox history through normal workspace APIs."""
import unittest
from datetime import timedelta
from fastapi.testclient import TestClient
from sqlalchemy import select
from daedalus import server
from daedalus.models import Membership, Organization, ReportJob, User, WorkspaceNotification, WorkspaceNotificationRead
try:
    from . import test_cis_pdf_flow as fixtures
except ImportError:
    import test_cis_pdf_flow as fixtures


class WorkspaceHistoryTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown

    def workspace(self):
        with self.session_factory() as db:
            org = db.scalar(select(Organization).where(Organization.domain == 'cybersecuritypilot.org'))
            member = db.scalar(select(Membership).where(Membership.organization_id == org.id, Membership.role == 'admin'))
            return org.id, member.user_id

    def notices(self, count, org_id=None):
        org_id = org_id or self.workspace()[0]
        now = server.utcnow()
        with self.session_factory() as db:
            rows = [WorkspaceNotification(organization_id=org_id, source_type='fixture', source_id=i,
                title=f'Notice {i}', summary='Saved evidence', reason='changes',
                detected_at=now - timedelta(days=i % 3)) for i in range(count)]
            db.add_all(rows); db.commit()
            return sorted(rows, key=lambda row: (row.detected_at, row.id), reverse=True)

    def reports(self, count, topic='external_posture', status='completed', org_id=None):
        own_id, user_id = self.workspace()
        now = server.utcnow()
        with self.session_factory() as db:
            rows = [ReportJob(organization_id=org_id or own_id, created_by_user_id=user_id,
                report_type=topic, domain='cybersecuritypilot.org', status=status, file_name='fixture.pdf',
                report_snapshot={'fixture': 'immutable'}, created_at=now, updated_at=now) for _ in range(count)]
            db.add_all(rows); db.commit()
            return [row.id for row in rows]

    def other_workspace(self):
        org_id, user_id = self.workspace()
        with self.session_factory() as db:
            other = Organization(name='Other', slug='history-other', domain='other.test', verification_status='verified', created_at=server.utcnow())
            db.add(other); db.flush()
            db.add(Membership(user_id=user_id, organization_id=other.id, role='admin', status='approved', created_at=server.utcnow()))
            db.commit(); return other.id

    def collect(self, endpoint, field, **params):
        result = []; cursors = set()
        while True:
            response = self.client.get(endpoint, params=params)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.headers['cache-control'], 'no-store')
            body = response.json(); result.extend(body[field])
            if not body['has_more']:
                self.assertIsNone(body['next_before']); return result, body
            self.assertNotIn(body['next_before'], cursors); cursors.add(body['next_before'])
            self.assertEqual(body['next_before'], body[field][-1]['id'])
            params['before'] = body['next_before']

    def test_all_notices_are_reachable_in_detection_order_with_ties_and_delayed_rows(self):
        expected = self.notices(153)
        rows, body = self.collect('/api/notifications', 'notifications', limit=17)
        self.assertEqual([row['id'] for row in rows], [row.id for row in expected])
        self.assertEqual(body['total_count'], 153)
        self.assertEqual(body['unread_count'], 153)
        self.assertEqual(len({row['id'] for row in rows}), 153)

    def test_unread_cursor_survives_marking_its_anchor_read_and_later_new_notices(self):
        expected = self.notices(105)
        first = self.client.get('/api/notifications?limit=7&unread_only=true').json()
        anchor = first['next_before']
        self.assertEqual(self.client.post(f'/api/notifications/{anchor}/read').status_code, 200)
        with self.session_factory() as db:
            db.add(WorkspaceNotification(organization_id=self.workspace()[0], source_type='new', source_id=99,
                title='New', summary='Later', reason='changes', detected_at=server.utcnow())); db.commit()
        rest, body = self.collect('/api/notifications', 'notifications', limit=11, before=anchor, unread_only='true')
        self.assertEqual([row['id'] for row in rest], [row.id for row in expected[7:]])
        self.assertEqual(body['total_count'], 105)
        self.assertEqual(body['unread_count'], 105)
        self.assertTrue(all(row['read_at'] is None for row in rest))

    def test_unread_filter_is_per_user_and_refresh_removes_read_notices(self):
        expected = self.notices(65)
        for row in expected[:60]:
            self.assertEqual(self.client.post(f'/api/notifications/{row.id}/read').status_code, 200)
        own = self.client.get('/api/notifications?unread_only=true').json()
        self.assertEqual(own['total_count'], 5)
        self.assertEqual([row['id'] for row in own['notifications']], [row.id for row in expected[60:]])
        org_id, _ = self.workspace()
        with self.session_factory() as db:
            member = db.scalar(select(User).where(User.google_subject == 'daedalus-local-demo-member'))
            db.add(Membership(user_id=member.id, organization_id=org_id, role='user', status='approved', created_at=server.utcnow())); db.commit()
        with TestClient(server.app) as other:
            self.assertEqual(other.post('/dev/login/member', follow_redirects=False).status_code, 303)
            self.assertEqual(other.post('/api/workspaces/select', json={'organization_id': org_id}).status_code, 200)
            rows = other.get('/api/notifications?unread_only=true').json()
            self.assertEqual(rows['unread_count'], 65)
            self.assertEqual(rows['total_count'], 65)
        with self.session_factory() as db:
            self.assertEqual(len(db.scalars(select(WorkspaceNotificationRead)).all()), 60)

    def test_reports_by_topic_and_status_remain_reachable_after_many_other_topics(self):
        saved = self.reports(3, 'meraki_security')
        failed = self.reports(107, 'meraki_security', 'failed')
        noise = self.reports(113)
        rows, body = self.collect('/api/reports', 'reports', report_type='meraki_security', limit=19)
        self.assertEqual([row['id'] for row in rows], list(reversed(saved + failed)))
        self.assertEqual(body['total_count'], 110)
        self.assertEqual(body['latest_completed']['id'], saved[-1])
        self.assertFalse(set(noise) & {row['id'] for row in rows})
        completed = self.client.get('/api/reports?report_type=meraki_security&status=completed').json()
        self.assertEqual([row['id'] for row in completed['reports']], saved[::-1])
        self.assertEqual(completed['total_count'], 3)
        all_rows, _ = self.collect('/api/reports', 'reports', limit=31)
        self.assertEqual(len(all_rows), 223)

    def test_combined_report_topics_have_their_own_count_and_stable_insert_cursor(self):
        meraki = self.reports(13, 'meraki_security'); cis = self.reports(12, 'cis_endpoint')
        self.reports(105, 'scanner_results')
        first = self.client.get('/api/reports?report_type=meraki_security,cis_endpoint&limit=5').json()
        self.reports(1, 'meraki_security')
        rest, body = self.collect('/api/reports', 'reports', report_type='meraki_security,cis_endpoint', limit=7, before=first['next_before'])
        self.assertEqual([row['id'] for row in first['reports'] + rest], list(reversed(meraki + cis)))
        self.assertEqual(body['total_count'], 26)

    def test_cross_workspace_positions_and_unknown_positions_are_rejected(self):
        self.reports(2); self.notices(2)
        other = self.other_workspace()
        report_id = self.reports(1, org_id=other)[0]; notice_id = self.notices(1, other)[0].id
        for path, identifier in [('/api/reports', report_id), ('/api/notifications', notice_id)]:
            for before in (identifier, 999999):
                with self.subTest(path=path, before=before):
                    self.assertEqual(self.client.get(path, params={'before': before}).status_code, 404)
            body = self.client.get(path).json()
            self.assertEqual(body['total_count'], 2)

    def test_invalid_filters_and_limits_are_rejected_without_returning_unfiltered_data(self):
        self.reports(1); self.notices(1)
        for path in ('/api/reports', '/api/notifications'):
            for params in ({'limit':0}, {'limit':101}, {'before':0}, {'before':'bad'}, {'before':'999999999999999999999'}):
                with self.subTest(path=path, params=params):
                    self.assertEqual(self.client.get(path, params=params).status_code, 422)
        for params in ({'report_type':'unknown'}, {'report_type':'meraki_security,'}, {'status':'done'}):
            self.assertEqual(self.client.get('/api/reports', params=params).status_code, 422)
        self.assertEqual(self.client.get('/api/notifications?unread_only=invalid').status_code, 422)

    def test_empty_history_is_explicit_and_login_is_required(self):
        for path, field in [('/api/reports', 'reports'), ('/api/notifications', 'notifications')]:
            body = self.client.get(path).json()
            self.assertEqual(body[field], [])
            self.assertEqual(body['total_count'], 0)
            self.assertFalse(body['has_more'])
            self.assertIsNone(body['next_before'])
        self.client.cookies.clear()
        for path in ('/api/reports', '/api/notifications'):
            self.assertEqual(self.client.get(path).status_code, 401)
