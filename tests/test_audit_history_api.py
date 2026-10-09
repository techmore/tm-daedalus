"""Complete, scoped, read-only access to recorded workspace actions."""
import unittest
from fastapi.testclient import TestClient
from sqlalchemy import select
from daedalus import server
from daedalus.models import AuditLog, Membership, Organization, User
import test_auth_and_workspace_flows as fixtures


class AuditHistoryAPITests(unittest.TestCase):
    setUp = fixtures.AuthAndWorkspaceFlowTests.setUp
    tearDown = fixtures.AuthAndWorkspaceFlowTests.tearDown

    def context(self):
        with self.session_factory() as db:
            org = db.scalar(select(Organization).where(Organization.domain == 'cybersecuritypilot.org'))
            member = db.scalar(select(Membership).where(Membership.organization_id == org.id, Membership.role == 'admin'))
            return org.id, member.user_id

    def events(self, count, org_id=None):
        own_id, user_id = self.context()
        with self.session_factory() as db:
            rows = [AuditLog(organization_id=org_id or own_id, actor_user_id=user_id if i % 2 else None,
                action='membership.role_changed', details={'email':'member@example.net','from_role':'user','to_role':'admin'},
                created_at=server.utcnow()) for i in range(count)]
            db.add_all(rows); db.commit()
            return [r.id for r in rows]

    def test_all_actions_are_reachable_without_duplicates_and_reads_do_not_change_evidence(self):
        ids = self.events(233); collected = []; cursor = None
        with self.session_factory() as db:
            before = [(r.id,r.details,r.created_at) for r in db.scalars(select(AuditLog)).all()]
        while True:
            response = self.admin_client.get('/api/audit-log',params={'limit':37, **({'before':cursor} if cursor else {})})
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(response.headers['cache-control'],'no-store')
            body = response.json(); self.assertEqual(body['organization_id'],self.context()[0]); self.assertTrue(body['observed_at'].endswith('Z'))
            self.assertEqual(body['total_count'],233);collected.extend(r['id'] for r in body['events'])
            if not body['has_more']:
                self.assertIsNone(body['next_before']);break
            cursor = body['next_before'];self.assertEqual(cursor,body['events'][-1]['id'])
        self.assertEqual(collected,ids[::-1]);self.assertEqual(len(set(collected)),233)
        with self.session_factory() as db:self.assertEqual(before,[(r.id,r.details,r.created_at) for r in db.scalars(select(AuditLog)).all()])

    def test_new_actions_do_not_move_older_cursor_and_system_actor_is_explicit(self):
        ids = self.events(7);first = self.admin_client.get('/api/audit-log?limit=3').json();new = self.events(2)
        rest = self.admin_client.get('/api/audit-log',params={'limit':10,'before':first['next_before']}).json()
        self.assertEqual([r['id'] for r in first['events']+rest['events']],ids[::-1]);self.assertEqual(rest['total_count'],9)
        self.assertFalse(set(new)&{r['id'] for r in rest['events']});self.assertTrue(any(r['actor']=='system' for r in rest['events']))

    def test_other_workspace_cursor_unknown_cursor_and_stale_document_are_refused(self):
        own,user_id = self.context();self.events(2)
        with self.session_factory() as db:
            org=Organization(name='Other',slug='audit-other',domain='other.test',verification_status='verified',created_at=server.utcnow());db.add(org);db.commit();other=org.id
        foreign=self.events(1,other)[0]
        for cursor in [foreign,999999]:self.assertEqual(self.admin_client.get('/api/audit-log',params={'before':cursor}).status_code,404)
        self.assertEqual(self.admin_client.get('/api/audit-log',headers={'X-Daedalus-Workspace':str(other)}).status_code,409)
        self.assertEqual(self.admin_client.get('/api/audit-log').json()['total_count'],2)

    def test_invalid_positions_limits_and_anonymous_reads_are_refused(self):
        for params in [{'limit':0},{'limit':201},{'before':0},{'before':'bad'},{'before':9223372036854775808}]:
            with self.subTest(params=params):self.assertEqual(self.admin_client.get('/api/audit-log',params=params).status_code,422)
        self.assertEqual(self.client.get('/api/audit-log').status_code,401)

    def test_empty_history_and_legacy_200_row_page_remain_available(self):
        empty=self.admin_client.get('/api/audit-log').json();self.assertEqual(empty['events'],[]);self.assertEqual(empty['total_count'],0);self.assertFalse(empty['has_more']);self.assertIsNone(empty['next_before'])
        self.events(201);page=self.admin_client.get('/api/audit-log?limit=200').json();self.assertEqual(len(page['events']),200);self.assertTrue(page['has_more'])

    def test_demoted_member_cannot_read_admin_history(self):
        org,user_id=self.context();self.events(1)
        with self.session_factory() as db:
            member=db.scalar(select(Membership).where(Membership.organization_id==org,Membership.user_id==user_id));member.role='user';db.commit()
        self.assertEqual(self.admin_client.get('/api/audit-log').status_code,403)
