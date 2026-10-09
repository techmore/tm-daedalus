"""Account-owned request dates and access survive having no approved workspace."""
import unittest
from datetime import timedelta
from sqlalchemy import select
from daedalus import server
from daedalus.models import AuditLog, Membership, Organization, User
import test_auth_and_workspace_flows as fixtures


class WorkspaceRequestAPITests(unittest.TestCase):
    setUp = fixtures.AuthAndWorkspaceFlowTests.setUp
    tearDown = fixtures.AuthAndWorkspaceFlowTests.tearDown
    google_callback = fixtures.AuthAndWorkspaceFlowTests.google_callback

    def requester(self):
        self.assertEqual(self.google_callback({'sub':'request-list-fixture', 'email':'request-list@example.net', 'email_verified':True}).status_code, 303)

    def test_no_workspace_first_request_dates_and_idempotent_repeat(self):
        self.requester()
        empty = self.client.get('/api/my-workspaces')
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.headers['cache-control'], 'no-store')
        self.assertEqual(empty.json()['workspaces'], [])
        self.assertTrue(empty.json()['observed_at'].endswith('Z'))
        self.assertEqual(self.client.post('/api/membership-requests', json={'domain':'cybersecuritypilot.org'}).status_code, 200)
        first = self.client.get('/api/my-workspaces').json()
        row = first['workspaces'][0]
        self.assertEqual((row['status'], row['role']), ('pending','user'))
        self.assertTrue(row['requested_at'].endswith('Z'))
        self.assertTrue(row['membership_created_at'].endswith('Z'))
        self.client.post('/api/membership-requests', json={'domain':'cybersecuritypilot.org'})
        self.assertEqual(self.client.get('/api/my-workspaces').json()['workspaces'], first['workspaces'])
        with self.session_factory() as db:
            user = db.scalar(select(User).where(User.google_subject=='request-list-fixture'))
            self.assertEqual(first['user_id'], user.id)
            self.assertEqual(len(db.scalars(select(AuditLog).where(AuditLog.action=='membership.requested',AuditLog.actor_user_id==user.id)).all()),1)

    def test_denied_re_request_shows_latest_episode_not_creation(self):
        self.requester()
        self.client.post('/api/membership-requests', json={'domain':'cybersecuritypilot.org'})
        with self.session_factory() as db:
            user = db.scalar(select(User).where(User.google_subject=='request-list-fixture'))
            member = db.scalar(select(Membership).where(Membership.user_id==user.id))
            member_id = member.id
            log = db.scalar(select(AuditLog).where(AuditLog.action=='membership.requested', AuditLog.actor_user_id==user.id))
            log.created_at = server.utcnow()-timedelta(days=3)
            db.commit()
        old = self.client.get('/api/my-workspaces').json()['workspaces'][0]
        self.assertEqual(self.admin_client.post(f'/api/memberships/{member_id}/decision',json={'approve':False}).status_code,200)
        self.assertEqual(self.client.get('/api/my-workspaces').json()['workspaces'][0]['status'],'denied')
        self.client.post('/api/membership-requests',json={'domain':'cybersecuritypilot.org'})
        new = self.client.get('/api/my-workspaces').json()['workspaces'][0]
        self.assertEqual(new['status'],'pending')
        self.assertGreater(new['requested_at'],old['requested_at'])
        self.assertEqual(new['membership_created_at'],old['membership_created_at'])
        self.assertEqual(self.admin_client.post(f'/api/memberships/{member_id}/decision',json={'approve':True}).status_code,200)
        approved = self.client.get('/api/my-workspaces').json()['workspaces'][0]
        self.assertEqual((approved['status'],approved['role']),('approved','user'))
        self.assertEqual(approved['requested_at'],new['requested_at'])
        self.assertEqual(self.admin_client.post(f'/api/memberships/{member_id}/revoke').status_code,200)
        self.assertEqual(self.client.get('/api/my-workspaces').json()['workspaces'][0]['status'],'revoked')

    def test_private_account_scope_unknown_historical_date_and_read_only(self):
        owner = self.admin_client.get('/api/my-workspaces').json()
        self.assertIsNone(owner['workspaces'][0]['requested_at'])
        self.requester()
        self.client.post('/api/membership-requests',json={'domain':'cybersecuritypilot.org'})
        with self.session_factory() as db:
            user=db.scalar(select(User).where(User.google_subject=='request-list-fixture'))
            member=db.scalar(select(Membership).where(Membership.user_id==user.id))
            db.add(AuditLog(organization_id=member.organization_id, actor_user_id=owner['user_id'], action='membership.requested', details={'membership_id':member.id}, created_at=server.utcnow()+timedelta(days=1)))
            db.commit()
            before=[(log.id,log.action) for log in db.scalars(select(AuditLog))]
        response=self.client.get('/api/my-workspaces',headers={'X-Daedalus-Workspace':'999999'})
        self.assertEqual(response.status_code,200)
        self.assertNotEqual(response.json()['user_id'],owner['user_id'])
        self.assertEqual(len(response.json()['workspaces']),1)
        self.assertLess(response.json()['workspaces'][0]['requested_at'],server.iso_utc(server.utcnow()+timedelta(hours=1)))
        with self.session_factory() as db:self.assertEqual(before,[(log.id,log.action) for log in db.scalars(select(AuditLog))])
        self.client.post('/logout')
        self.assertEqual(self.client.get('/api/my-workspaces').status_code,401)

    def test_workspace_scoped_keys_cannot_read_other_account_workspaces(self):
        key=self.admin_client.post('/api/user-keys',json={'name':'Request scope fixture'}).json()
        self.assertEqual(self.client.get('/api/my-workspaces',headers={'Authorization':'Bearer '+key['token']}).status_code,403)
        self.assertEqual(self.client.post('/auth/token',json={'token':key['token']}).status_code,200)
        self.assertEqual(self.client.get('/api/my-workspaces').status_code,403)

    def test_unchanged_dashboard_reads_do_not_reissue_the_old_identity_cookie(self):
        for path in ('/api/dashboard','/api/workspace-posture','/api/memberships','/api/my-workspaces','/api/audit-log'):
            with self.subTest(path=path):
                response=self.admin_client.get(path)
                self.assertEqual(response.status_code,200,response.text)
                self.assertNotIn('daedalus_session=',response.headers.get('set-cookie',''))
        with self.session_factory() as db:
            member_user=db.scalar(select(User).where(User.google_subject=='daedalus-local-demo-member'))
            org=db.scalar(select(Organization).where(Organization.domain=='cybersecuritypilot.org'))
            db.add(Membership(user_id=member_user.id,organization_id=org.id,role='user',status='approved',created_at=server.utcnow()))
            db.commit()
        changed=self.admin_client.post('/dev/login/member',follow_redirects=False)
        self.assertEqual(changed.status_code,303)
        self.assertIn('daedalus_session=',changed.headers.get('set-cookie',''))
        self.assertEqual(self.admin_client.get('/api/dashboard').json()['role'],'user')
        self.assertNotIn('daedalus_session=',self.admin_client.get('/api/dashboard').headers.get('set-cookie',''))

    def test_key_login_reads_do_not_restore_the_cookie_after_logout(self):
        key=self.admin_client.post('/api/user-keys',json={'name':'Session read fixture'}).json()
        self.client.post('/auth/token',json={'token':key['token']})
        for path in ('/api/dashboard','/api/workspace-posture','/api/memberships'):
            with self.subTest(path=path):
                response=self.client.get(path)
                self.assertEqual(response.status_code,200)
                self.assertNotIn('daedalus_session=',response.headers.get('set-cookie',''))
        self.assertIn('daedalus_session=null',self.client.post('/logout',follow_redirects=False).headers.get('set-cookie',''))
        self.assertEqual(self.client.get('/api/dashboard').status_code,401)
