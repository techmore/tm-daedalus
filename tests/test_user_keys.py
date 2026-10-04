import unittest
from datetime import timedelta
from sqlalchemy import select
from daedalus import server
from daedalus.models import UserAPIKey, Membership
import test_active_website_flows as fixtures


class UserKeyTests(unittest.TestCase):
    setUp = fixtures.ActiveWebsiteFlowsTests.setUp
    tearDown = fixtures.ActiveWebsiteFlowsTests.tearDown
    context = fixtures.ActiveWebsiteFlowsTests.context

    def issue(self):
        response = self.client.post('/api/user-keys', json={'name':'Fixture','expires_days':1})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.headers['cache-control'],'no-store')
        return response.json()

    def test_hash_only_bearer_and_revocation(self):
        key = self.issue()
        with self.session_factory() as db:
            stored = db.get(UserAPIKey,key['id'])
            self.assertEqual(stored.token_hash,server.token_digest(key['token']))
            self.assertNotEqual(stored.token_hash,key['token'])
        self.client.post('/logout')
        headers = {'Authorization':'Bearer '+key['token']}
        self.assertEqual(self.client.get('/api/dashboard',headers=headers).status_code,200)
        self.assertEqual(self.client.post('/api/user-keys',headers=headers,json={'name':'Recursive'}).status_code,403)
        self.assertEqual(self.client.delete('/api/user-keys/'+str(key['id']),headers=headers).status_code,200)
        self.assertEqual(self.client.get('/api/dashboard',headers=headers).status_code,401)

    def test_login_session_revocation_and_scope(self):
        key=self.issue()
        self.client.post('/logout')
        self.assertEqual(self.client.post('/auth/token',json={'token':key['token']}).status_code,200)
        self.assertEqual(self.client.get('/api/dashboard').status_code,200)
        self.assertEqual(self.client.get('/api/my-workspaces').status_code,403)
        self.assertEqual(self.client.post('/api/workspaces/select',json={'organization_id':999}).status_code,403)
        self.client.delete('/api/user-keys/'+str(key['id']))
        self.assertEqual(self.client.get('/api/dashboard').status_code,401)

    def test_expired_and_unapproved_membership(self):
        key=self.issue()
        with self.session_factory() as db:
            db.get(UserAPIKey,key['id']).expires_at=server.utcnow()-timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.client.post('/auth/token',json={'token':key['token']}).status_code,401)
        key=self.issue()
        org,user=self.context()
        with self.session_factory() as db:
            db.scalar(select(Membership).where(Membership.user_id==user,Membership.organization_id==org)).status='denied'
            db.commit()
        self.assertEqual(self.client.get('/api/dashboard',headers={'Authorization':'Bearer '+key['token']}).status_code,401)

    def test_invalid_header_never_falls_back_to_cookie_and_list_is_secret_free(self):
        key=self.issue()
        self.assertNotIn(key['token'],self.client.get('/api/user-keys').text)
        self.assertEqual(self.client.get('/api/dashboard',headers={'Authorization':'Bearer invalid'}).status_code,401)
        self.assertEqual(self.client.get('/account/keys').status_code,200)
        self.assertIn('token-login',self.client.get('/').text if not self.client.cookies else self.client.post('/logout').text + self.client.get('/').text)
