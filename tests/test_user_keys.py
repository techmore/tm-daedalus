import unittest
from pathlib import Path
from datetime import timedelta
from sqlalchemy import select
from daedalus import server
from daedalus.models import UserAPIKey, Membership
import test_active_website_flows as fixtures


class UserKeyTests(unittest.TestCase):
    def test_account_controls_use_readable_dates_and_scoped_form_layout(self):
        root = Path(__file__).parents[1] / 'src/daedalus'
        script = (root / 'static/js/user_keys.js').read_text()
        css = (root / 'static/css/app.css').read_text()
        self.assertIn('keyDate(key.revoked_at)', script)
        self.assertIn('keyDate(key.expires_at)', script)
        self.assertIn('button.setAttribute("aria-label", `Revoke ${key.name}`)', script)
        self.assertIn('#create-key, #token-login { display: grid;', css)
        self.assertIn('#new-key { white-space: pre-wrap; overflow-wrap: anywhere; }', css)

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

    def test_cis_user_key_upload_without_rotating_shared_key(self):
        shared = self.client.post('/api/cis/api-key').json()['api_key']
        profile = {'name':'Key fixture','slug':'key-fixture','version':'1','platform':'macos',
                   'checks':[{'id':'one','category':'macos','description':'One'}]}
        self.assertEqual(self.client.post('/api/cis/profiles',json=profile).status_code,200)
        key = self.issue()
        self.assertEqual(self.client.post('/api/workspaces',json={'name':'Other','domain':'other-cis.example'}).status_code,200)
        self.assertEqual(self.client.post('/api/cis/profiles',json={**profile,'slug':'other-fixture'}).status_code,200)
        self.client.post('/logout')
        headers = {'X-API-Key':key['token']}
        catalog = self.client.get('/api/cis/client/profiles',headers=headers)
        self.assertEqual(catalog.status_code,200,catalog.text)
        self.assertEqual(len(catalog.json()['profiles']),1)
        self.assertEqual(catalog.json()['domain'],'cybersecuritypilot.org')
        self.assertEqual(catalog.json()['profiles'][0]['slug'],'key-fixture')
        payload = {'device_uuid':'key-fixture-device','report_id':'key-fixture-run',
                   'timestamp':'2026-10-04T05:00:00Z','profile_slug':'key-fixture','profile_version':'1',
                   'system_info':{'hostname':'Fixture','os_version':'26.0'},
                   'results':[{'id':'one','category':'macos','description':'One','status':'pass'}]}
        uploaded = self.client.post('/api/cis/report',headers=headers,json=payload)
        self.assertEqual(uploaded.status_code,200,uploaded.text)
        self.client.delete('/api/user-keys/'+str(key['id']),headers={'Authorization':'Bearer '+key['token']})
        self.assertEqual(self.client.get('/api/cis/client/profiles',headers=headers).status_code,401)
        self.assertEqual(self.client.post('/api/cis/report',headers=headers,json=payload).status_code,401)
        self.assertEqual(self.client.get('/api/cis/client/profiles',headers={'X-API-Key':shared}).status_code,200)

    def test_cis_user_key_revalidates_membership_and_expiry(self):
        key = self.issue()
        org,user = self.context()
        with self.session_factory() as db:
            db.get(UserAPIKey,key['id']).expires_at = server.utcnow()-timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.client.get('/api/cis/client/profiles',headers={'X-API-Key':key['token']}).status_code,401)
        key = self.issue()
        with self.session_factory() as db:
            db.scalar(select(Membership).where(Membership.user_id==user,Membership.organization_id==org)).status='denied'
            db.commit()
        self.assertEqual(self.client.get('/api/cis/client/profiles',headers={'X-API-Key':key['token']}).status_code,401)
