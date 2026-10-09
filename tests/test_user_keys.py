import unittest
from pathlib import Path
from datetime import timedelta
from sqlalchemy import select
from daedalus import server
from daedalus.models import UserAPIKey, Membership, Organization, DomainChallenge, AuditLog
import test_active_website_flows as fixtures


class UserKeyTests(unittest.TestCase):
    def test_account_controls_use_readable_dates_and_scoped_form_layout(self):
        root = Path(__file__).parents[1] / 'src/daedalus'
        script = (root / 'static/js/user_keys.js').read_text()
        css = (root / 'static/css/app.css').read_text()
        self.assertIn('keyDate(key.revoked_at)', script)
        self.assertIn('keyDate(key.expires_at)', script)
        self.assertIn('button.setAttribute("aria-label", `Revoke ${key.name}`)', script)
        self.assertIn('error.status = response.status;', script)
        self.assertIn('if (error.status === 401) { location.assign("/"); return; }', script)
        self.assertIn('#create-key, #token-login { display: grid;', css)
        self.assertIn('#new-key { white-space: pre-wrap; overflow-wrap: anywhere; }', css)
        for name in ('login.html', 'user_keys.html'):
            template = (root / 'templates' / name).read_text()
            self.assertIn('app.css?v=daedalus-20261009-193', template)
            self.assertIn('user_keys.js?v=20261009-1', template)

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

    def test_workspace_key_cannot_create_customers_with_bearer_or_login_cookie(self):
        key = self.issue()
        org_id, _user_id = self.context()
        def counts():
            with self.session_factory() as db:
                return tuple(len(db.scalars(select(model)).all()) for model in (Organization, DomainChallenge, AuditLog))
        self.client.post('/logout')
        headers = {'Authorization': 'Bearer ' + key['token']}
        before = counts()
        response = self.client.post('/api/customers', headers=headers,
                                    json={'name': 'Unrelated customer', 'domains': ['bearer-other.example.org']})
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(counts(), before)
        self.assertEqual(self.client.get('/api/dashboard', headers=headers).json()['organization']['id'], org_id)
        self.assertEqual(self.client.post('/auth/token', json={'token': key['token']}).status_code, 200)
        before = counts()
        response = self.client.post('/api/customers', json={'name': 'Unrelated customer', 'domains': ['cookie-other.example.org']})
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(counts(), before)
        self.assertEqual(self.client.get('/api/dashboard').json()['organization']['id'], org_id)

    def test_portfolio_respects_key_scope_for_bearer_and_login_cookie(self):
        org_id, _ = self.context()
        key = self.issue()
        response = self.client.post('/api/workspaces', json={'name': 'Private other customer', 'domain': 'private-customer.example'})
        self.assertEqual(response.status_code, 200, response.text)
        other_id = response.json()['organization_id']
        normal = self.client.get('/api/portfolio')
        self.assertEqual(normal.status_code, 200, normal.text)
        self.assertIn(other_id, [row['id'] for row in normal.json()['workspaces']])
        self.assertIs(normal.json()['can_switch_workspaces'], True)
        self.client.post('/logout')
        bearer = self.client.get('/api/portfolio', headers={'Authorization': 'Bearer ' + key['token']})
        self.assertEqual(bearer.status_code, 200, bearer.text)
        self.assertEqual([row['id'] for row in bearer.json()['workspaces']], [org_id])
        self.assertEqual(bearer.json()['organization_id'], org_id)
        self.assertIs(bearer.json()['can_switch_workspaces'], False)
        self.assertNotIn('private-customer.example', bearer.text)
        self.assertEqual(bearer.headers['cache-control'], 'no-store')
        self.assertEqual(self.client.post('/auth/token', json={'token': key['token']}).status_code, 200)
        cookie = self.client.get('/api/portfolio')
        self.assertEqual(cookie.status_code, 200, cookie.text)
        self.assertEqual([row['id'] for row in cookie.json()['workspaces']], [org_id])
        self.assertIs(cookie.json()['can_switch_workspaces'], False)
        self.assertNotIn('Private other customer', cookie.text)
        self.assertEqual(self.client.post('/api/workspaces/select', json={'organization_id': other_id}).status_code, 403)

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

    def test_key_inventory_scoped_metadata_and_no_store(self):
        original, _ = self.context()
        first = self.issue()
        second = self.issue()
        response = self.client.get('/api/user-keys')
        self.assertEqual(response.headers['cache-control'], 'no-store')
        body = response.json()
        self.assertEqual(body['organization_id'], original)
        self.assertIs(body['can_create'], True)
        self.assertIsNone(body['current_key_id'])
        self.assertEqual([row['id'] for row in body['keys']], [second['id'], first['id']])
        self.assertTrue(all(row['created_at'].endswith('Z') for row in body['keys']))
        self.assertNotIn(first['token'], response.text)
        self.assertNotIn('token_hash', response.text)
        page = self.client.get('/account/keys')
        self.assertEqual(page.headers['cache-control'], 'no-store')
        self.assertIn('data-organization-id="'+str(original)+'"', page.text)
        self.client.post('/logout')
        self.client.post('/auth/token', json={'token': first['token']})
        body = self.client.get('/api/user-keys').json()
        self.assertIs(body['can_create'], False)
        self.assertEqual(body['current_key_id'], first['id'])
        page = self.client.get('/account/keys')
        self.assertNotIn('id="create-key"', page.text)
        self.assertIn('Sign in with Google to create another key', page.text)

    def test_repeated_revocation_preserves_date_and_single_audit(self):
        key = self.issue()
        response = self.client.delete('/api/user-keys/'+str(key['id']))
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertIs(response.json()['ends_current_session'], False)
        first_date = response.json()['revoked_at']
        second = self.client.delete('/api/user-keys/'+str(key['id']))
        self.assertEqual(second.json()['revoked_at'], first_date)
        with self.session_factory() as db:
            rows = db.scalars(select(AuditLog).where(AuditLog.action == 'user_key.revoked')).all()
            self.assertEqual(len(rows), 1)

    def test_self_revocation_explicitly_ends_key_login(self):
        key = self.issue()
        self.client.post('/logout')
        self.client.post('/auth/token', json={'token': key['token']})
        response = self.client.delete('/api/user-keys/'+str(key['id']))
        self.assertIs(response.json()['ends_current_session'], True)
        self.assertEqual(self.client.get('/api/user-keys').status_code, 401)
        self.assertEqual(self.client.get('/dashboard', follow_redirects=False).status_code, 303)

    def test_old_account_tab_cannot_read_create_or_revoke_after_workspace_switch(self):
        original, _ = self.context()
        key = self.issue()
        other = self.client.post('/api/workspaces', json={'name': 'Other keys', 'domain': 'keys-other.example'}).json()['organization_id']
        before = self.client.get('/api/user-keys').json()
        stale = {'X-Daedalus-Workspace': str(original)}
        self.assertEqual(self.client.get('/api/user-keys', headers=stale).status_code, 409)
        self.assertEqual(self.client.post('/api/user-keys', headers=stale, json={'name': 'Wrong customer'}).status_code, 409)
        self.assertEqual(self.client.delete('/api/user-keys/'+str(key['id']), headers=stale).status_code, 409)
        after = self.client.get('/api/user-keys').json()
        self.assertEqual(after['keys'], before['keys'])
        self.assertEqual(after['organization_id'], other)
        with self.session_factory() as db:
            self.assertIsNone(db.get(UserAPIKey, key['id']).revoked_at)
            self.assertEqual(len(db.scalars(select(UserAPIKey)).all()), 1)

    def test_key_does_not_read_other_approved_workspace_icon(self):
        from daedalus.models import WorkspaceIcon
        original, _ = self.context()
        key = self.issue()
        other = self.client.post('/api/workspaces', json={'name': 'Private icon', 'domain': 'icon-other.example'}).json()['organization_id']
        with self.session_factory() as db:
            for workspace in (original, other):
                db.add(WorkspaceIcon(organization_id=workspace, content_type='image/png', data=b'fixture', fetched_at=server.utcnow()))
            db.commit()
        self.assertEqual(self.client.get(f'/api/workspaces/{other}/icon').status_code, 200)
        headers = {'Authorization': 'Bearer '+key['token']}
        response = self.client.get(f'/api/workspaces/{original}/icon', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(self.client.get(f'/api/workspaces/{other}/icon', headers=headers).status_code, 404)
        self.client.post('/logout')
        self.client.post('/auth/token', json={'token': key['token']})
        self.assertEqual(self.client.get(f'/api/workspaces/{other}/icon').status_code, 404)

    def test_key_permissions_follow_admin_demotion(self):
        key = self.issue()
        org, user = self.context()
        with self.session_factory() as db:
            db.scalar(select(Membership).where(Membership.user_id == user, Membership.organization_id == org)).role = 'user'
            db.commit()
        headers = {'Authorization': 'Bearer '+key['token']}
        self.assertEqual(self.client.get('/api/workspace-posture', headers=headers).status_code, 200)
        self.assertIs(self.client.get('/api/workspace-posture', headers=headers).json()['can_manage'], False)
        self.assertEqual(self.client.put('/api/external-checks/web/schedule', headers=headers, json={'enabled': True, 'interval_hours': 24}).status_code, 403)
        self.assertEqual(self.client.post('/api/cis/api-key', headers=headers).status_code, 403)

    def test_key_live_feed_scope_and_revocation(self):
        from starlette.websockets import WebSocketDisconnect
        original, _ = self.context()
        key = self.issue()
        other = self.client.post('/api/workspaces', json={'name': 'Other live feed', 'domain': 'live-keys-other.example'}).json()['organization_id']
        self.client.post('/logout')
        self.client.post('/auth/token', json={'token': key['token']})
        with self.assertRaises(WebSocketDisconnect) as denied:
            with self.client.websocket_connect(f'/ws/live?organization_id={other}', headers={'origin': 'http://testserver'}) as feed:
                feed.receive_json()
        self.assertEqual(denied.exception.code, 4401)
        with self.client.websocket_connect(f'/ws/live?organization_id={original}&membership_updates=1', headers={'origin': 'http://testserver'}) as feed:
            self.assertEqual(feed.receive_json()['organization_id'], original)
            self.assertEqual(self.client.delete('/api/user-keys/'+str(key['id'])).status_code, 200)
            feed.send_text('revalidate')
            with self.assertRaises(WebSocketDisconnect) as ended:
                feed.receive_json()
            self.assertEqual(ended.exception.code, 4401)
