import unittest
from datetime import timedelta
from sqlalchemy import select
from daedalus import server
from daedalus.models import ExternalCheckRun, Organization, Membership
import test_active_website_flows as fixtures


class WorkspacePostureTests(unittest.TestCase):
    setUp=fixtures.ActiveWebsiteFlowsTests.setUp
    tearDown=fixtures.ActiveWebsiteFlowsTests.tearDown
    context=fixtures.ActiveWebsiteFlowsTests.context

    def save(self, org_id, kind='dns', status='completed', snapshot=None):
        with self.session_factory() as db:
            row=ExternalCheckRun(organization_id=org_id,check_type=kind,domain='cybersecuritypilot.org',status=status,trigger_source='manual',started_at=server.utcnow(),completed_at=server.utcnow() if status!='running' else None,snapshot=snapshot,change_count=0)
            db.add(row);db.commit()
            return row.id

    def test_no_results_stay_unassessed_and_no_raw_payload_is_returned(self):
        response=self.client.get('/api/workspace-posture')
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.headers["cache-control"],"no-store")
        areas={area['key']:area for area in response.json()['areas']}
        for key in ('dns','web','cis','meraki'):
            self.assertEqual(areas[key]['state'],'not_assessed')
        self.assertNotIn('token_hash',response.text)
        self.assertNotIn('device_fingerprint',response.text)

    def test_running_attempt_keeps_dated_saved_evidence_even_after_many_failures(self):
        org,_=self.context()
        self.save(org,snapshot={'email_authentication_assessment':{'spf':{'label':'Published','tone':'good'},'dmarc':{'label':'Published','tone':'good'}},'resolver_errors':{},'raw_secret':'never-return-this'})
        for _ in range(51): self.save(org,status='failed')
        self.save(org,status='running')
        area=next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='dns')
        self.assertEqual(area['state'],'running')
        self.assertIn('SPF: Published',area['summary'])
        self.assertTrue(area['updated_at'])
        self.assertNotIn('never-return-this',str(area))

    def test_other_workspace_results_are_not_visible(self):
        org,_=self.context()
        with self.session_factory() as db:
            other=Organization(name='Other',slug='other',domain='other.example',verification_status='verified',created_at=server.utcnow())
            db.add(other);db.commit();other_id=other.id
        self.save(other_id,snapshot={'email_authentication_assessment':{'spf':{'label':'Other workspace secret'}}})
        response=self.client.get('/api/workspace-posture')
        self.assertEqual(response.json()['domain'],'cybersecuritypilot.org')
        self.assertNotIn('Other workspace secret',response.text)
        self.client.post('/logout')
        self.assertEqual(self.client.get('/api/workspace-posture').status_code,401)

    def test_policy_unknowns_and_failed_latest_attempt_have_review_states(self):
        org,_=self.context()
        self.save(org,snapshot={'resolver_errors':{'MX':'timeout'},'email_authentication_assessment':{}})
        self.save(org,kind='web',snapshot={'http_status':500,'security_headers':{}})
        areas={a['key']:a for a in self.client.get('/api/workspace-posture').json()['areas']}
        self.assertEqual(areas['dns']['state'],'attention')
        self.assertEqual(areas['web']['state'],'attention')
        self.save(org,kind='web',status='failed')
        area=next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='web')
        self.assertEqual(area['state'],'unavailable')
        self.assertIn('HTTPS 500',area['summary'])

    def test_deeper_audit_has_separate_timestamp_without_raw_observations(self):
        org,_=self.context()
        self.save(org,kind='web-nikto',status='completed_with_warnings',snapshot={'findings':[{'description':'private detector text'}],'coverage_complete':False})
        area=next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='web')
        self.assertIn('1 observations',area['audit_summary'])
        self.assertTrue(area['audit_updated_at'])
        self.assertIsNone(area['updated_at'])
        self.assertEqual(area['state'],'attention')
        self.assertNotIn('private detector text',str(area))
