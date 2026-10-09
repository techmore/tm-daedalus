"""Saved monitoring configuration, current authority and repeat decisions."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from daedalus import server
from daedalus.models import AuditLog, ExternalCheckSchedule, Membership, UserAPIKey
import test_domain_challenge_flows as fixtures


class MonitoringScheduleReviewAPITests(unittest.TestCase):
    setUp = fixtures.DomainChallengeFlowTests.setUp
    tearDown = fixtures.DomainChallengeFlowTests.tearDown
    create = fixtures.DomainChallengeFlowTests.create

    def schedule(self, org, kind='dns'):
        with self.session_factory() as db:
            row = db.scalar(select(ExternalCheckSchedule).where(ExternalCheckSchedule.organization_id == org, ExternalCheckSchedule.check_type == kind))
            return (row.enabled, row.interval_hours, row.next_run_at, row.updated_at, row.updated_by_user_id)

    def count(self, org):
        with self.session_factory() as db:
            return db.scalar(select(func.count(AuditLog.id)).where(AuditLog.organization_id == org, AuditLog.action == 'external_check.schedule_updated'))

    def read(self, kind='dns'):
        response = self.admin_client.get(f'/api/external-checks/{kind}/schedule')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        return response.json()

    def reference(self, kind='dns'):
        return {'X-Daedalus-Schedule-State':self.read(kind)['state_reference']}

    def test_dated_scoped_read_has_stable_configuration_reference_and_no_writes(self):
        org = self.create()['organization_id']
        before = self.schedule(org)
        body = self.read()
        self.assertEqual(body['organization_id'], org)
        self.assertEqual(body['domain'], 'instructions.example.org')
        self.assertIsInstance(body['user_id'], int)
        self.assertTrue(body['can_manage'])
        self.assertTrue(body['observed_at'].endswith('Z'))
        self.assertTrue(body['updated_at'].endswith('Z'))
        self.assertEqual(len(body['state_reference']), 64)
        self.assertEqual(self.read()['state_reference'], body['state_reference'])
        self.assertEqual(self.schedule(org), before)
        self.assertEqual(self.count(org), 0)

    def test_stale_and_other_topic_references_cannot_replace_a_new_configuration(self):
        org = self.create()['organization_id']
        old = self.reference()
        changed = self.admin_client.put('/api/external-checks/dns/schedule',headers=old,json={'enabled':False,'interval_hours':168})
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertTrue(changed.json()['changed'])
        self.assertEqual(changed.headers['cache-control'], 'no-store')
        before = self.schedule(org)
        for reference in (old, self.reference('web')):
            response = self.admin_client.put('/api/external-checks/dns/schedule',headers=reference,json={'enabled':True,'interval_hours':24})
            self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(self.schedule(org), before)
        self.assertEqual(self.count(org), 1)

    def test_worker_progress_does_not_invalidate_configuration_reference(self):
        org = self.create()['organization_id']
        before = self.read()
        with self.session_factory() as db:
            row = db.scalar(select(ExternalCheckSchedule).where(ExternalCheckSchedule.organization_id==org,ExternalCheckSchedule.check_type=='dns'))
            row.next_run_at = server.utcnow()
            row.last_run_status = 'deferred'
            row.last_completed_at = server.utcnow()
            db.commit()
        after = self.read()
        self.assertEqual(after['state_reference'], before['state_reference'])
        self.assertEqual(after['last_run_status'], 'deferred')
        self.assertNotEqual(after['next_run_at'], before['next_run_at'])

    def test_simultaneous_decisions_with_one_reference_have_one_winner(self):
        org = self.create()['organization_id']
        headers = self.reference()
        barrier = Barrier(2)
        def save(enabled):
            with TestClient(server.app) as client:
                client.cookies.update(self.admin_client.cookies)
                barrier.wait(timeout=10)
                return client.put('/api/external-checks/dns/schedule',headers=headers,json={'enabled':enabled,'interval_hours':168})
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(save,[True,False]))
        self.assertEqual(sorted(r.status_code for r in responses), [200,409])
        self.assertEqual(self.count(org),1)

    def test_saved_reply_is_captured_before_a_following_configuration(self):
        self.create()
        original = Session.commit
        intervened = False
        def commit(db):
            nonlocal intervened
            original(db)
            if not intervened:
                intervened = True
                next_reply = self.admin_client.put('/api/external-checks/dns/schedule',json={'enabled':False,'interval_hours':24})
                self.assertEqual(next_reply.status_code,200,next_reply.text)
        with patch.object(Session,'commit',commit):
            reply = self.admin_client.put('/api/external-checks/dns/schedule',headers=self.reference(),json={'enabled':True,'interval_hours':168})
        self.assertEqual(reply.status_code,200,reply.text)
        self.assertTrue(reply.json()['enabled'])
        self.assertEqual(reply.json()['interval_hours'],168)
        self.assertNotEqual(reply.json()['state_reference'],self.read()['state_reference'])

    def test_member_can_read_but_cannot_save_and_scoped_context_mismatch_is_rejected(self):
        org = self.create()['organization_id']
        before = self.schedule(org)
        response = self.admin_client.put('/api/external-checks/dns/schedule',headers={'X-Daedalus-Workspace':str(org+1)},json={'enabled':False,'interval_hours':168})
        self.assertEqual(response.status_code,409,response.text)
        with self.session_factory() as db:
            db.scalar(select(Membership).where(Membership.organization_id==org)).role='user'
            db.commit()
        self.assertFalse(self.read()['can_manage'])
        response=self.admin_client.put('/api/external-checks/dns/schedule',json={'enabled':False,'interval_hours':168})
        self.assertEqual(response.status_code,403,response.text)
        self.assertEqual(self.schedule(org),before)

    def test_key_expiry_during_admission_cannot_save_configuration(self):
        org = self.create()['organization_id']
        before = self.schedule(org)
        key=self.admin_client.post('/api/user-keys',json={'name':'Schedule admission fixture'}).json()
        original=server.lock_domain_challenge_workspace
        def lock(db,organization,user,request):
            with self.session_factory() as other:
                other.get(UserAPIKey,key['id']).expires_at=server.utcnow()-server.timedelta(seconds=1)
                other.commit()
            return original(db,organization,user,request)
        with patch.object(server,'lock_domain_challenge_workspace',side_effect=lock):
            reply=self.admin_client.put('/api/external-checks/dns/schedule',headers={'Authorization':'Bearer '+key['token']},json={'enabled':False,'interval_hours':168})
        self.assertEqual(reply.status_code,401,reply.text)
        self.assertEqual(self.schedule(org),before)
        self.assertEqual(self.count(org),0)

    def test_pending_ownership_can_run_its_configured_public_schedule(self):
        org = self.create()['organization_id']
        with patch.object(server,'run_dns_check',return_value={'domain':'instructions.example.org','records':{},'resolver_errors':{}}) as collector:
            result=server.execute_external_check(org,None,'dns','schedule')
        self.assertIn(result['status'],{'completed','completed_with_warnings'})
        collector.assert_called_once()
        self.assertEqual(self.admin_client.get(f'/api/workspaces/{org}/domain-challenge').json()['verified'],False)
        for kind in ('web-active','web-nikto'):
            reply=self.admin_client.get(f'/api/external-checks/{kind}/schedule')
            self.assertEqual(reply.status_code,404,reply.text)

    def test_same_saved_configuration_does_not_postpone_collection_or_duplicate_audit(self):
        org = self.create()['organization_id']
        first = self.admin_client.put('/api/external-checks/dns/schedule', json={'enabled':True,'interval_hours':168})
        self.assertEqual(first.status_code, 200, first.text)
        before = self.schedule(org)
        repeated = self.admin_client.put('/api/external-checks/dns/schedule', json={'enabled':True,'interval_hours':168})
        self.assertEqual(repeated.status_code, 200, repeated.text)
        self.assertEqual(self.schedule(org), before)
        self.assertEqual(self.count(org), 1)

    def test_authority_loss_after_initial_context_cannot_change_schedule(self):
        org = self.create()['organization_id']
        before = self.schedule(org)
        original = server.get_org_context
        def context(*args, **kwargs):
            result = original(*args, **kwargs)
            with self.session_factory() as db:
                row = db.scalar(select(Membership).where(Membership.organization_id == org, Membership.user_id == result[0].id))
                row.role = 'user'
                db.commit()
            return result
        with patch.object(server, 'get_org_context', side_effect=context):
            response = self.admin_client.put('/api/external-checks/dns/schedule', json={'enabled':False,'interval_hours':168})
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(self.schedule(org), before)
        self.assertEqual(self.count(org), 0)
