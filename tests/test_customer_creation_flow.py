"""Creation retains the displayed workspace and recovers per-domain outcomes."""
import unittest
import threading
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from daedalus import server
from daedalus.models import AuditLog, DomainChallenge, ExternalCheckSchedule, Membership, Organization
import test_auth_and_workspace_flows as fixtures


class CustomerCreationFlowTests(unittest.TestCase):
    setUp=fixtures.AuthAndWorkspaceFlowTests.setUp
    tearDown=fixtures.AuthAndWorkspaceFlowTests.tearDown

    def payload(self,**extra):
        return {'name':'Customer review', 'domains':['https://customer-one.example/','customer-two.example'], 'select_created_workspace':False, **extra}

    def test_partial_creation_records_dates_and_keeps_current_workspace(self):
        original=self.admin_client.get('/api/dashboard').json()['organization']['id']
        body=self.payload(domains=['https://customer-one.example/','www.customer-one.example','cybersecuritypilot.org','bad'])
        response=self.admin_client.post('/api/customers',json=body)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.headers['cache-control'],'no-store')
        result=response.json()
        self.assertEqual(result['created'],1)
        self.assertEqual(sorted(row['status'] for row in result['results']),['created','exists','invalid'])
        created=next(row for row in result['results'] if row['status']=='created')
        self.assertTrue(created['created_at'].endswith('Z'))
        self.assertTrue(created['probation_expires_at'].endswith('Z'))
        self.assertGreater(created['probation_expires_at'],created['created_at'])
        self.assertNotIn('daedalus_session=',response.headers.get('set-cookie',''))
        self.assertEqual(self.admin_client.get('/api/workspace-posture',headers={'X-Daedalus-Workspace':str(original)}).json()['organization_id'],original)
        with self.session_factory() as db:
            self.assertEqual(db.get(Organization,created['organization_id']).verification_status,'pending')
            member=db.scalar(select(Membership).where(Membership.organization_id==created['organization_id']))
            self.assertEqual((member.user_id,member.role,member.status),(result['user_id'],'admin','approved'))
            schedules=db.scalars(select(ExternalCheckSchedule).where(ExternalCheckSchedule.organization_id==member.organization_id)).all()
            self.assertEqual(len(schedules),2)
            self.assertTrue(all(s.enabled and s.interval_hours==24 for s in schedules))
        rows=self.admin_client.get('/api/my-workspaces').json()['workspaces']
        self.assertIn(created['organization_id'],[r['id'] for r in rows])
        selected=self.admin_client.post('/api/workspaces/select',json={'organization_id':created['organization_id']})
        self.assertEqual(selected.status_code,200)
        self.assertEqual(self.admin_client.get('/api/dashboard').json()['organization']['id'],created['organization_id'])

    def test_repeated_submission_preserves_proof_deadline_and_single_creation(self):
        first=self.admin_client.post('/api/customers',json=self.payload()).json()
        with self.session_factory() as db:
            before=[(r.id,r.token_hash,r.created_at,r.expires_at) for r in db.scalars(select(DomainChallenge))]
        second=self.admin_client.post('/api/customers',json=self.payload()).json()
        self.assertEqual(second['created'],0)
        self.assertTrue(all(r['status']=='exists' for r in second['results']))
        with self.session_factory() as db:
            self.assertEqual(before,[(r.id,r.token_hash,r.created_at,r.expires_at) for r in db.scalars(select(DomainChallenge))])
            for row in first['results']:
                self.assertEqual(db.scalar(select(func.count(AuditLog.id)).where(AuditLog.organization_id==row['organization_id'],AuditLog.action=='workspace.created')),1)

    def test_concurrent_same_domains_create_once_without_switching(self):
        clients=[TestClient(server.app),TestClient(server.app)]
        try:
            for client in clients:client.post('/dev/login')
            with ThreadPoolExecutor(max_workers=2) as pool:
                replies=list(pool.map(lambda c:c.post('/api/customers',json=self.payload()),clients))
            self.assertTrue(all(r.status_code==200 for r in replies),[r.text for r in replies])
            self.assertEqual(sum(r.json()['created'] for r in replies),2)
            with self.session_factory() as db:
                for domain in ('customer-one.example','customer-two.example'):
                    org=db.scalar(select(Organization).where(Organization.domain==domain))
                    self.assertEqual(db.scalar(select(func.count(Membership.id)).where(Membership.organization_id==org.id)),1)
                    self.assertEqual(db.scalar(select(func.count(DomainChallenge.id)).where(DomainChallenge.organization_id==org.id)),1)
        finally:
            for client in clients:client.close()

    def test_whitespace_name_invalid_only_and_unrelated_existing_domain_grant_no_access(self):
        denied=self.admin_client.post('/api/customers',json=self.payload(name='   '))
        self.assertEqual(denied.status_code,422)
        invalid=self.admin_client.post('/api/customers',json=self.payload(domains=['bad']))
        self.assertEqual(invalid.json()['created'],0)
        self.client.post('/dev/login/member')
        existing=self.client.post('/api/customers',json=self.payload(domains=['cybersecuritypilot.org']))
        self.assertEqual(existing.json()['created'],0)
        self.assertEqual(existing.json()['results'][0]['status'],'exists')
        self.assertNotIn('organization_id',existing.json()['results'][0])
        self.assertEqual(self.client.get('/api/my-workspaces').json()['workspaces'],[])

    def test_default_api_selection_remains_compatible(self):
        reply=self.admin_client.post('/api/customers',json={'name':'API customer','domains':['api-customer.example']})
        self.assertEqual(reply.status_code,200)
        self.assertEqual(self.admin_client.get('/api/dashboard').json()['organization']['id'],reply.json()['results'][0]['organization_id'])

    def test_concurrent_default_schedule_setup_after_distinct_customer_creation(self):
        ready=threading.Barrier(2);missing=threading.Barrier(2);local=threading.local()
        original_setup=server.ensure_default_external_schedules;original_scalar=Session.scalar
        def setup():
            ready.wait(timeout=10)
            return original_setup()
        def scalar(db,statement,*args,**kwargs):
            result=original_scalar(db,statement,*args,**kwargs)
            if result is None and str(statement).startswith('SELECT external_check_schedules.id') and not getattr(local,'checked',False):
                local.checked=True
                missing.wait(timeout=10)
            return result
        clients=[TestClient(server.app),TestClient(server.app)]
        try:
            for client in clients:client.post('/dev/login')
            with patch.object(server,'ensure_default_external_schedules',setup),patch.object(Session,'scalar',scalar),ThreadPoolExecutor(max_workers=2) as pool:
                tasks=[pool.submit(client.post,'/api/customers',json=self.payload(domains=[f'parallel-{index}.example'])) for index,client in enumerate(clients)]
                replies=[task.result(timeout=20) for task in tasks]
            self.assertTrue(all(reply.status_code==200 for reply in replies))
            with self.session_factory() as db:
                for domain in ('parallel-0.example','parallel-1.example'):
                    org=db.scalar(select(Organization).where(Organization.domain==domain))
                    rows=db.scalars(select(ExternalCheckSchedule).where(ExternalCheckSchedule.organization_id==org.id)).all()
                    self.assertEqual(sorted(r.check_type for r in rows),['dns','web'])
                    self.assertEqual(db.scalar(select(func.count(AuditLog.id)).where(AuditLog.organization_id==org.id,AuditLog.action=='external_check.schedule_defaulted')),2)
        finally:
            for client in clients:client.close()
