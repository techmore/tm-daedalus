import unittest
from datetime import timedelta
from unittest.mock import patch

from sqlalchemy import select

from daedalus import onboarding, server
from daedalus.models import AuditLog, CustomerOnboarding, Membership, Organization, User, WorkspaceNotification
import test_auth_and_workspace_flows as auth_flows


class CustomerOnboardingTests(unittest.TestCase):
    google_callback = auth_flows.AuthAndWorkspaceFlowTests.google_callback

    def setUp(self):
        auth_flows.AuthAndWorkspaceFlowTests.setUp(self)
        with self.session_factory() as db:
            owner = db.scalar(select(User).where(User.google_subject == 'daedalus-local-demo-admin'))
            owner.email = 'sean.dolbec@cybersecuritypilot.org'
            db.commit()
        self.admins = patch.object(server, 'PLATFORM_ADMIN_EMAILS', ('sean.dolbec@cybersecuritypilot.org',))
        self.admins.start()

    def tearDown(self):
        self.admins.stop()
        auth_flows.AuthAndWorkspaceFlowTests.tearDown(self)

    def create(self, domain='transition.example.org'):
        response = self.admin_client.post('/api/customers', json={
            'name': 'Transition customer', 'domains': [domain], 'onboarding': True})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()['results'][0]['organization_id']

    def expire(self, org_id):
        with self.session_factory() as db:
            db.get(CustomerOnboarding, org_id).review_due_at = server.utcnow() - timedelta(seconds=1)
            db.commit()

    def decision(self, org_id, version=1, action='approve', **kwargs):
        return self.admin_client.post(f'/api/admin/onboarding/{org_id}', json={
            'version': version, 'action': action, 'reason': 'Vendor transition reviewed by owner'}, **kwargs)

    def test_customer_creation_grants_30_days_without_marking_dns_verified(self):
        before = server.utcnow()
        org_id = self.create()
        with self.session_factory() as db:
            row = db.get(CustomerOnboarding, org_id)
            org = db.get(Organization, org_id)
            self.assertEqual(org.verification_status, 'pending')
            self.assertGreater(row.review_due_at, before + timedelta(days=29))
            self.assertLess(row.review_due_at, server.utcnow() + timedelta(days=30, seconds=1))
            self.assertTrue(server.workspace_controls_available(db, org))
            event = db.scalar(select(AuditLog).where(AuditLog.action == 'onboarding.approved', AuditLog.organization_id == org_id))
            self.assertEqual(event.details['complimentary'], True)
        self.assertTrue(self.admin_client.get('/api/dashboard').json()['organization']['controls_enabled'])
        page = self.admin_client.get('/dashboard').text
        self.assertIn('onboarding-review-dialog', page)
        self.assertIn('onboarding.js', page)

    def test_due_review_pauses_exception_notice_is_deduplicated_and_renewal_is_explicit(self):
        org_id = self.create()
        self.expire(org_id)
        with self.session_factory() as db:
            self.assertFalse(server.workspace_controls_available(db, db.get(Organization, org_id)))
        onboarding.record_due()
        onboarding.record_due()
        rows = self.admin_client.get('/api/admin/onboarding').json()['customers']
        self.assertTrue(next(r for r in rows if r['id'] == org_id)['onboarding']['review_required'])
        with self.session_factory() as db:
            self.assertEqual(len(db.scalars(select(WorkspaceNotification).where(WorkspaceNotification.source_type == 'onboarding_review_due')).all()), 1)
        renewed = self.decision(org_id)
        self.assertEqual(renewed.status_code, 200, renewed.text)
        self.assertEqual(renewed.json()['onboarding']['version'], 2)
        self.assertFalse(renewed.json()['onboarding']['review_required'])
        self.expire(org_id)
        onboarding.record_due()
        with self.session_factory() as db:
            self.assertEqual(len(db.scalars(select(WorkspaceNotification).where(WorkspaceNotification.source_type == 'onboarding_review_due')).all()), 2)

    def test_stale_reviews_cannot_extend_a_new_approval(self):
        org_id = self.create()
        self.expire(org_id)
        self.assertEqual(self.decision(org_id).status_code, 200)
        self.assertEqual(self.decision(org_id, action='end').status_code, 409)
        with self.session_factory() as db:
            self.assertEqual(db.get(CustomerOnboarding, org_id).status, 'onboarding')
        self.assertEqual(self.decision(org_id, version=2).status_code, 409)

    def test_end_onboarding_preserves_verified_controls_and_never_charges(self):
        org_id = self.create()
        self.assertEqual(self.decision(org_id, action='end').status_code, 200)
        with self.session_factory() as db:
            row = db.get(CustomerOnboarding, org_id)
            self.assertEqual(row.status, 'ended')
            self.assertFalse(server.workspace_controls_available(db, db.get(Organization, org_id)))
            db.get(Organization, org_id).verification_status = 'verified'
            db.commit()
            self.assertTrue(server.workspace_controls_available(db, db.get(Organization, org_id)))
        self.assertEqual(self.decision(org_id, version=2).status_code, 200)

    def test_regular_customer_admin_cannot_self_grant_or_see_platform_queue(self):
        self.assertEqual(self.google_callback({'sub':'tenant-owner','email':'tenant@example.net','email_verified':True}).status_code,303)
        denied = self.client.post('/api/customers',json={'name':'Customer','domains':['other.example.org'],'onboarding':True})
        self.assertEqual(denied.status_code,403)
        with self.session_factory() as db:
            self.assertIsNone(db.scalar(select(Organization).where(Organization.domain == 'other.example.org')))
        normal = self.client.post('/api/customers',json={'name':'Customer','domains':['other.example.org']})
        self.assertEqual(normal.status_code,200)
        self.assertEqual(self.client.get('/api/admin/onboarding').status_code,403)
        org_id = normal.json()['results'][0]['organization_id']
        self.assertEqual(self.client.post(f'/api/admin/onboarding/{org_id}',json={'version':0,'action':'approve','reason':'Self granting should fail'}).status_code,403)
        self.assertNotIn('onboarding-review-dialog',self.client.get('/dashboard').text)

    def test_platform_admin_still_requires_approved_admin_membership(self):
        self.google_callback({'sub':'other-owner','email':'other@example.net','email_verified':True})
        org_id = self.client.post('/api/workspaces',json={'name':'Unrelated customer','domain':'unrelated.example.org'}).json()['organization_id']
        with self.session_factory() as db:
            owner = db.scalar(select(User).where(User.email == 'sean.dolbec@cybersecuritypilot.org'))
            membership = db.scalar(select(Membership).where(Membership.user_id == owner.id,Membership.organization_id == org_id))
            membership.status='revoked'
            db.commit()
        self.assertEqual(self.decision(org_id,version=0).status_code,404)
        self.assertNotIn(org_id,[r['id'] for r in self.admin_client.get('/api/admin/onboarding').json()['customers']])

    def test_cross_origin_and_workspace_scoped_access_keys_cannot_grant(self):
        org_id=self.create()
        self.assertEqual(self.decision(org_id,action='end',headers={'origin':'https://evil.example'}).status_code,403)
        response=self.admin_client.post('/api/user-keys',json={'name':'Onboarding scope test','expires_days':1})
        self.assertEqual(response.status_code,200,response.text)
        token=response.json()['token']
        self.assertEqual(self.client.get('/api/admin/onboarding',headers={'authorization':'Bearer '+token}).status_code,403)
        self.assertEqual(self.decision(org_id,action='end',headers={'authorization':'Bearer '+token}).status_code,403)

    def test_existing_customer_can_be_put_into_onboarding_without_switching_workspace(self):
        org_id=self.admin_client.post('/api/workspaces',json={'name':'Existing customer','domain':'existing.example.org'}).json()['organization_id']
        selected=self.admin_client.get('/api/dashboard').json()['organization']['id']
        self.assertEqual(self.decision(org_id,version=0).status_code,200)
        self.assertEqual(self.admin_client.get('/api/dashboard').json()['organization']['id'],selected)
