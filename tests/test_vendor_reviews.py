import unittest
import json
from uuid import uuid4
from sqlalchemy import select
from daedalus import server
from daedalus.models import AuditLog, ExternalCheckRun, Membership, Organization, VendorReview, User
import test_active_website_flows as fixtures


class VendorReviewTests(unittest.TestCase):
    setUp = fixtures.ActiveWebsiteFlowsTests.setUp
    tearDown = fixtures.ActiveWebsiteFlowsTests.tearDown
    context = fixtures.ActiveWebsiteFlowsTests.context

    def inventory(self, org=None):
        org = org or self.context()[0]
        with self.session_factory() as db:
            run = ExternalCheckRun(organization_id=org, check_type='web', domain='cybersecuritypilot.org', status='completed', trigger_source='manual', started_at=server.utcnow(), completed_at=server.utcnow(), snapshot={'external_resources':[{'host':'cdn.example','scheme':'https','port':None,'resource_types':['Script']}]}, change_count=0)
            db.add(run); db.commit(); return run.id

    def payload(self, run):
        return {'run_id':run,'resource_index':0,'request_id':str(uuid4()),'status':'needs_action','note':'Owner must review this dependency.'}

    def test_append_only_history_and_idempotent_retry(self):
        run=self.inventory();payload=self.payload(run)
        first=self.client.post('/api/vendor-reviews',json=payload)
        self.assertEqual(first.status_code,200,first.text)
        self.assertTrue(first.json()['created'])
        self.assertEqual(first.json()['review']['origin'],{'host':'cdn.example','scheme':'https','port':None})
        self.assertTrue(first.json()['review']['created_at'])
        retry=self.client.post('/api/vendor-reviews',json=payload)
        self.assertFalse(retry.json()['created'])
        self.assertEqual(retry.json()['review']['id'],first.json()['review']['id'])
        changed=dict(payload,status='reviewed')
        self.assertEqual(self.client.post('/api/vendor-reviews',json=changed).status_code,409)
        changed['request_id']=str(uuid4())
        self.assertTrue(self.client.post('/api/vendor-reviews',json=changed).json()['created'])
        saved=self.client.get('/api/vendor-reviews',params={'run_id':run}).json()
        self.assertEqual(len(saved['history']),2)
        self.assertEqual(len(saved['reviews']),1)
        self.assertEqual(saved['reviews'][0]['status'],'reviewed')
        self.assertFalse(saved['security_assessment'])
        with self.session_factory() as db:
            self.assertEqual(len(db.scalars(select(AuditLog).where(AuditLog.action=='vendor.review.recorded')).all()),2)
            self.assertEqual(len(db.scalars(select(VendorReview)).all()),2)
        next_run=self.inventory()
        self.assertEqual(self.client.get('/api/vendor-reviews',params={'run_id':next_run}).json()['reviews'],[])

    def test_invalid_inventory_and_rationale_are_rejected(self):
        run=self.inventory();payload=self.payload(run)
        for patch in ({'resource_index':1},{'resource_index':True},{'status':'secure'},{'note':'        '},{'run_id':999999}):
            response=self.client.post('/api/vendor-reviews',json=dict(payload,**patch))
            self.assertIn(response.status_code,(404,422),response.text)
        with self.session_factory() as db:
            db.get(ExternalCheckRun,run).status='failed';db.commit()
        self.assertEqual(self.client.post('/api/vendor-reviews',json=payload).status_code,404)

    def test_workspace_scope_live_role_and_sign_in_are_required(self):
        run=self.inventory();org,user=self.context()
        with self.session_factory() as db:
            other=Organization(name='Other',slug='review-other',domain='other.example',verification_status='verified',created_at=server.utcnow())
            db.add(other);db.commit();other_id=other.id
        other_run=self.inventory(other_id)
        self.assertEqual(self.client.post('/api/vendor-reviews',json=self.payload(other_run)).status_code,404)
        self.assertEqual(self.client.get('/api/vendor-reviews',params={'run_id':other_run}).status_code,404)
        with self.session_factory() as db:
            member=db.scalar(select(Membership).where(Membership.organization_id==org,Membership.user_id==user));member.role='user';db.commit()
        self.assertEqual(self.client.post('/api/vendor-reviews',json=self.payload(run)).status_code,403)
        self.assertEqual(self.client.get('/api/vendor-reviews',params={'run_id':run}).status_code,200)
        self.client.post('/logout')
        self.assertEqual(self.client.get('/api/vendor-reviews',params={'run_id':run}).status_code,401)

    def test_report_snapshot_freezes_decisions_and_reviewer(self):
        run=self.inventory();payload=self.payload(run)
        self.client.post('/api/vendor-reviews',json=payload)
        org,user=self.context()
        with self.session_factory() as db:
            frozen=server.capture_external_report_snapshot(db,db.get(Organization,org),db.get(User,user))
        saved=json.dumps(frozen)
        decisions=frozen['checks']['web']['vendor_reviews']
        self.assertEqual(decisions['run_id'],run)
        self.assertEqual(decisions['latest'][0]['status'],'needs_action')
        self.assertTrue(decisions['latest'][0]['reviewer'])
        self.assertFalse(decisions['security_assessment'])
        changed=dict(payload,request_id=str(uuid4()),status='reviewed',note='Later review decision with a different rationale.')
        self.client.post('/api/vendor-reviews',json=changed)
        self.assertEqual(json.dumps(frozen),saved)
        with self.session_factory() as db:
            newer=server.capture_external_report_snapshot(db,db.get(Organization,org),db.get(User,user))
        self.assertEqual(newer['checks']['web']['vendor_reviews']['latest'][0]['status'],'reviewed')
        self.assertEqual(len(newer['checks']['web']['vendor_reviews']['history']),2)
        self.inventory()
        with self.session_factory() as db:
            latest=server.capture_external_report_snapshot(db,db.get(Organization,org),db.get(User,user))
        self.assertEqual(latest['checks']['web']['vendor_reviews']['latest'],[])
