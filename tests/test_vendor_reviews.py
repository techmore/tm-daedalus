import unittest
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
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

    def test_concurrent_identical_requests_save_one_decision_and_audit(self):
        run=self.inventory();payload=self.payload(run)
        barrier=threading.Barrier(2);original=Session.flush
        def synchronized(db,*args,**kwargs):
            if any(isinstance(row,VendorReview) for row in db.new):barrier.wait(timeout=5)
            return original(db,*args,**kwargs)
        clients=[TestClient(server.app),TestClient(server.app)]
        for client in clients:client.cookies.update(self.client.cookies)
        try:
            with patch.object(Session,'flush',synchronized):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    responses=[future.result(timeout=15) for future in [pool.submit(client.post,'/api/vendor-reviews',json=payload) for client in clients]]
            self.assertEqual([r.status_code for r in responses],[200,200])
            self.assertEqual(sum(r.json()['created'] for r in responses),1)
            self.assertEqual(responses[0].json()['review']['id'],responses[1].json()['review']['id'])
            with self.session_factory() as db:
                self.assertEqual(len(db.scalars(select(VendorReview)).all()),1)
                audit=db.scalars(select(AuditLog).where(AuditLog.action=='vendor.review.recorded')).all()
                self.assertEqual(len(audit),1)
                self.assertEqual(audit[0].details['request_id'],payload['request_id'])
        finally:
            for client in clients:client.close()

    def test_paginated_history_keeps_older_current_decisions_and_frozen_rationale(self):
        run=self.inventory();org,user=self.context();now=server.utcnow()
        with self.session_factory() as db:
            saved=db.get(ExternalCheckRun,run)
            saved.snapshot={'external_resources':[{'host':'old.example','scheme':'https','port':None},{'host':'active.example','scheme':'https','port':None}]}
            for index in range(102):
                resource=0 if index==0 else 1
                db.add(VendorReview(organization_id=org,run_id=run,resource_index=resource,request_id=str(uuid4()),actor_user_id=user,origin={'host':'old.example' if resource==0 else 'active.example','scheme':'https','port':None},status='needs_action' if resource==0 else 'monitor',note='Old current rationale remains essential.' if resource==0 else f'Revision {index} rationale.',created_at=now))
            db.commit()
        first=self.client.get('/api/vendor-reviews',params={'run_id':run}).json()
        self.assertEqual(len(first['reviews']),2)
        self.assertEqual(len(first['history']),100)
        self.assertTrue(first['history_has_more'])
        older=self.client.get('/api/vendor-reviews',params={'run_id':run,'before':first['history_next_before']}).json()
        self.assertEqual(len(older['history']),2)
        self.assertFalse(older['history_has_more'])
        self.assertEqual(older['reviews'],first['reviews'])
        ids=[row['id'] for row in first['history']+older['history']]
        self.assertEqual(len(set(ids)),102)
        with self.session_factory() as db:
            frozen=server.capture_external_report_snapshot(db,db.get(Organization,org),db.get(User,user))
        reviews=frozen['checks']['web']['vendor_reviews']
        self.assertTrue(reviews['history_truncated'])
        self.assertEqual(len(reviews['history']),100)
        self.assertEqual(len(reviews['latest']),2)
        from daedalus import reports
        with patch.object(reports,'_paragraph',wraps=reports._paragraph) as paragraphs:
            pdf=reports.build_external_posture_pdf(frozen)
        self.assertTrue(pdf.startswith(b'%PDF'))
        values=[str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertIn('Old current rationale remains essential.',values)
