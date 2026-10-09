import unittest
from datetime import timedelta
from sqlalchemy import select
from daedalus import server
from daedalus.models import ExternalCheckRun, Organization, Membership, CISDevice, CISReport, ReportJob, Agent, ScanEvent
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
        org, _ = self.context()
        self.assertEqual(response.json()["organization_id"], org)
        self.assertIs(response.json()["can_manage"], True)
        self.assertTrue(response.json()["assessed_at"])
        areas={area['key']:area for area in response.json()['areas']}
        for key in ('dns','web','cis','meraki'):
            self.assertEqual(areas[key]['state'],'not_assessed')
        self.assertNotIn('token_hash',response.text)
        self.assertNotIn('device_fingerprint',response.text)

    def test_role_metadata_uses_current_approved_membership(self):
        org, user = self.context()
        with self.session_factory() as db:
            membership = db.scalar(select(Membership).where(Membership.organization_id == org, Membership.user_id == user))
            membership.role = "member"
            db.commit()
        response = self.client.get('/api/workspace-posture')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['organization_id'], org)
        self.assertIs(response.json()['can_manage'], False)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(self.client.post('/api/external-checks/dns/run').status_code, 403)

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

    def test_malformed_http_status_and_missing_headers_remain_unknown(self):
        org,_=self.context()
        for status in ('not captured', '200', True, 0, 999, None, {'code':200}):
            with self.subTest(status=status):
                self.save(org,kind='web',snapshot={'http_status':status})
                response=self.client.get('/api/workspace-posture')
                self.assertEqual(response.status_code,200)
                area=next(a for a in response.json()['areas'] if a['key']=='web')
                self.assertEqual(area['state'],'attention')
                self.assertIn('HTTPS unknown',area['summary'])
                self.assertIn('Selected header evidence unknown',area['summary'])
                self.assertNotIn('0 selected header(s) absent',area['summary'])

    def test_wrong_shape_header_evidence_does_not_break_summary(self):
        org,_=self.context()
        for headers in (['Content-Security-Policy'], 'not captured', True):
            with self.subTest(headers=headers):
                self.save(org,kind='web',snapshot={'http_status':200,'security_headers':headers})
                response=self.client.get('/api/workspace-posture')
                self.assertEqual(response.status_code,200)
                area=next(a for a in response.json()['areas'] if a['key']=='web')
                self.assertEqual(area['state'],'attention')
                self.assertIn('Selected header evidence unknown',area['summary'])

    def test_deeper_audit_has_separate_timestamp_without_raw_observations(self):
        org,_=self.context()
        self.save(org,kind='web-nikto',status='completed_with_warnings',snapshot={'findings':[{'description':'private detector text'}],'coverage_complete':False})
        area=next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='web')
        self.assertIn('1 observations',area['audit_summary'])
        self.assertTrue(area['audit_updated_at'])
        self.assertIsNone(area['updated_at'])
        self.assertEqual(area['state'],'attention')
        self.assertNotIn('private detector text',str(area))

    def test_latest_cis_results_surface_review_counts_without_raw_evidence(self):
        org,_=self.context()
        now=server.utcnow()
        with self.session_factory() as db:
            device=CISDevice(organization_id=org,device_fingerprint='fixture',name='Private endpoint',first_seen_at=now,last_seen_at=now)
            db.add(device);db.flush()
            report=CISReport(organization_id=org,device_id=device.id,client_report_hash='fixture',collected_at=now,created_at=now,summary={'score':24.68,'fail':90,'manual':9,'error':17},results=[{'details':'private local evidence'}])
            db.add(report);db.commit();report_id=report.id
        area=next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='cis')
        self.assertEqual(area['state'],'attention')
        self.assertIn('latest report pass rate: 24.68%',area['summary'])
        self.assertIn('90 failed · 9 manual · 17 errors',area['summary'])
        self.assertNotIn('private local evidence',str(area))
        self.assertNotIn('Private endpoint',str(area))
        for counts,state in [({'score':100,'fail':0,'manual':0,'error':0},'recorded'),({'score':100},'attention')]:
            with self.session_factory() as db:
                db.get(CISReport,report_id).summary=counts;db.commit()
            area=next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='cis')
            self.assertEqual(area['state'],state)

    def test_meraki_review_counts_and_failed_attempt_keep_saved_evidence(self):
        org,_=self.context();now=server.utcnow()
        with self.session_factory() as db:
            job=ReportJob(organization_id=org,report_type='meraki_security',domain='cybersecuritypilot.org',status='completed',progress=100,stage='PDF ready',file_name='fixture.pdf',created_at=now,updated_at=now,completed_at=now,report_snapshot={'meraki':{'summary':{'network_count':1,'device_count':0,'security_controls_unavailable':2},'findings':[{'status':'Review','title':'private observation'},{'status':'Info','title':'private info'}]}})
            db.add(job);db.commit()
        def area():return next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='meraki')
        self.assertEqual(area()['state'],'attention')
        self.assertIn('1 review observations · 2 controls unavailable',area()['summary'])
        self.assertNotIn('private observation',str(area()))
        with self.session_factory() as db:
            db.add(ReportJob(organization_id=org,report_type='meraki_security',domain='cybersecuritypilot.org',status='failed',progress=0,stage='Failed',file_name='failed.pdf',created_at=now,updated_at=now,report_snapshot={}));db.commit()
        self.assertEqual(area()['state'],'unavailable')
        self.assertIn('1 review observations',area()['summary'])
        self.assertTrue(area()['updated_at'])

    def test_missing_meraki_findings_are_not_zero_reviews(self):
        self.assertNotIn('review_observation_count',server.meraki_review_summary({'summary':{}}))
        self.assertEqual(server.meraki_review_summary({'findings':[]})['review_observation_count'],0)

    def test_cis_receipt_does_not_refresh_old_or_future_assessment(self):
        org,_=self.context();now=server.utcnow()
        with self.session_factory() as db:
            for index,collected in enumerate((now-timedelta(days=3),now+timedelta(days=1),None)):
                device=CISDevice(organization_id=org,device_fingerprint=f'coverage-{index}',name='Private endpoint',first_seen_at=now,last_seen_at=now)
                db.add(device);db.flush()
                if collected is not None:
                    db.add(CISReport(organization_id=org,device_id=device.id,client_report_hash=f'coverage-{index}',collected_at=collected,created_at=now,summary={'score':100,'fail':0,'manual':0,'error':0},results=[]))
            db.commit()
        area=next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='cis')
        self.assertEqual(area['state'],'attention')
        self.assertIn('0/3 devices with current assessments',area['summary'])
        self.assertIn('1 stale · 1 missing · 1 unknown',area['summary'])

    def test_cis_review_includes_each_devices_latest_assessment(self):
        org,_=self.context();now=server.utcnow()
        with self.session_factory() as db:
            for index,failures in enumerate((2,0)):
                device=CISDevice(organization_id=org,device_fingerprint=f'multi-{index}',name='Private endpoint',first_seen_at=now,last_seen_at=now)
                db.add(device);db.flush()
                db.add(CISReport(organization_id=org,device_id=device.id,client_report_hash=f'multi-{index}',collected_at=now-timedelta(minutes=1-index),created_at=now,summary={'score':100,'fail':failures,'manual':0,'error':0},results=[]))
            db.commit()
        area=next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='cis')
        self.assertEqual(area['state'],'attention')
        self.assertIn('2/2 devices with current assessments',area['summary'])
        self.assertIn('1 devices with checks needing review',area['summary'])
        self.assertIn('0 failed · 0 manual · 0 errors',area['summary'])

    def test_scanner_readiness_does_not_imply_saved_scan_evidence(self):
        org,_=self.context();now=server.utcnow()
        with self.session_factory() as db:
            agent=Agent(organization_id=org,name='Private scanner',token_hash='private-fixture-token',enabled=True,nmapui_connected=True,nmapui_ready=True,authorized_networks=['10.9.0.0/24'],last_seen_at=now,created_at=now)
            db.add(agent);db.commit();agent_id=agent.id
        def area():return next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='scanners')
        self.assertEqual(area()['state'],'not_assessed')
        self.assertIn('1/1 scan engines ready',area()['summary'])
        self.assertIn('0 with a completed latest scan',area()['summary'])
        self.assertIsNone(area()['updated_at'])
        def event(job,status,offset,kind='scan'):
            with self.session_factory() as db:
                db.add(ScanEvent(organization_id=org,agent_id=agent_id,event_name='job_status',source_job_id=job,source_job_type=kind,payload={'status':status,'job_type':kind},occurred_at=now+timedelta(seconds=offset),created_at=now));db.commit()
        event('completed-fixture','completed',0)
        self.assertEqual(area()['state'],'recorded')
        self.assertIn('1 with a completed latest scan',area()['summary'])
        event('latest-fixture','failed',1)
        self.assertEqual(area()['state'],'attention')
        event('latest-fixture','completed',2,'report')
        self.assertEqual(area()['state'],'attention')
        self.assertNotIn('10.9.0.0',str(area()))
        self.assertNotIn('private-fixture-token',str(area()))

    def test_one_recent_scan_does_not_hide_older_or_future_scan_evidence(self):
        org,_=self.context();now=server.utcnow()
        with self.session_factory() as db:
            agents=[]
            for offset in (0, -72, 1):
                agent=Agent(organization_id=org,name='Fixture',token_hash=f'fixture-{offset}',enabled=True,
                    nmapui_connected=True,nmapui_ready=True,authorized_networks=['127.0.0.1/32'],last_seen_at=now,created_at=now)
                db.add(agent);db.flush();agents.append(agent.id)
                db.add(ScanEvent(organization_id=org,agent_id=agent.id,event_name='job_status',
                    source_job_id=f'fixture-{offset}',source_job_type='scan',payload={'status':'completed','job_type':'scan'},
                    occurred_at=now+timedelta(hours=offset),created_at=now))
            db.commit()
        area=next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='scanners')
        self.assertEqual(area['state'],'attention')
        self.assertIn('3 with a completed latest scan',area['summary'])
        self.assertIn('1 within 48 hours · 1 older · 1 with unknown scan time',area['summary'])
        self.assertEqual(area['updated_at'],server.iso_utc(now))
        self.assertNotIn('127.0.0.1',str(area))

    def test_website_certificate_expiry_is_an_independent_review_signal(self):
        org,_=self.context();now=server.utcnow()
        for expiry,state,label in ((None,'attention','unknown'),('invalid','attention','unknown'),(now.isoformat(),'attention','unknown'),((now-timedelta(days=1)).replace(tzinfo=server.UTC).isoformat(),'attention','expired'),((now+timedelta(days=10)).replace(tzinfo=server.UTC).isoformat(),'attention','expires soon'),((now+timedelta(days=60)).replace(tzinfo=server.UTC).isoformat(),'recorded','expires')):
            with self.subTest(expiry=expiry):
                self.save(org,kind='web',snapshot={'http_status':200,'security_headers':{'Content-Security-Policy':"default-src 'self'"},'tls':{'valid_until':expiry}})
                area=next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='web')
                self.assertEqual(area['state'],state)
                self.assertIn(label,area['summary'])
        self.save(org,kind='web',status='queued')
        area=next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='web')
        self.assertEqual(area['state'],'running')
        self.assertIn('Saved certificate expires',area['summary'])
