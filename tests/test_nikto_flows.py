import unittest
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch
from sqlalchemy import select, create_engine, text
from daedalus import server
from daedalus.models import Organization, Membership, ExternalCheckRun, ProbationOverride, AuditLog
import test_active_website_flows as fixtures


class NiktoFlowsTests(unittest.TestCase):
    setUp = fixtures.ActiveWebsiteFlowsTests.setUp
    tearDown = fixtures.ActiveWebsiteFlowsTests.tearDown
    context = fixtures.ActiveWebsiteFlowsTests.context

    def snapshot(self, findings=None):
        return {'domain':'cybersecuritypilot.org','preset_version':'nikto-nondos-v1','engine':'nikto','coverage_complete':False,'findings':findings or [],'coverage_reason':'test_exhaustion_not_reported'}

    def run_check(self, snapshot=None):
        with patch.object(server,'run_nikto_check',return_value=snapshot or self.snapshot()) as collector:
            response=self.client.post('/api/external-checks/web-nikto/run')
            if response.status_code == 202:
                completed = server.process_next_website_audit()
                response.status_code = 200
                response._content = json.dumps(completed[1]).encode()
        return response,collector

    def test_queue_returns_before_collection_and_prevents_duplicate_requests(self):
        with patch.object(server, 'run_nikto_check', return_value=self.snapshot()) as collector:
            response = self.client.post('/api/external-checks/web-nikto/run')
            self.assertEqual(response.status_code, 202, response.text)
            self.assertEqual(response.json()['status'], 'queued')
            self.assertEqual(response.json()['queued_at'],response.json()['started_at'])
            self.assertIsNone(response.json()['collection_started_at'])
            collector.assert_not_called()
            self.assertEqual(self.client.post('/api/external-checks/web-nikto/run').status_code, 409)
            self.assertEqual(server.recover_interrupted_external_checks(), 0)
            completed = server.process_next_website_audit()
            self.assertEqual(completed[1]['id'], response.json()['id'])
            self.assertEqual(completed[1]['status'], 'completed_with_warnings')
            self.assertEqual(completed[1]['queued_at'],response.json()['queued_at'])
            self.assertIsNotNone(completed[1]['collection_started_at'])
            self.assertGreaterEqual(completed[1]['collection_started_at'],completed[1]['queued_at'])
            collector.assert_called_once()
            self.assertIsNone(server.process_next_website_audit())

    def test_queue_rechecks_admin_authorization_before_collection(self):
        response = self.client.post('/api/external-checks/web-nikto/run')
        self.assertEqual(response.status_code, 202)
        org_id,user_id=self.context()
        with self.session_factory() as db:
            db.scalar(select(Membership).where(Membership.organization_id==org_id,Membership.user_id==user_id)).role='user'
            db.commit()
        with patch.object(server, 'run_nikto_check') as collector:
            completed = server.process_next_website_audit()
        collector.assert_not_called()
        self.assertEqual(completed[1]['status'], 'failed')

    def test_queue_refuses_collection_after_domain_verification_is_lost(self):
        response = self.client.post('/api/external-checks/web-nikto/run')
        self.assertEqual(response.status_code, 202)
        org_id,_=self.context()
        with self.session_factory() as db:
            db.get(Organization,org_id).verification_status='pending'
            db.commit()
        with patch.object(server,'run_nikto_check') as collector:
            completed=server.process_next_website_audit()
        collector.assert_not_called()
        self.assertEqual(completed[1]['status'],'failed')
        self.assertEqual(completed[1]['id'],response.json()['id'])

    def test_queue_refuses_collection_if_workspace_domain_changed(self):
        response = self.client.post('/api/external-checks/web-nikto/run')
        self.assertEqual(response.status_code,202)
        org_id,_=self.context()
        with self.session_factory() as db:
            db.get(Organization,org_id).domain='different.example'
            db.commit()
        with patch.object(server,'run_nikto_check') as collector:
            completed=server.process_next_website_audit()
        collector.assert_not_called()
        self.assertEqual(completed[1]['status'],'failed')
        self.assertEqual(completed[1]['domain'],'cybersecuritypilot.org')

    def test_queue_capacity_rejects_submission_without_creating_a_run(self):
        org_id,user_id=self.context()
        with self.session_factory() as db:
            for _ in range(25):
                db.add(ExternalCheckRun(organization_id=org_id,check_type='web-nikto',
                    domain='cybersecuritypilot.org',status='queued',trigger_source='manual',
                    triggered_by_user_id=user_id,started_at=server.utcnow(),change_count=0))
            db.commit()
        with patch.object(server,'run_nikto_check') as collector:
            response=self.client.post('/api/external-checks/web-nikto/run')
        self.assertEqual(response.status_code,429)
        collector.assert_not_called()
        with self.session_factory() as db:
            self.assertEqual(len(db.scalars(select(ExternalCheckRun)).all()),25)

    def test_concurrent_submissions_create_only_one_queued_audit(self):
        org_id,user_id=self.context()
        barrier=threading.Barrier(2)
        def submit():
            barrier.wait(timeout=5)
            try:
                result=server._execute_external_check(org_id,user_id,'web-nikto','manual',True)
                return result['status']
            except server.HTTPException as exc:
                return exc.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(submit) for _ in range(2)]
            outcomes=[future.result(timeout=10) for future in futures]
        self.assertCountEqual(outcomes,['queued',409])
        with self.session_factory() as db:
            self.assertEqual(len(db.scalars(select(ExternalCheckRun)).all()),1)

    def test_concurrent_workers_collect_a_saved_run_only_once(self):
        self.assertEqual(self.client.post('/api/external-checks/web-nikto/run').status_code,202)
        barrier=threading.Barrier(2)
        def collect():
            barrier.wait(timeout=5)
            return server.process_next_website_audit()
        with patch.object(server,'run_nikto_check',return_value=self.snapshot()) as collector:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(collect) for _ in range(2)]
                outcomes=[future.result(timeout=10) for future in futures]
        self.assertEqual(sum(result is not None for result in outcomes),1)
        collector.assert_called_once()

    def test_queued_override_is_rechecked_after_expiration(self):
        org_id,user_id=self.context()
        with self.session_factory() as db:
            db.get(Organization,org_id).verification_status='pending'
            override=ProbationOverride(organization_id=org_id,granted_by_user_id=user_id,
                reason='fixture authorization',starts_at=server.utcnow()-timedelta(seconds=1),
                expires_at=server.utcnow()+timedelta(days=14),created_at=server.utcnow())
            db.add(override);db.commit();override_id=override.id
        self.assertEqual(self.client.post('/api/external-checks/web-nikto/run').status_code,202)
        with self.session_factory() as db:
            db.get(ProbationOverride,override_id).expires_at=server.utcnow()-timedelta(seconds=1)
            db.commit()
        with patch.object(server,'run_nikto_check') as collector:
            completed=server.process_next_website_audit()
        collector.assert_not_called()
        self.assertEqual(completed[1]['status'],'failed')

    def test_queue_timestamp_migration_preserves_legacy_rows_and_is_idempotent(self):
        engine=create_engine('sqlite://')
        try:
            with engine.begin() as connection:
                connection.execute(text("CREATE TABLE external_check_runs (id INTEGER PRIMARY KEY, trigger_source VARCHAR(24), started_at TIMESTAMP, snapshot JSON)"))
                connection.execute(text("INSERT INTO external_check_runs VALUES (1, 'manual', '2026-01-01', :snapshot)"), {'snapshot':json.dumps({'legacy':True})})
                server.ensure_external_check_columns(connection)
                server.ensure_external_check_columns(connection)
                row=connection.execute(text('SELECT started_at,snapshot,queued_at,collection_started_at,comparison_context FROM external_check_runs')).one()
                self.assertEqual(row[0],'2026-01-01')
                self.assertEqual(json.loads(row[1]),{'legacy':True})
                self.assertIsNone(row[2]);self.assertIsNone(row[3])
                self.assertIsNone(row[4])
        finally:
            engine.dispose()

    def test_queued_cancellation_is_audited_idempotent_and_never_collected(self):
        queued=self.client.post('/api/external-checks/web-nikto/run').json()
        path=f"/api/external-checks/web-nikto/runs/{queued['id']}/cancel"
        response=self.client.post(path)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['status'],'cancelled')
        self.assertIsNone(response.json()['collection_started_at'])
        self.assertEqual(self.client.post(path).status_code,200)
        with patch.object(server,'run_nikto_check') as collector:
            self.assertIsNone(server.process_next_website_audit())
        collector.assert_not_called()
        with self.session_factory() as db:
            self.assertEqual(len(db.scalars(select(AuditLog).where(AuditLog.action=='external_check.cancelled')).all()),1)

    def test_started_audit_cancellation_does_not_claim_running_collection_stopped(self):
        queued=self.client.post('/api/external-checks/web-nikto/run').json()
        with self.session_factory() as db:
            db.get(ExternalCheckRun,queued['id']).status='running';db.commit()
        response=self.client.post(f"/api/external-checks/web-nikto/runs/{queued['id']}/cancel")
        self.assertEqual(response.status_code,409)
        with self.session_factory() as db:
            self.assertEqual(db.get(ExternalCheckRun,queued['id']).status,'running')

    def test_queued_cancellation_requires_current_workspace_admin(self):
        queued=self.client.post('/api/external-checks/web-nikto/run').json()
        org_id,user_id=self.context()
        with self.session_factory() as db:
            db.scalar(select(Membership).where(Membership.organization_id==org_id,Membership.user_id==user_id)).role='user';db.commit()
        self.assertEqual(self.client.post(f"/api/external-checks/web-nikto/runs/{queued['id']}/cancel").status_code,403)
        with self.session_factory() as db:
            self.assertEqual(db.get(ExternalCheckRun,queued['id']).status,'queued')

    def test_pdf_keeps_completed_nikto_evidence_and_newer_cancelled_attempt(self):
        from daedalus import reports
        check={'run':{'id':51,'status':'completed_with_warnings','completed_at':'2026-10-04T07:47:52Z','snapshot':self.snapshot([{'test_id':'999100','method':'GET','path':'/trace.axd','description':'Infrastructure header observation'}])},
            'latest_attempt':{'id':52,'status':'cancelled','queued_at':'2026-10-04T07:49:23Z','started_at':'2026-10-04T07:49:23Z','collection_started_at':None,'error_summary':'Cancelled before collection'}}
        with patch.object(reports,'_paragraph',wraps=reports._paragraph) as paragraphs:
            pdf=reports.build_external_posture_pdf({'domain':'cybersecuritypilot.org','checks':{'web-nikto':check}})
        values=[str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertTrue(pdf.startswith(b'%PDF-'))
        self.assertTrue(any('Latest attempt #52: cancelled' in value and 'queued Oct 4' in value for value in values))
        self.assertTrue(any('saved successful run #51' in value for value in values))
        self.assertTrue(any('Infrastructure header observation' in value for value in values))
        self.assertFalse(any('collection started' in value.lower() for value in values))

    def test_queued_pdf_does_not_describe_collection_as_started(self):
        from daedalus import reports
        with patch.object(reports, '_paragraph', wraps=reports._paragraph) as paragraphs:
            pdf = reports.build_external_posture_pdf({'domain':'cybersecuritypilot.org','checks':{'web-nikto':{'latest_attempt':{'id':1,'status':'queued','started_at':'2026-10-04T04:11:44Z'}}}})
        values = [str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertTrue(pdf.startswith(b'%PDF-'))
        self.assertTrue(any('Queued Oct 4' in value for value in values))
        self.assertTrue(any('Collection has not started' in value for value in values))

    def test_verified_run_is_saved_with_actor_and_unknown_coverage(self):
        response,collector=self.run_check()
        self.assertEqual(response.status_code,200,response.text)
        collector.assert_called_once_with('cybersecuritypilot.org')
        self.assertEqual(response.json()['status'],'completed_with_warnings')
        history=self.client.get('/api/external-checks/web-nikto').json()
        self.assertEqual(history['runs'][0]['snapshot']['engine'],'nikto')
        self.assertTrue(history['runs'][0]['actor'])

    def test_unverified_and_nonadmin_cannot_invoke_collector(self):
        org_id,user_id=self.context()
        with self.session_factory() as db:
            db.get(Organization,org_id).verification_status='pending';db.commit()
        response,collector=self.run_check()
        self.assertEqual(response.status_code,403);collector.assert_not_called()
        with self.session_factory() as db:
            db.get(Organization,org_id).verification_status='verified'
            db.scalar(select(Membership).where(Membership.organization_id==org_id,Membership.user_id==user_id)).role='user';db.commit()
        response,collector=self.run_check()
        self.assertEqual(response.status_code,403);collector.assert_not_called()

    def test_additions_are_recorded_without_false_removals(self):
        finding={'signature_id':'nikto_1_GET','path':'/fixture','http_status':None}
        self.assertEqual(self.run_check()[0].status_code,200)
        added,_=self.run_check(self.snapshot([finding]))
        self.assertEqual(added.json()['change_count'],1)
        removed,_=self.run_check()
        self.assertEqual(removed.json()['change_count'],0)
        self.assertEqual(removed.json()['snapshot']['comparison_scope'],'new_observations_only')

    def test_missing_runtime_is_reported_as_failed_not_clean(self):
        response,_=self.run_check(dict(self.snapshot(),error_code='nikto_runtime_unavailable'))
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['status'],'failed')
        self.assertIn('runtime is unavailable',response.json()['error_summary'])

    def test_recurring_nikto_schedule_is_not_available(self):
        self.assertEqual(self.client.put('/api/external-checks/web-nikto/schedule',json={'enabled':True,'interval_hours':24}).status_code,404)

    def test_nikto_evidence_renders_in_themed_posture_pdf(self):
        from daedalus.reports import build_external_posture_pdf
        snapshot=self.snapshot([{'test_id':'1234','method':'GET','path':'/fixture','description':'Missing header <script>fixture</script>'}])
        pdf=build_external_posture_pdf({'domain':'cybersecuritypilot.org','checks':{'web-nikto':{'run':{'id':1,'status':'completed_with_warnings','snapshot':snapshot}}}})
        self.assertTrue(pdf.startswith(b'%PDF-'))

    def test_running_nikto_pdf_has_start_time_and_pending_findings_note(self):
        from daedalus import reports
        with patch.object(reports, '_paragraph', wraps=reports._paragraph) as paragraphs:
            pdf=reports.build_external_posture_pdf({'domain':'cybersecuritypilot.org','checks':{'web-nikto':{'latest_attempt':{'id':43,'status':'running','started_at':'2026-10-04T04:11:44Z'}}}})
        values=[str(call.args[0]) for call in paragraphs.call_args_list]
        self.assertTrue(pdf.startswith(b'%PDF-'))
        self.assertTrue(any('Started Oct 4' in value for value in values))
        self.assertTrue(any('still running when the report snapshot was captured' in value for value in values))
