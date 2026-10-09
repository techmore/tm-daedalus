"""Saved failure → resumed collection, including real SQLite admission."""
from concurrent.futures import ThreadPoolExecutor
import threading
import unittest
import asyncio
from unittest.mock import AsyncMock, patch
from sqlalchemy import select
from daedalus import server
from daedalus.models import AuditLog,ExternalCheckRun,ExternalCheckSchedule,Organization,Membership,WorkspaceNotification
import test_cis_pdf_flow as fixtures

BASE={'domain':'cybersecuritypilot.org','records':{'A':['192.0.2.1']},'resolver_errors':{}}

class CollectionRecoveryTests(unittest.TestCase):
    setUp=fixtures.CISReportPDFFlowTests.setUp
    tearDown=fixtures.CISReportPDFFlowTests.tearDown

    def context(self):
        with self.session_factory() as db:
            org=db.scalar(select(Organization).where(Organization.domain=='cybersecuritypilot.org'))
            member=db.scalar(select(Membership).where(Membership.organization_id==org.id,Membership.role=='admin'))
            return org.id,member.user_id

    def collect(self,value=BASE,kind='dns',source='manual',error=None):
        org,user=self.context()
        with patch.object(server,'run_dns_check' if kind=='dns' else 'run_website_check',return_value=value,side_effect=error), patch.object(server,'refresh_workspace_icon'):
            return server.execute_external_check(org,None if source=='schedule' else user,kind,source)

    def notices(self):return self.client.get('/api/notifications').json()['notifications']

    def test_failure_repeats_then_identical_baseline_resumes_once_with_dated_audit(self):
        baseline=self.collect()
        first=self.collect(error=RuntimeError('private detail'))
        failed=self.collect(error=RuntimeError('private detail'))
        self.assertTrue(failed['notice_suppressed']);self.assertEqual(len(self.notices()),1)
        resumed=self.collect()
        self.assertEqual(resumed['change_count'],0);self.assertFalse(resumed['notice_suppressed'])
        self.assertEqual(resumed['comparison_context']['previous_run_id'],baseline['id'])
        notice=self.notices()[0]
        self.assertEqual(notice['reason'],'collection_resumed');self.assertEqual(notice['source_id'],resumed['id'])
        self.assertEqual(notice['tab'],'dns');self.assertIn('collection resumed',notice['title'])
        self.assertIn(f"failed attempt {failed['id']}",notice['summary'])
        self.assertNotIn('private detail',str(self.notices()))
        self.collect();self.assertEqual(len(self.notices()),2)
        with self.session_factory() as db:
            run=db.get(ExternalCheckRun,resumed['id'])
            event=db.scalar(select(AuditLog).where(AuditLog.action=='external_check.completed').order_by(AuditLog.id.desc()).offset(1))
            self.assertEqual(event.details['run_id'],run.id)
            self.assertTrue(event.details['collection_resumed'])
            self.assertEqual(event.details['previous_failed_run_id'],failed['id'])
            self.assertEqual(notice['detected_at'],server.iso_utc(run.completed_at))
            self.assertEqual(db.get(ExternalCheckRun,first['id']).status,'failed')

    def test_first_success_after_failure_keeps_first_baseline_and_warning_limits(self):
        self.collect(error=TimeoutError('private'))
        resumed=self.collect({'records':{},'resolver_errors':{'TXT':'TimeoutError'}})
        self.assertTrue(resumed['initial_baseline'])
        self.assertEqual(resumed['status'],'completed_with_warnings')
        notice=self.notices()[0]
        self.assertEqual(notice['reason'],'collection_resumed')
        self.assertIn('with limitations',notice['summary'])
        self.assertIn('first saved baseline',notice['summary'])
        self.assertIn('Check warning',notice['summary'])
        self.assertNotIn('No confirmed changes',notice['summary'])
        self.assertIn('does not establish that security findings were resolved',notice['summary'])

    def test_scheduled_website_recovery_retains_changes_in_one_notice(self):
        org,_=self.context()
        with self.session_factory() as db:
            db.add(ExternalCheckSchedule(organization_id=org,check_type='web',enabled=True,interval_hours=24,next_run_at=server.utcnow(),updated_at=server.utcnow()))
            db.commit()
        self.collect({'http_status':200,'security_headers':{'Content-Security-Policy':'default-src self'}},kind='web',source='schedule')
        failed=self.collect(kind='web',source='schedule',error=RuntimeError('private'))
        resumed=self.collect({'http_status':200,'security_headers':{'Content-Security-Policy':'default-src none'}},kind='web',source='schedule')
        self.assertGreater(resumed['change_count'],0)
        notice=self.notices()[0]
        self.assertEqual(notice['reason'],'collection_resumed');self.assertEqual(notice['tab'],'web')
        self.assertIn('material change',notice['summary'])
        self.assertIn(str(failed['id']),notice['summary'])
        self.assertEqual(len(self.notices()),2)
        with self.session_factory() as db:
            audit=db.scalar(select(AuditLog).where(AuditLog.action=='external_check.completed').order_by(AuditLog.id.desc()))
            self.assertIsNone(audit.actor_user_id);self.assertEqual(audit.details['source'],'schedule')

    def test_restart_interruption_then_recovery_retains_failed_evidence(self):
        org,user=self.context()
        with self.session_factory() as db:
            run=ExternalCheckRun(organization_id=org,domain='cybersecuritypilot.org',check_type='dns',status='running',trigger_source='manual',triggered_by_user_id=user,started_at=server.utcnow(),snapshot={'partial':'retained'},change_count=0)
            db.add(run);db.commit();identifier=run.id
        self.assertEqual(server.recover_interrupted_external_checks(),1)
        self.assertEqual(server.recover_interrupted_external_checks(),0)
        self.collect();self.collect()
        self.assertEqual(len(self.notices()),2)
        self.assertEqual(self.notices()[0]['reason'],'collection_resumed')
        with self.session_factory() as db:self.assertEqual(db.get(ExternalCheckRun,identifier).snapshot,{'partial':'retained'})

    def test_other_workspace_type_or_domain_failure_does_not_claim_recovery(self):
        org,_=self.context()
        with self.session_factory() as db:
            foreign=Organization(name='Other',slug='other-recovery',domain='other.example',created_at=server.utcnow())
            db.add(foreign);db.flush()
            for organization,kind,domain in [(foreign.id,'dns','other.example'),(org,'web','cybersecuritypilot.org'),(org,'dns','old.example')]:
                db.add(ExternalCheckRun(organization_id=organization,domain=domain,check_type=kind,status='failed',trigger_source='manual',started_at=server.utcnow(),completed_at=server.utcnow(),change_count=0))
            db.commit()
        self.collect()
        self.assertEqual(self.notices(),[])

    def test_database_admission_blocks_second_worker_without_holding_collection_lock(self):
        org,user=self.context()
        entered=threading.Event();release=threading.Event()
        def held(*args,**kwargs):
            entered.set()
            self.assertTrue(release.wait(10))
            return BASE
        with patch.object(server,'run_dns_check',side_effect=held) as collector:
            with ThreadPoolExecutor(max_workers=1) as executor:
                first=executor.submit(server._execute_external_check,org,user,'dns','manual')
                try:
                    self.assertTrue(entered.wait(5))
                    with self.assertRaises(server.HTTPException) as error:
                        server._execute_external_check(org,user,'dns','manual')
                    self.assertEqual(error.exception.status_code,409)
                    # A different check can claim/commit while DNS collection waits.
                    with patch.object(server,'run_website_check',return_value={'http_status':503}):
                        second=server._execute_external_check(org,user,'web','manual')
                    self.assertEqual(second['check_type'],'web')
                finally:release.set()
                self.assertEqual(first.result(timeout=10)['status'],'completed')
                collector.assert_called_once()
        with self.session_factory() as db:
            self.assertEqual(len(db.scalars(select(ExternalCheckRun).where(ExternalCheckRun.organization_id==org,ExternalCheckRun.check_type=='dns')).all()),1)

    def test_scheduler_defers_database_busy_claim_without_recording_a_collection_failure(self):
        org, user = self.context()
        with self.session_factory() as db:
            schedule = ExternalCheckSchedule(
                organization_id=org, check_type='dns', enabled=True,
                interval_hours=24, next_run_at=server.utcnow(),
                updated_at=server.utcnow(),
            )
            db.add(schedule)
            db.add(ExternalCheckRun(
                organization_id=org, domain='cybersecuritypilot.org',
                check_type='dns', status='running', trigger_source='manual',
                triggered_by_user_id=user, started_at=server.utcnow(),
                change_count=0,
            ))
            db.commit()
            schedule_id = schedule.id

        deferred = []

        async def run_cycle_operation(function, *args):
            if function is server.claim_due_external_check_schedules:
                return function(*args)
            if function is server.execute_external_check:
                # Bypass the process-local guard to exercise the SQL admission.
                return server._execute_external_check(*args)
            if function is server.defer_external_check_schedule:
                deferred.append(args[0])
                return function(*args)
            if function in (server.fail_external_check_schedule,
                            server.finish_external_check_schedule):
                self.fail('A busy collection must defer, without a failed attempt')
            return []

        with patch.object(server, 'run_in_threadpool', side_effect=run_cycle_operation), \
                patch.object(server.asyncio, 'sleep', new=AsyncMock(side_effect=asyncio.CancelledError)), \
                patch.object(server, 'run_dns_check') as collector:
            with self.assertRaises(asyncio.CancelledError):
                asyncio.run(server.external_check_scheduler())

        self.assertEqual(deferred, [schedule_id])
        collector.assert_not_called()
        self.assertEqual(self.notices(), [])
        with self.session_factory() as db:
            schedule = db.get(ExternalCheckSchedule, schedule_id)
            self.assertEqual(schedule.last_run_status, 'deferred')
            self.assertGreater(schedule.next_run_at, server.utcnow().replace(tzinfo=None))
            self.assertEqual(len(db.scalars(select(ExternalCheckRun)).all()), 1)

    def test_authenticated_history_notice_report_and_reload_preserve_the_evidence_trail(self):
        import hashlib,json
        from fastapi.testclient import TestClient
        from daedalus.models import ReportJob
        def request(value=BASE,error=None):
            with patch.object(server,'run_dns_check',return_value=value,side_effect=error):
                response=self.client.post('/api/external-checks/dns/run')
            self.assertEqual(response.status_code,200,response.text)
            return response.json()
        baseline=request()
        report=self.client.post('/api/reports/external-posture')
        self.assertEqual(report.status_code,200,report.text)
        old_id=report.json()['id']
        original=self.client.get(f'/api/reports/{old_id}/download').content
        self.assertTrue(original.startswith(b'%PDF-'))
        with self.session_factory() as db:
            original_snapshot=json.dumps(db.get(ReportJob,old_id).report_snapshot,sort_keys=True)
        failed=request(error=RuntimeError('private collector reason'))
        request(error=RuntimeError('private collector reason'))
        history=self.client.get('/api/external-checks/dns').json()
        self.assertEqual(history['latest_snapshot_run']['id'],baseline['id'])
        self.assertEqual(history['runs'][0]['status'],'failed')
        resumed=request()
        self.assertTrue(resumed['collection_resumed']);self.assertTrue(self.collect()['notice_suppressed'])
        notices=self.notices()
        recovery=next(n for n in notices if n['reason']=='collection_resumed')
        self.assertEqual(recovery['source_id'],resumed['id']);self.assertEqual(len(notices),2)
        report=self.client.post('/api/reports/external-posture');self.assertEqual(report.status_code,200,report.text)
        identifier=report.json()['id']
        downloaded=self.client.get(f'/api/reports/{identifier}/download')
        self.assertEqual(downloaded.status_code,200);self.assertTrue(downloaded.content.startswith(b'%PDF-'))
        with self.session_factory() as db:
            snapshot=db.get(ReportJob,identifier).report_snapshot
            current=db.scalar(select(ExternalCheckRun).where(ExternalCheckRun.check_type=='dns').order_by(ExternalCheckRun.id.desc()))
            self.assertEqual(snapshot['checks']['dns']['run']['id'],current.id)
            self.assertEqual(snapshot['checks']['dns']['run']['comparison_context']['previous_run_id'],resumed['id'])
            self.assertEqual(db.get(ExternalCheckRun,failed['id']).status,'failed')
            self.assertEqual(json.dumps(db.get(ReportJob,old_id).report_snapshot,sort_keys=True),original_snapshot)
        self.assertEqual(hashlib.sha256(self.client.get(f'/api/reports/{old_id}/download').content).digest(),hashlib.sha256(original).digest())
        with TestClient(server.app,cookies=self.client.cookies) as reloaded:
            self.assertEqual(reloaded.get('/api/notifications').json()['notifications'],notices)
            self.assertEqual(reloaded.get('/api/reports').json()['total_count'],2)
            self.assertEqual(reloaded.post(f"/api/notifications/{recovery['id']}/read").status_code,200)
        receipt=next(n for n in self.notices() if n['id']==recovery['id'])
        self.assertIsNotNone(receipt['read_at'])
