import unittest
from unittest.mock import patch
from sqlalchemy import select
from daedalus import server
from daedalus.models import Organization, Membership
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
        return response,collector

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
