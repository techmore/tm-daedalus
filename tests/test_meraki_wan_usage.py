import unittest
from daedalus.meraki_api import MerakiAPIError, compare_meraki_snapshots
from daedalus.meraki_wan import summarize_wan_usage


def interval(start='2026-10-08T00:00:00Z', end='2026-10-08T01:00:00Z', **counters):
    return {'startTime': start, 'endTime': end, 'byInterface': [{'interface': 'wan1', **counters}]}


class MerakiWanUsageTests(unittest.TestCase):
    def test_byte_units_weighted_rates_zero_and_missing_evidence(self):
        data = summarize_wan_usage([
            interval(sent=450_000_000, received=0),
            interval('2026-10-08T01:00:00Z', '2026-10-08T01:30:00Z', sent=450_000_000, received=True),
            interval('2026-10-08T02:00:00Z', '2026-10-08T03:00:00Z', sent=-1)])
        interface = data['interfaces'][0]
        sent, received = interface['directions']['sent'], interface['directions']['received']
        self.assertEqual(sent['observed_bytes'], 900_000_000)
        self.assertEqual(sent['observed_seconds'], 5400)
        self.assertAlmostEqual(sent['average_mbps'], 4/3)
        self.assertEqual(sent['peak_interval_average_mbps'], 2)
        self.assertEqual(received['observed_bytes'], 0)
        self.assertEqual(received['average_mbps'], 0)
        self.assertEqual(received['measured_interval_count'], 1)
        self.assertEqual(interface['reported_interval_count'], 3)
        self.assertEqual(data['intervals'][2]['bytes'], {})
        self.assertEqual(data['intervals'][2]['counter_coverage'], 'partial')
        self.assertEqual(data['requested_resolution_seconds'], 3600)
        self.assertNotIn('utilization_percent', data)

    def test_sorted_intervals_timezone_equivalence_and_privacy(self):
        second=interval('2026-10-08T01:00:00Z', '2026-10-08T02:00:00Z', sent=0, received=0)
        first=interval('2026-10-07T20:00:00-04:00', '2026-10-07T21:00:00-04:00', sent=0, received=0)
        first['secret']='never-store';first['byInterface'][0]['clientMac']='never-store'
        data=summarize_wan_usage([second,first])
        self.assertEqual(data['first_interval_start'], '2026-10-08T00:00:00+00:00')
        self.assertEqual(data['interfaces'][0]['directions']['sent']['observed_seconds'], 7200)
        self.assertNotIn('never-store', str(data))
        with self.assertRaises(MerakiAPIError):summarize_wan_usage([first,interval(sent=0)])

    def test_invalid_shapes_overlaps_and_resource_limits(self):
        valid=interval(sent=1)
        cases=[None,[None],[{}],[valid,valid],
               [interval('2026-10-08T00:30:00Z','2026-10-08T01:30:00Z'),valid],
               [{**valid,'startTime':'2026-10-08T00:00:00'}],
               [{**valid,'endTime':valid['startTime']}],
               [{**valid,'endTime':'2026-10-08T02:00:00Z'}],
               [{**valid,'byInterface':None}],
               [{**valid,'byInterface':valid['byInterface']*2}],
               [{**valid,'byInterface':[{'interface':'bad/name'}]}],
               [valid]*1001]
        for raw in cases:
            with self.subTest(raw=str(raw)[:70]),self.assertRaises(MerakiAPIError):summarize_wan_usage(raw)
        with self.assertRaises(MerakiAPIError):summarize_wan_usage([valid,interval('2026-10-16T00:00:00Z','2026-10-16T01:00:00Z')])

    def test_unavailable_counters_are_not_zero_or_full_day_coverage(self):
        for value in (None,True,-1,1.5,1_000_000_000_001):
            with self.subTest(value=value):
                data=summarize_wan_usage([interval(sent=value,received=value)])
                self.assertEqual(data['interfaces'][0]['directions'],{})
        empty=summarize_wan_usage([])
        self.assertEqual(empty['interval_count'],0)
        self.assertEqual(empty['interfaces'],[])
        self.assertIsNone(empty['first_interval_start'])

    def test_rolling_counters_do_not_claim_configuration_changes(self):
        def snapshot(count):return {'organization':{'id':'ORG'},'security_controls':[{'network_id':'N_1','control':'WAN usage history','status':'complete','data':{'count':count}}]}
        self.assertEqual(compare_meraki_snapshots(snapshot(1),snapshot(2))['changed_control_count'],0)

    def test_projection_bounds_interfaces_and_omits_raw_interval_and_unknown_fields(self):
        from daedalus.meraki_wan import project_wan_usage
        raw={'interfaces':[{'interface':'wan1','reported_interval_count':1,'secret':'never-store',
            'directions':{'sent':{'observed_bytes':0,'average_mbps':float('inf'),'secret':'never-store'}}}]*33,
            'intervals':['never-store'],'scope':'x'*500}
        result=project_wan_usage(raw)
        self.assertEqual(len(result['interfaces']),32)
        self.assertEqual(result['additional_interfaces'],1)
        self.assertEqual(len(result['scope']),400)
        self.assertEqual(result['interfaces'][0]['directions']['sent']['observed_bytes'],0)
        self.assertIsNone(result['interfaces'][0]['directions']['sent']['average_mbps'])
        self.assertNotIn('never-store',str(result))

    def test_original_seven_day_hourly_window_preserves_all_intervals(self):
        from datetime import datetime, timedelta, UTC
        start=datetime(2026,10,1,tzinfo=UTC)
        raw=[interval((start+timedelta(hours=i)).isoformat(),(start+timedelta(hours=i+1)).isoformat(),sent=0,received=0) for i in range(168)]
        data=summarize_wan_usage(raw)
        self.assertEqual(data['requested_timespan_seconds'],604800)
        self.assertEqual(data['interval_count'],168)
        self.assertEqual(data['interfaces'][0]['directions']['sent']['observed_seconds'],604800)
        self.assertEqual(data['interfaces'][0]['directions']['sent']['measured_interval_count'],168)

    def test_pdf_new_summary_marker_keeps_legacy_rendering_and_complete_json(self):
        from datetime import datetime, timedelta, UTC
        from copy import deepcopy
        from io import BytesIO
        from pypdf import PdfReader
        from daedalus.reports import build_meraki_security_pdf
        start=datetime(2026,10,1,tzinfo=UTC)
        data=summarize_wan_usage([interval((start+timedelta(hours=i)).isoformat(),(start+timedelta(hours=i+1)).isoformat(),sent=100,received=200)for i in range(168)])
        control={'control':'WAN usage history','status':'complete','network_name':'Fixture','data':data}
        snapshot={'domain':'example.test','meraki':{'organization':{'name':'Fixture'},'collected_at':'2026-10-08T00:00:00Z',
            'security_controls':[control],'wan_usage':[deepcopy(control)]}}
        legacy=PdfReader(BytesIO(build_meraki_security_pdf(snapshot)))
        bad=deepcopy(snapshot);bad['meraki']['security_controls'][0]['pdf_evidence_summary_version']=True
        unsupported=PdfReader(BytesIO(build_meraki_security_pdf(bad)))
        self.assertEqual([page.get_contents().get_data()for page in legacy.pages],[page.get_contents().get_data()for page in unsupported.pages])
        compact=deepcopy(snapshot);compact['meraki']['security_controls'][0]['pdf_evidence_summary_version']=1
        rendered=PdfReader(BytesIO(build_meraki_security_pdf(compact)))
        self.assertLess(len(rendered.pages),len(legacy.pages))
        self.assertIn('See WAN usage history appendix', '\n'.join(page.extract_text()for page in rendered.pages))
        self.assertEqual(len(compact['meraki']['security_controls'][0]['data']['intervals']),168)
        self.assertEqual(snapshot['meraki']['security_controls'][0],control)
