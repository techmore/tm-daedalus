import unittest
from daedalus.meraki_api import MerakiAPIError, summarize_wan_uplinks, compare_meraki_snapshots


class MerakiWanTests(unittest.TestCase):
    def test_assigned_interfaces_preserve_state_and_omit_addresses(self):
        data = summarize_wan_uplinks([
            {'serial': 'MX1', 'networkId': 'N_1', 'lastReportedAt': '2026-10-08T00:00:00Z', 'uplinks': [
                {'interface': 'wan1', 'status': 'active', 'publicIp': 'never-store'},
                {'interface': 'wan2', 'status': 'not connected'},
                {'interface': 'cellular', 'status': None}]},
            {'serial': 'OTHER', 'networkId': 'OTHER', 'uplinks': []}], {'MX1': 'N_1', 'MX2': 'N_1'})
        self.assertEqual(data['rows'][0]['last_reported_at'], '2026-10-08T00:00:00Z')
        self.assertEqual(data['reported_device_count'], 1)
        self.assertEqual(data['missing_device_count'], 1)
        self.assertEqual(data['omitted_device_count'], 1)
        self.assertEqual(data['state_counts'], {'active': 1, 'not connected': 1, 'unknown': 1})
        self.assertNotIn('never-store', str(data))
        self.assertNotIn('speed', str(data))
        self.assertEqual(summarize_wan_uplinks([], {'MX1': 'N_1'})['missing_device_count'], 1)

    def test_invalid_identities_networks_and_interfaces_are_unavailable(self):
        row = {'serial': 'MX1', 'networkId': 'N_1', 'uplinks': [{'interface': 'wan1', 'status': 'active'}]}
        for raw in (None, [row, row], [{**row, 'networkId': 'OTHER'}],
                    [{**row, 'uplinks': None}], [{**row, 'uplinks': row['uplinks'] * 2}],
                    [{**row, 'uplinks': [{'interface': 'unsupported'}]}], [row] * 1001):
            with self.subTest(raw=str(raw)[:80]), self.assertRaises(MerakiAPIError):
                summarize_wan_uplinks(raw, {'MX1': 'N_1'})

    def test_link_state_changes_do_not_claim_configuration_changes(self):
        def snapshot(state):
            return {'organization': {'id': 'ORG'}, 'security_controls': [{'control': 'WAN uplink states',
                'network_id': '', 'status': 'complete', 'data': {'state': state}}]}
        self.assertEqual(compare_meraki_snapshots(snapshot('active'), snapshot('ready'))['changed_control_count'], 0)

    def test_missing_or_invalid_report_times_remain_unavailable(self):
        for timestamp in (None, True, 'invalid', '2026-10-08T00:00:00', 'x' * 65):
            with self.subTest(timestamp=timestamp):
                data = summarize_wan_uplinks([{'serial': 'MX1', 'networkId': 'N_1',
                    'lastReportedAt': timestamp, 'uplinks': [{'interface': 'wan1', 'status': 'active'}]}], {'MX1': 'N_1'})
                self.assertIsNone(data['rows'][0]['last_reported_at'])
