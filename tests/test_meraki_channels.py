import unittest

from daedalus.meraki_api import MerakiAPIError, summarize_channel_utilization, compare_meraki_snapshots


class MerakiChannelTests(unittest.TestCase):
    def test_nested_bands_zero_partial_and_scoped_inventory(self):
        data = summarize_channel_utilization([
            {"serial": "AP1", "network": {"id": "N_1"}, "mac": "never-store", "byBand": [
                {"band": "2.4", "wifi": {"percentage": 0}, "nonWifi": {"percentage": 20}, "total": {"percentage": 20}},
                {"band": "5", "wifi": {"percentage": True}, "nonWifi": {"percentage": -1}, "total": {"percentage": 101}}]},
            {"serial": "OTHER", "network": {"id": "OTHER"}, "byBand": []}], {"AP1": "N_1", "AP2": "N_1"})
        self.assertEqual(data["reported_device_count"], 1)
        self.assertEqual(data["missing_device_count"], 1)
        self.assertEqual(data["omitted_device_count"], 1)
        self.assertEqual(data["review_band_count"], 1)
        self.assertEqual(data["measured_band_count"], 1)
        self.assertEqual(data["rows"][0]["percentages"]["wifi"], 0)
        self.assertEqual(data["rows"][1]["percentages"], {})
        self.assertEqual(data["rows"][1]["measurement_coverage"], "partial")
        self.assertNotIn("never-store", str(data))

    def test_invalid_shapes_duplicate_id_bands_and_wrong_network(self):
        row = {"serial": "AP1", "network": {"id": "N_1"}, "byBand": [{"band": "5"}]}
        cases = [None, [row, row], [{**row, "network": {"id": "OTHER"}}],
                 [{**row, "byBand": [{"band": "5"}, {"band": "5"}]}],
                 [{**row, "byBand": [{"band": "unknown"}]}]]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(MerakiAPIError):
                summarize_channel_utilization(raw, {"AP1": "N_1"})
        self.assertEqual(summarize_channel_utilization([], {"AP1": "N_1"})["missing_device_count"], 1)

    def test_rolling_readings_do_not_change_configuration(self):
        def snapshot(value):
            return {"organization": {"id": "ORG"}, "security_controls": [{"control": "Wireless channel utilization", "network_id": "", "status": "complete", "data": {"total": value}}]}
        self.assertEqual(compare_meraki_snapshots(snapshot(1), snapshot(60))["changed_control_count"], 0)
