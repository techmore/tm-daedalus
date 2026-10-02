import unittest
from daedalus.meraki_history import compare_meraki_inventory


class MerakiInventoryHistoryTests(unittest.TestCase):
    def snapshot(self, **values):
        return {"organization": {"id": "fixture-org"}, **values}

    def test_inventory_reorder_tags_and_report_timestamps_do_not_alert(self):
        before = self.snapshot(networks=[{"id":"n1", "tags":["b","a"]}],
                               devices=[{"serial":"s1", "status":"online", "lastReportedAt":"old"}])
        after = self.snapshot(networks=[{"id":"n1", "tags":["a","b"]}],
                              devices=[{"serial":"s1", "status":"online", "lastReportedAt":"new"}])
        self.assertEqual(compare_meraki_inventory(before, after)["inventory_changes"], [])

    def test_add_remove_firmware_and_known_status_changes_are_saved(self):
        before=self.snapshot(networks=[{"id":"old"}], devices=[{"serial":"s1", "firmware":"v1", "status":"online"}])
        after=self.snapshot(networks=[{"id":"new"}], devices=[{"serial":"s1", "firmware":"v2", "status":"offline", "apiKey":"private"}])
        changes=compare_meraki_inventory(before, after)["inventory_changes"]
        self.assertEqual([row["kind"] for row in changes], ["added", "removed", "updated"])
        self.assertEqual(changes[-1]["changed_fields"], ["firmware", "status"])
        self.assertNotIn("private", str(changes))

    def test_missing_collections_and_unknown_availability_are_coverage_not_removal(self):
        before=self.snapshot(devices=[{"serial":"s1", "status":"online"}], networks=[{"id":"n1"}])
        after=self.snapshot(devices=[{"serial":"s1", "status":"unknown"}])
        result=compare_meraki_inventory(before, after)
        self.assertEqual(result["inventory_changes"], [])
        self.assertEqual(result["inventory_coverage_change_count"], 2)

    def test_duplicate_or_missing_id_cannot_create_false_inventory_removals(self):
        before=self.snapshot(devices=[{"serial":"s1"}])
        for malformed in [[{}], [{"serial":"s1"},{"serial":"s1"}]]:
            result=compare_meraki_inventory(before, self.snapshot(devices=malformed))
            self.assertEqual(result["inventory_changes"], [])
            self.assertEqual(result["inventory_coverage_changes"][0]["current_status"], "invalid_evidence")

    def test_cannot_compare_different_cisco_organizations(self):
        with self.assertRaises(ValueError):
            compare_meraki_inventory(self.snapshot(), {"organization":{"id":"different"}})
