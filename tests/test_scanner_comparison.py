import json
import unittest
from uuid import uuid4
from daedalus.scanner_comparison import normalize_snapshot, compare_snapshots
try:
    from . import test_scanner_runs as fixtures
except ImportError:
    import test_scanner_runs as fixtures


def payload(address="192.168.1.1", ports=None, targets=None, complete=False):
    host = {"ip": address, "ports": ports or [], "ports_complete": complete}
    return {"hosts": [host], **({"covered_targets": targets} if targets else {})}


class ScannerComparisonTests(unittest.TestCase):
    def test_incomplete_or_unknown_coverage_never_confirms_removals(self):
        before = normalize_snapshot(payload())
        after = normalize_snapshot(payload("192.168.1.2"))
        result = compare_snapshots(before, after, previous_status="completed", current_status="completed")
        self.assertFalse(result["coverage"]["comparable"])
        self.assertEqual(result["hosts_removed"], [])
        self.assertEqual(result["hosts_not_observed"], ["192.168.1.1"])
        self.assertEqual(result["hosts_added"], ["192.168.1.2"])
        scoped_before = normalize_snapshot(payload(targets=["192.168.1.0/24"]))
        scoped_after = normalize_snapshot(payload("192.168.1.2", targets=["192.168.1.0/24"]))
        interrupted = compare_snapshots(scoped_before, scoped_after, previous_status="completed", current_status="interrupted")
        self.assertEqual(interrupted["hosts_removed"], [])
        completed = compare_snapshots(scoped_before, scoped_after, previous_status="completed", current_status="completed")
        self.assertEqual(completed["hosts_removed"], ["192.168.1.1"])
        different = normalize_snapshot(payload("192.168.1.2", targets=["192.168.2.0/24"]))
        self.assertFalse(compare_snapshots(scoped_before, different, previous_status="completed", current_status="completed")["coverage"]["comparable"])

    def test_coverage_requires_valid_networks_containing_observations(self):
        for targets in (["claimed complete"], ["192.168.2.0/24"]):
            snapshot = normalize_snapshot(payload(targets=targets))
            self.assertIsNone(snapshot["covered_targets"])
        snapshot = normalize_snapshot(payload(targets=["192.168.1.1", "192.168.1.0/24"]))
        self.assertEqual(snapshot["covered_targets"], ["192.168.1.0/24", "192.168.1.1/32"])

    def test_port_identity_and_service_changes_and_unconfirmed_absence(self):
        old = [{"protocol": "tcp", "port": 443, "state": "open", "service": "https"},
               {"protocol": "udp", "port": 443, "state": "open", "service": "quic"}]
        new = [{"protocol": "tcp", "port": 443, "state": "closed", "service": "https"}]
        before, after = normalize_snapshot(payload(ports=old)), normalize_snapshot(payload(ports=new))
        result = compare_snapshots(before, after, previous_status="completed", current_status="completed")
        changes = {(row["protocol"], row["port"]): row for row in result["port_changes"]}
        self.assertEqual(changes[("tcp", 443)]["change"], "state_service_changed")
        self.assertEqual(changes[("udp", 443)]["change"], "not_observed")
        self.assertFalse(changes[("udp", 443)]["confirmed"])

    def test_product_version_changes_are_preserved_and_empty_coverage_not_comparable(self):
        old = [{"protocol": "tcp", "port": 443, "state": "open", "service": "https", "product": "nginx", "version": "1.0"}]
        new = [{"protocol": "tcp", "port": 443, "state": "open", "service": "https", "product": "nginx", "version": "2.0"}]
        before = normalize_snapshot({"hosts": payload(ports=old)["hosts"], "covered_targets": []})
        after = normalize_snapshot({"hosts": payload(ports=new)["hosts"], "covered_targets": []})
        result = compare_snapshots(before, after, previous_status="completed", current_status="completed")
        self.assertFalse(result["coverage"]["comparable"])
        change = result["port_changes"][0]
        self.assertEqual(change["change"], "state_service_changed")
        self.assertEqual(change["before"]["version"], "1.0")
        self.assertEqual(change["after"]["version"], "2.0")

    def test_missing_service_is_evidence_change_not_false_service_change(self):
        before = normalize_snapshot(payload(ports=[{"protocol": "tcp", "port": 443, "state": "open"}]))
        after = normalize_snapshot(payload(ports=[{"protocol": "tcp", "port": 443, "state": "open", "service": "https"}]))
        result = compare_snapshots(before, after, previous_status="completed", current_status="completed")
        self.assertEqual(result["port_changes"][0]["change"], "evidence_changed")
        self.assertFalse(result["port_changes"][0]["confirmed"])


class ScannerComparisonAPITests(unittest.TestCase):
    setUp = fixtures.ScannerRunTests.setUp
    tearDown = fixtures.ScannerRunTests.tearDown
    create_scanner = fixtures.ScannerRunTests.create_scanner
    setup_scanner = fixtures.ScannerRunTests.setup_scanner
    envelope = fixtures.ScannerRunTests.envelope
    send = fixtures.ScannerRunTests.send

    def compare(self, previous):
        return self.client.get(f"/api/agents/{self.agent}/runs/{self.job_id}/comparison", params={"previous_run_id": previous})

    def test_latest_valid_artifact_only_no_phase_mix_scope_and_missing_results(self):
        self.setup_scanner()
        previous = self.job_id
        self.send(self.envelope("deep_scan_results", payload(ports=[{"protocol": "tcp", "port": 443, "state": "open", "service": "https"}])))
        self.send(self.envelope("job_status", {"status": "completed", "job_type": "scan"}))
        self.job_id = str(uuid4())
        self.send(self.envelope("scan_results", [{"ip": "192.168.1.99"}]))
        missing = self.compare(previous)
        self.assertEqual(missing.status_code, 200)
        self.assertFalse(missing.json()["available"])
        envelope = self.envelope("deep_scan_results", payload(ports=[{"protocol": "tcp", "port": 443, "state": "closed", "service": "https"}]))
        envelope["payload"]["padding"] = "x" * 520000
        artifact = self.client.post(f"/api/agents/{self.agent}/event-artifacts", headers=self.headers, content=json.dumps(envelope))
        self.assertEqual(artifact.status_code, 200, artifact.text)
        self.send(self.envelope("job_status", {"status": "completed", "job_type": "scan"}))
        result = self.compare(previous).json()
        self.assertTrue(result["available"])
        self.assertEqual(result["current_run"]["selected_result_event_id"], artifact.json()["event_id"])
        self.assertEqual(result["hosts_added"], [])
        self.assertEqual(result["port_changes"][0]["after"]["state"], "closed")
        self.send(self.envelope("deep_scan_results", {"hosts": ["malformed"]}))
        result = self.compare(previous).json()
        self.assertTrue(result["available"])
        self.assertTrue(result["current_run"]["skipped_invalid_result_event_ids"])
        self.assertFalse(result["coverage"]["comparable"])
        self.client.post("/api/workspaces", json={"name": "Other", "domain": "other-comparison-fixture.example"})
        self.assertEqual(self.compare(previous).status_code, 404)
