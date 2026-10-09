"""Compile and exercise the actual Swift scanner runtime presentation on macOS."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('xcrun'), 'Requires macOS Swift compiler')
class ScannerStatusNativeTests(unittest.TestCase):
    def test_runtime_activity_and_maintenance_presentations(self):
        source = Path(__file__).parents[1] / 'src/daedalus/agent_bundle/ScannerStatus.swift'
        app_source = source.read_text()
        prefix, separator, _ = app_source.partition('\nlet app = NSApplication.shared\n')
        self.assertTrue(separator, 'Native application entry point must be explicit')
        fixtures = r'''
func verify(_ condition: Bool, _ name: String) {
    if !condition { fputs("Failed: \(name)\n", stderr); exit(1) }
}
let offline = ScannerRuntimePresentation(nil)
verify(!offline.running && offline.badge == "Offline" && offline.activity == "Scan activity: unknown", "offline")
let idle = ScannerRuntimePresentation(["has_active_jobs": false, "active_jobs": []])
verify(idle.running && !idle.working && idle.badge == "Nmap" && idle.activity == "Scan activity: idle", "legacy idle")
let paused = ScannerRuntimePresentation(["has_active_jobs": false, "active_jobs": [], "maintenance_active": true])
verify(paused.running && paused.maintenance && !paused.scanning && paused.badge == "Maintenance", "maintenance badge")
verify(paused.activity.contains("new scans and reports are paused") && paused.symbol == "wrench.and.screwdriver", "maintenance explanation")
let resumed = ScannerRuntimePresentation(["has_active_jobs": false, "active_jobs": [], "maintenance_active": false])
verify(!resumed.maintenance && resumed.activity == idle.activity, "maintenance cleared")
let scan = ScannerRuntimePresentation(["has_active_jobs": true, "active_jobs": [["job_type": "scan", "details": ["target": "127.0.0.1", "progress": 42]]]])
verify(scan.scanning && scan.working && scan.badge == "Scanning" && scan.activity.contains("127.0.0.1 · 42%"), "scan progress")
let report = ScannerRuntimePresentation(["has_active_jobs": true, "active_jobs": [["job_type": "report"]]])
verify(report.working && !report.scanning && report.badge == "Working", "report activity")
for data: [String: Any] in [[:], ["active_jobs": []], ["has_active_jobs": true, "active_jobs": []], ["has_active_jobs": false, "active_jobs": [["job_type": "scan"]]]] {
    let unknown = ScannerRuntimePresentation(data)
    verify(unknown.activity == "Scan activity: unknown" && !unknown.scanning, "incomplete/contradictory activity")
}
let deliveryTime = ScannerDeliveryPresentation.date("2026-10-08T12:00:00Z")!
let delivery: [String: Any] = ["schema_version": 1, "state": "observed", "pending_events": 3, "review_events": 0, "preservation_failed": false, "last_acknowledged_at": NSNull(), "observed_at": "2026-10-08T12:00:00Z"]
let queued = ScannerDeliveryPresentation(delivery, now: deliveryTime)
verify(queued.valid && queued.pending == 3 && !queued.needsReview && queued.summary.contains("3 queued"), "queued independently from engine")
var retained = delivery; retained["review_events"] = 1
verify(ScannerDeliveryPresentation(retained, now: deliveryTime).needsReview, "retained review")
var failed = delivery; failed["preservation_failed"] = true
verify(ScannerDeliveryPresentation(failed, now: deliveryTime).summary.contains("local save incomplete"), "unfinished save")
let unknownFailure: [String: Any] = ["schema_version": 1, "state": "unknown", "pending_events": NSNull(), "review_events": NSNull(), "preservation_failed": true, "last_acknowledged_at": NSNull(), "observed_at": "2026-10-08T12:00:00Z"]
let unmeasured = ScannerDeliveryPresentation(unknownFailure, now: deliveryTime)
verify(!unmeasured.valid && unmeasured.pending == nil && unmeasured.needsReview && unmeasured.summary.contains("queue unknown"), "known failure with unknown counts")
for change: [String: Any] in [["pending_events": true], ["pending_events": -1], ["pending_events": 10001], ["review_events": 1.5], ["preservation_failed": 1], ["schema_version": true], ["observed_at": "2026-10-08T12:00:01Z"], ["observed_at": "2026-10-08T11:59:14Z"], ["last_acknowledged_at": "bad"], ["extra_private": "private"]] {
    var malformed = delivery; malformed.merge(change) { _, new in new }
    let result = ScannerDeliveryPresentation(malformed, now: deliveryTime)
    verify(!result.valid && result.pending == nil && result.summary == "Results delivery: unknown", "invalid delivery")
}
var acknowledged = delivery; acknowledged["last_acknowledged_at"] = "2026-10-08T11:59:59.123Z"
verify(ScannerDeliveryPresentation(acknowledged, now: deliveryTime).summary.contains("last acknowledged"), "dated ack")
acknowledged["last_acknowledged_at"] = "2026-10-08T12:01:00Z"
verify(!ScannerDeliveryPresentation(acknowledged, now: deliveryTime).summary.contains("last acknowledged"), "future ack not displayed")
let privateDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
try FileManager.default.createDirectory(at: privateDirectory, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: privateDirectory) }
let observation = privateDirectory.appendingPathComponent("upload.status")
try JSONSerialization.data(withJSONObject: delivery).write(to: observation)
verify(privateUploadObservation(observation)?["state"] as? String == "observed", "actual local read")
let link = privateDirectory.appendingPathComponent("link")
try FileManager.default.createSymbolicLink(at: link, withDestinationURL: observation)
verify(privateUploadObservation(link) == nil, "no symlink read")
verify(privateUploadObservation(privateDirectory) == nil, "no directory read")
try Data(repeating: 32, count: 16385).write(to: observation)
verify(privateUploadObservation(observation) == nil, "bounded local read")
try Data("broken".utf8).write(to: observation)
verify(privateUploadObservation(observation) == nil, "malformed local read")
print("Scanner runtime and delivery presentation fixtures passed")
'''
        with tempfile.TemporaryDirectory(prefix='daedalus-native-status-') as directory:
            path = Path(directory)
            fixture = path / 'main.swift'
            fixture.write_text(prefix + fixtures)
            binary = path / 'status-fixtures'
            result = subprocess.run(['xcrun', 'swiftc', str(fixture), '-o', str(binary)], capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr)
            executed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            self.assertIn('fixtures passed', executed.stdout)
