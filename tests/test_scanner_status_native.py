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
print("Scanner runtime presentation fixtures passed")
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
