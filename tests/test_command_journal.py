import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import httpx

from daedalus.agent import NmapUIBridge
from daedalus.command_journal import CommandJournal


class CommandJournalTests(unittest.TestCase):
    def test_corrupt_pending_result_does_not_prevent_new_outcome(self):
        journal = CommandJournal(self.root / "commands")
        (journal.root / "result-00000000000000000001-1.json").write_text("{broken")
        journal.enqueue(2, "succeeded", "Complete")
        self.assertEqual([value["command_id"] for _, value in journal.pending()], [2])
        self.assertTrue(list(journal.root.glob("*.rejected")))

    def test_corrupt_restart_record_does_not_block_other_restarts(self):
        journal = CommandJournal(self.root / "commands")
        for identifier, record in [(1, "{broken"), (2, json.dumps({"command_id": 2, "started_at": float("nan")})), (3, json.dumps({"command_id": 4, "started_at": 1}))]:
            (journal.root / f"waiting-{identifier}.json").write_text(record)
        journal.wait_for_restart({"id": 5})
        self.assertEqual([record["command_id"] for _, record in journal.waiting_restarts()], [5])
        self.assertEqual(len(list(journal.root.glob("waiting-*.rejected"))), 3)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def bridge(self):
        bridge = NmapUIBridge({"agent_id": 1, "server": "https://fixture.example.org", "agent_token": "fixture"},
                              "http://127.0.0.1:9000", spool_dir=self.root / "events")
        self.addCleanup(bridge.http.close)
        return bridge

    def test_claim_is_persistent_conflict_checked_and_private(self):
        journal = CommandJournal(self.root / "commands")
        command = {"id": 1, "action": "start_scan", "target": "127.0.0.1"}
        self.assertTrue(journal.claim(command))
        self.assertFalse(CommandJournal(journal.root).claim(command))
        with self.assertRaises(ValueError):
            journal.claim({**command, "target": "10.0.0.1"})
        self.assertEqual(journal.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(next(journal.root.glob("claim-*.json")).stat().st_mode & 0o777, 0o600)

    def test_claim_fingerprint_includes_per_scan_host_discovery_option(self):
        journal = CommandJournal(self.root / "commands")
        base = {"id": 8, "action": "start_scan", "target": "127.0.0.1", "skip_host_discovery": False}
        self.assertTrue(journal.claim(base))
        self.assertFalse(journal.claim({"id": 8, "action": "start_scan", "target": "127.0.0.1"}))
        with self.assertRaisesRegex(ValueError, "conflicts"):
            journal.claim({**base, "skip_host_discovery": True})
        with self.assertRaisesRegex(ValueError, "Invalid command payload"):
            journal.claim({"id": 9, "action": "start_scan", "target": "127.0.0.1", "skip_host_discovery": 1})

    def test_legacy_claims_are_only_compatible_with_legacy_scan_semantics(self):
        journal = CommandJournal(self.root / "commands")
        command = {"id": 12, "action": "start_scan", "target": "127.0.0.1"}
        old_fingerprint = hashlib.sha256(json.dumps({"action": command["action"], "target": command["target"]}, sort_keys=True).encode()).hexdigest()
        (journal.root / "claim-12.json").write_text(json.dumps({"command_id": 12, "fingerprint": old_fingerprint, "claimed_at": 1}))
        self.assertFalse(journal.claim(command))
        with self.assertRaisesRegex(ValueError, "conflicts"):
            journal.claim({**command, "skip_host_discovery": True})

    def test_result_recovery_preserves_order_and_requires_ack(self):
        bridge = self.bridge()
        bridge._request = Mock(side_effect=httpx.ConnectError("offline"))
        bridge._send_command_result(1, "accepted", "Delivered")
        bridge._send_command_result(1, "succeeded", "Complete")
        restarted = self.bridge()
        restarted._request = Mock(return_value=httpx.Response(200, json={}))
        restarted._flush_command_results()
        self.assertEqual(len(restarted.command_journal.pending()), 2)
        restarted._request = Mock(side_effect=lambda method, path, **kwargs: httpx.Response(200, json={"ok": True, "command_id": int(path.split("/")[-2]), "status": kwargs["json"]["status"]}))
        restarted._flush_command_results()
        self.assertEqual([call.kwargs["json"]["status"] for call in restarted._request.call_args_list], ["accepted", "succeeded"])
        self.assertEqual(restarted.command_journal.pending(), [])

    def test_conflicting_rejected_result_is_retained_without_blocking_later_result(self):
        bridge = self.bridge()
        bridge.command_journal.enqueue(1, "accepted", "Delivered")
        bridge.command_journal.enqueue(2, "succeeded", "Complete")
        bridge._request = Mock(side_effect=[httpx.Response(409), httpx.Response(200, json={"ok": True, "command_id": 2, "status": "succeeded"})])
        bridge._flush_command_results()
        self.assertEqual(bridge.command_journal.counts(), {"pending_command_results": 0, "rejected_command_results": 1})

    def test_duplicate_delivery_does_not_repeat_side_effect(self):
        bridge = self.bridge()
        bridge.nmapui_connected.set()
        bridge._request = Mock(return_value=httpx.Response(200, request=httpx.Request("GET", "https://fixture.example.org/next"), json={"command": {"id": 9, "action": "start_scan", "target": "127.0.0.1"}}))
        bridge.sio.emit = Mock()
        bridge._send_command_result = Mock()
        bridge._run_one_command()
        bridge._run_one_command()
        bridge.sio.emit.assert_called_once()

    def test_diagnostics_are_allowlisted_and_work_without_nmapui(self):
        bridge = self.bridge()
        bridge._read_nmapui_health = Mock(return_value={"nmapui_version": None, "nmapui_ready": False})
        with patch.dict("os.environ", {"SECRET": "private-value"}):
            facts = bridge._collect_diagnostics()
        self.assertFalse(facts["nmapui_connected"])
        self.assertNotIn("private-value", json.dumps(facts))
        self.assertNotIn("fixture.example.org", json.dumps(facts))
        self.assertLess(len(json.dumps(facts)), 1000)

    def test_storage_cap_refuses_new_claim_before_execution(self):
        journal = CommandJournal(self.root / "commands")
        journal.MAX_BYTES = 1
        with self.assertRaises(OSError):
            journal.claim({"id": 1, "action": "start_scan"})
        self.assertEqual(list(journal.root.iterdir()), [])

    def test_terminal_receipt_suppresses_replayed_accepted_and_identical_outcome(self):
        bridge = self.bridge()
        bridge.command_journal.claim({"id": 3, "action": "start_scan"})
        bridge._request = Mock(side_effect=lambda method, path, **kwargs: httpx.Response(200, json={"ok": True, "command_id": int(path.split("/")[-2]), "status": kwargs["json"]["status"]}))
        bridge._send_command_result(3, "succeeded", "Scan completed")
        bridge.command_journal.enqueue(3, "accepted", "Started")
        bridge.command_journal.enqueue(3, "succeeded", "Scan completed")
        self.assertEqual(bridge.command_journal.pending(), [])
        bridge.command_journal.enqueue(3, "failed", "Conflicting outcome")
        self.assertEqual(len(bridge.command_journal.pending()), 1)

    def test_correlated_envelope_never_infers_completion_or_accepts_unknown_command(self):
        bridge = self.bridge()
        bridge.command_journal.claim({"id": 4, "action": "start_scan"})
        receive = bridge.sio.handlers["/"]["*"]
        receive("daedalus_protocol", {"version": 1, "command_results": True})
        self.assertTrue(bridge.command_completion_supported)
        receive("daedalus_event", {"event_name": "daedalus_command_result", "payload": {"command_namespace": bridge.command_namespace, "command_id": 4, "status": "succeeded", "result": "Completed"}})
        receive("daedalus_event", {"event_name": "daedalus_command_result", "payload": {"command_namespace": bridge.command_namespace, "command_id": 99, "status": "succeeded", "result": "Unknown"}})
        pending = bridge.command_journal.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0][1]["command_id"], 4)

    def test_modern_scan_includes_command_id_and_waits_for_real_result(self):
        bridge = self.bridge()
        bridge.nmapui_connected.set()
        bridge.command_completion_supported = True
        bridge._request = Mock(return_value=httpx.Response(200, request=httpx.Request("GET", "https://fixture.example.org/next"), json={"command": {"id": 5, "action": "start_scan", "target": "127.0.0.1"}}))
        bridge.sio.emit = Mock()
        bridge._send_command_result = Mock()
        bridge._run_one_command()
        bridge.sio.emit.assert_called_once_with("start_scan", {"target": "127.0.0.1", "daedalus_command_id": 5, "daedalus_command_namespace": bridge.command_namespace})
        bridge._send_command_result.assert_not_called()

    def test_corrupt_result_is_retained_without_stopping_uploads(self):
        bridge = self.bridge()
        bridge.command_journal.enqueue(8, "succeeded", "Complete")
        (bridge.command_journal.root / "result-00000000000000000000-1.json").write_text("broken JSON")
        bridge._request = Mock(side_effect=lambda method, path, **kwargs: httpx.Response(200, json={"ok": True, "command_id": int(path.split("/")[-2]), "status": kwargs["json"]["status"]}))
        bridge._flush_command_results()
        self.assertEqual(bridge.command_journal.counts(), {"pending_command_results": 0, "rejected_command_results": 1})

    def test_command_state_cannot_cross_enrollment_tokens(self):
        first = self.bridge()
        first.command_journal.claim({"id": 7, "action": "start_scan"})
        first.command_journal.enqueue(7, "succeeded", "Old enrollment")
        second = NmapUIBridge({"agent_id": 1, "server": "https://fixture.example.org", "agent_token": "rotated"}, "http://127.0.0.1:9000", spool_dir=self.root / "events")
        self.addCleanup(second.http.close)
        self.assertNotEqual(first.command_namespace, second.command_namespace)
        self.assertEqual(second.command_journal.pending(), [])
        second.command_journal.claim({"id": 7, "action": "start_scan"})
        second._handle_command_completion({"command_namespace": first.command_namespace, "command_id": 7, "status": "succeeded", "result": "Old enrollment"})
        self.assertEqual(second.command_journal.pending(), [])

    def test_restart_needs_observed_readiness(self):
        bridge = self.bridge()
        bridge.command_journal.wait_for_restart({"id": 6})
        bridge._send_command_result = Mock()
        bridge._read_nmapui_health = Mock(return_value={"nmapui_ready": False})
        bridge._complete_waiting_restarts()
        bridge._send_command_result.assert_not_called()
        bridge.nmapui_connected.set()
        bridge._complete_waiting_restarts()
        bridge._send_command_result.assert_not_called()
        bridge._read_nmapui_health.return_value = {"nmapui_ready": True}
        bridge._complete_waiting_restarts()
        bridge._send_command_result.assert_called_once_with(6, "succeeded", "Managed NmapUI reconnected and reports ready after restart.")


if __name__ == "__main__":
    unittest.main()
