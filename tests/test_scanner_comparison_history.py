import json
import unittest
from uuid import uuid4
from unittest.mock import AsyncMock, patch
from sqlalchemy import select
from daedalus import server
from daedalus.models import AgentCommand, ScanEvent, ScannerRunComparison, AuditLog, User
try:
    from . import test_scanner_runs as fixtures
except ImportError:
    import test_scanner_runs as fixtures


class ScannerComparisonHistoryTests(unittest.TestCase):
    setUp = fixtures.ScannerRunTests.setUp
    tearDown = fixtures.ScannerRunTests.tearDown
    create_scanner = fixtures.ScannerRunTests.create_scanner
    setup_scanner = fixtures.ScannerRunTests.setup_scanner
    envelope = fixtures.ScannerRunTests.envelope
    send = fixtures.ScannerRunTests.send

    def event(self, name, payload, second):
        envelope = self.envelope(name, payload)
        envelope["occurred_at"] = f"2026-09-29T14:00:{second:02d}Z"
        return envelope

    def baseline(self):
        self.setup_scanner()
        old_id = self.job_id
        self.send(self.event("deep_scan_results", [{"ip": "192.168.1.1", "ports": []}], 1))
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 2))
        self.job_id = str(uuid4())
        return old_id

    def history(self):
        return self.client.get(f"/api/agents/{self.agent}/run-comparisons")

    def successful_single_ip_command(self, target, *, status="succeeded"):
        now = server.utcnow()
        with self.session_factory() as db:
            agent = db.get(server.Agent, self.agent)
            admin = db.scalar(select(User).where(User.google_subject == "daedalus-local-demo-admin"))
            command = AgentCommand(
                organization_id=agent.organization_id,
                agent_id=agent.id,
                action="start_scan",
                target=target,
                skip_host_discovery=True,
                status=status,
                created_by_user_id=admin.id,
                created_at=now,
                updated_at=now,
                completed_at=now if status == "succeeded" else None,
            )
            db.add(command)
            db.commit()
            return command.id

    def completed_job_payload(self, target, command_id):
        return {
            "status": "completed",
            "job_type": "scan",
            "details": {
                "target": target,
                "skip_host_discovery": True,
                "daedalus_command_id": command_id,
            },
        }

    def test_completed_comparison_persists_and_alerts_once_across_retry(self):
        old = self.baseline()
        with patch.object(server.live_hub, "publish", new_callable=AsyncMock) as publish:
            self.send(self.event("deep_scan_results", [{"ip": "192.168.1.2", "ports": []}], 3))
            self.assertEqual(self.history().json()["comparisons"], [])
            completion = self.event("job_status", {"status": "completed", "job_type": "scan"}, 4)
            self.assertEqual(self.send(completion).status_code, 200)
            self.assertTrue(self.send(completion).json()["duplicate"])
            alerts = [call.args[1] for call in publish.call_args_list if call.args[1]["type"] == "scanner_comparison_detected"]
            self.assertEqual(len(alerts), 1)
        rows = self.history().json()["comparisons"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["previous_run_id"], old)
        self.assertEqual(rows[0]["current_run_id"], self.job_id)
        self.assertEqual(rows[0]["meaningful_change_count"], 1)
        self.assertEqual(rows[0]["comparison"]["hosts_added"], ["192.168.1.2"])
        self.assertEqual(rows[0]["comparison"]["hosts_removed"], [])
        self.assertTrue(rows[0]["detected_at"])
        inbox = self.client.get("/api/notifications").json()
        self.assertEqual(inbox["unread_count"], 1)
        self.assertEqual(len(inbox["notifications"]), 1)
        notice = inbox["notifications"][0]
        self.assertEqual(notice["source_type"], "scanner_comparison")
        self.assertEqual(notice["source_id"], rows[0]["id"])
        self.assertEqual(notice["tab"], "scanners")
        self.assertEqual(notice["reason"], "changes")
        self.assertIn("1 host newly observed", notice["summary"])
        self.assertIn("absence does not confirm", notice["summary"])
        with self.session_factory() as db:
            self.assertEqual(len(db.scalars(select(AuditLog).where(AuditLog.action == "scanner.run_comparison_saved")).all()), 1)

    def test_late_artifact_results_trigger_and_snapshot_stays_immutable(self):
        self.baseline()
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 4))
        self.assertEqual(self.history().json()["comparisons"], [])
        artifact = self.event("deep_scan_results", {"hosts": [{"ip": "192.168.1.2", "ports": []}], "padding": "x" * 520000}, 3)
        with patch.object(server.live_hub, "publish", new_callable=AsyncMock) as publish:
            endpoint = f"/api/agents/{self.agent}/event-artifacts"
            upload = self.client.post(endpoint, headers=self.headers, content=json.dumps(artifact))
            self.assertEqual(upload.status_code, 200, upload.text)
            self.assertTrue(self.client.post(endpoint, headers=self.headers, content=json.dumps(artifact)).json()["duplicate"])
            alerts = [call for call in publish.call_args_list if call.args[1]["type"] == "scanner_comparison_detected"]
            self.assertEqual(len(alerts), 1)
        first = self.history().json()["comparisons"][0]
        self.assertEqual(first["current_result_event_id"], upload.json()["event_id"])
        self.assertTrue(first["comparison"]["current_run"]["selected_result_artifact_sha256"])
        self.send(self.event("deep_scan_results", [{"ip": "192.168.1.3", "ports": []}], 5))
        rows = self.history().json()["comparisons"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1], first)

    def test_unconfirmed_absence_saved_without_alert_and_scoped_history(self):
        self.baseline()
        with patch.object(server.live_hub, "publish", new_callable=AsyncMock) as publish:
            self.send(self.event("deep_scan_results", [], 3))
            self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 4))
            self.assertFalse(any(call.args[1]["type"] == "scanner_comparison_detected" for call in publish.call_args_list))
        history = self.history().json()["comparisons"]
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["meaningful_change_count"], 0)
        self.assertEqual(history[0]["comparison"]["hosts_not_observed"], ["192.168.1.1"])
        self.client.post("/api/workspaces", json={"name": "Other", "domain": "other-history-fixture.example"})
        self.assertEqual(self.history().status_code, 404)

    def test_confirmed_port_removal_in_comparable_scope_creates_durable_notice(self):
        self.setup_scanner()
        old = self.job_id
        targets = ["192.168.1.0/24"]
        baseline = self.event("deep_scan_results", {
            "hosts": [{"ip": "192.168.1.1", "ports": [
                {"protocol": "tcp", "port": 22, "state": "open", "service": "ssh"}], "ports_complete": True}],
            "covered_targets": targets,
        }, 1)
        self.send(baseline)
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 2))

        self.job_id = str(uuid4())
        current = self.event("deep_scan_results", {
            "hosts": [{"ip": "192.168.1.1", "ports": [], "ports_complete": True}],
            "covered_targets": targets,
        }, 3)
        self.send(current)
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 4))

        comparison = self.history().json()["comparisons"][0]
        self.assertEqual(comparison["previous_run_id"], old)
        self.assertTrue(comparison["comparison"]["coverage"]["comparable"])
        self.assertEqual(comparison["comparison"]["counts"]["confirmed_removed_ports"], 1)
        self.assertEqual(comparison["meaningful_change_count"], 1)
        notice = self.client.get("/api/notifications").json()["notifications"][0]
        self.assertEqual(notice["source_type"], "scanner_comparison")
        self.assertEqual(notice["tab"], "scanners")
        self.assertIn("1 port no longer reported after complete port coverage", notice["summary"])
        self.assertNotIn("port was closed", notice["summary"])

    def test_single_ip_command_supplies_host_scope_but_never_claims_port_completeness(self):
        self.setup_scanner()
        target = "192.168.1.1"
        baseline_id = self.job_id
        baseline_command = self.successful_single_ip_command(target)
        self.send(self.event("deep_scan_results", [{"ip": target, "ports": [
            {"protocol": "tcp", "port": 22, "state": "open", "service": "ssh"},
        ]}], 1))
        self.send(self.event("job_status", self.completed_job_payload(target, baseline_command), 2))

        self.job_id = str(uuid4())
        current_command = self.successful_single_ip_command(target)
        self.send(self.event("deep_scan_results", [{"ip": target, "ports": []}], 3))
        self.send(self.event("job_status", self.completed_job_payload(target, current_command), 4))

        comparison = self.client.get(
            f"/api/agents/{self.agent}/runs/{self.job_id}/comparison",
            params={"previous_run_id": baseline_id},
        ).json()
        self.assertTrue(comparison["coverage"]["comparable"])
        self.assertEqual(comparison["previous_run"]["covered_targets_source"], "successful_daedalus_single_ip_command")
        self.assertEqual(comparison["current_run"]["covered_targets_source"], "successful_daedalus_single_ip_command")
        self.assertEqual(comparison["coverage"]["previous_targets"], ["192.168.1.1/32"])
        self.assertEqual(comparison["coverage"]["current_targets"], ["192.168.1.1/32"])
        self.assertEqual(comparison["port_changes"][0]["change"], "not_observed")
        self.assertFalse(comparison["port_changes"][0]["confirmed"])
        self.assertEqual(comparison["counts"]["confirmed_removed_ports"], 0)

    def test_host_scope_is_not_inferred_from_failed_untracked_or_subnet_command(self):
        self.setup_scanner()
        target = "192.168.1.1"
        baseline_id = self.job_id
        baseline_command = self.successful_single_ip_command(target)
        self.send(self.event("deep_scan_results", [{"ip": target, "ports": []}], 1))
        self.send(self.event("job_status", self.completed_job_payload(target, baseline_command), 2))

        cases = [
            (target, "failed", "present"),
            ("192.168.1.0/24", "succeeded", "present"),
            (target, "succeeded", "missing"),
        ]
        for index, (command_target, command_status, command_identity) in enumerate(cases, start=3):
            self.job_id = str(uuid4())
            command_id = self.successful_single_ip_command(command_target, status=command_status) if command_identity == "present" else 999999
            self.send(self.event("deep_scan_results", [{"ip": target, "ports": []}], index * 2 - 3))
            payload = self.completed_job_payload(command_target, command_id)
            if command_identity == "missing":
                payload["details"].pop("daedalus_command_id")
            self.send(self.event("job_status", payload, index * 2 - 2))
            comparison = self.client.get(
                f"/api/agents/{self.agent}/runs/{self.job_id}/comparison",
                params={"previous_run_id": baseline_id},
            ).json()
            self.assertFalse(comparison["coverage"]["comparable"])
            self.assertNotIn("covered_targets_source", comparison["current_run"])

    def test_comparison_failure_does_not_reject_committed_event_and_retry_recovers(self):
        self.baseline()
        self.send(self.event("deep_scan_results", [{"ip": "192.168.1.2", "ports": []}], 3))
        completion = self.event("job_status", {"status": "completed", "job_type": "scan"}, 4)
        with patch.object(server, "record_scanner_run_comparison", side_effect=RuntimeError("fixture derivative failure")):
            with self.assertLogs(server.logger, level="ERROR"):
                accepted = self.send(completion)
        self.assertEqual(accepted.status_code, 200)
        with self.session_factory() as db:
            self.assertIsNotNone(db.get(ScanEvent, accepted.json()["event_id"]))
        retried = self.send(completion)
        self.assertTrue(retried.json()["duplicate"])
        self.assertEqual(len(self.history().json()["comparisons"]), 1)

    def test_eventtime_baseline_excludes_later_or_interrupted_runs(self):
        old = self.baseline()
        current = self.job_id
        self.job_id = str(uuid4())
        self.send(self.event("deep_scan_results", [{"ip": "192.168.1.8"}], 8))
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 9))
        self.job_id = current
        self.send(self.event("deep_scan_results", [{"ip": "192.168.1.2"}], 3))
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 4))
        current_rows = [row for row in self.history().json()["comparisons"] if row["current_run_id"] == current]
        self.assertEqual(current_rows[0]["previous_run_id"], old)

    def test_unchanged_comparison_is_persisted_without_realtime_alert(self):
        self.baseline()
        with patch.object(server.live_hub, "publish", new_callable=AsyncMock) as publish:
            self.send(self.event("deep_scan_results", [{"ip": "192.168.1.1", "ports": []}], 3))
            self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 4))
            self.assertFalse(any(call.args[1]["type"] == "scanner_comparison_detected" for call in publish.call_args_list))
        rows = self.history().json()["comparisons"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["meaningful_change_count"], 0)
        self.assertEqual(rows[0]["comparison"]["hosts_added"], [])
        self.assertEqual(rows[0]["comparison"]["hosts_not_observed"], [])

    def test_late_baseline_reconciles_only_immediate_successor_and_retry_is_idempotent(self):
        self.setup_scanner()
        baseline = self.job_id
        successor = str(uuid4())
        later = str(uuid4())
        # Later runs upload completely before their earlier baseline has any evidence.
        self.job_id = successor
        self.send(self.event("deep_scan_results", [{"ip": "192.168.1.2"}], 3))
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 4))
        self.job_id = later
        self.send(self.event("deep_scan_results", [{"ip": "192.168.1.3"}], 5))
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 6))
        original_later = self.history().json()["comparisons"][0]
        self.assertEqual(original_later["current_run_id"], later)
        self.job_id = baseline
        completion = self.event("job_status", {"status": "completed", "job_type": "scan"}, 2)
        self.send(completion)
        self.assertEqual(len(self.history().json()["comparisons"]), 1)
        result = self.event("deep_scan_results", [{"ip": "192.168.1.1"}], 1)
        with patch.object(server.live_hub, "publish", new_callable=AsyncMock) as publish:
            uploaded = self.send(result)
            self.assertEqual(uploaded.status_code, 200)
            self.assertTrue(self.send(result).json()["duplicate"])
            self.assertTrue(self.send(completion).json()["duplicate"])
            alerts = [call.args[1] for call in publish.call_args_list if call.args[1]["type"] == "scanner_comparison_detected"]
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["current_run_id"], successor)
        rows = self.history().json()["comparisons"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["current_run_id"], successor)
        self.assertEqual(rows[0]["previous_run_id"], baseline)
        self.assertEqual(rows[1], original_later)

    def test_new_late_baseline_identity_preserves_existing_successor_comparison(self):
        old = self.baseline()
        successor = self.job_id
        self.send(self.event("deep_scan_results", [{"ip": "192.168.1.2"}], 7))
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 8))
        original = self.history().json()["comparisons"][0]
        self.assertEqual(original["previous_run_id"], old)
        late_baseline = str(uuid4())
        self.job_id = late_baseline
        self.send(self.event("deep_scan_results", [{"ip": "192.168.1.3"}], 4))
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 5))
        successor_rows = [row for row in self.history().json()["comparisons"] if row["current_run_id"] == successor]
        self.assertEqual(len(successor_rows), 2)
        self.assertEqual(successor_rows[0]["previous_run_id"], late_baseline)
        self.assertEqual(successor_rows[1], original)

    def test_history_response_byte_cap_and_full_saved_snapshot_download(self):
        self.baseline()
        self.send(self.event("deep_scan_results", [{"ip": "192.168.1.2"}], 3))
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 4))
        with self.session_factory() as db:
            row = db.scalar(select(ScannerRunComparison))
            saved = {**row.comparison, "fixture_full_evidence": "x" * (5 * 1024 * 1024)}
            row.comparison = saved
            db.commit()
            comparison_id = row.id
        response = self.history()
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(response.content), 4 * 1024 * 1024)
        body = response.json()
        self.assertEqual(body["returned_count"], 1)
        self.assertTrue(body["truncated"])
        self.assertIn("oversized_entry_summary", body["truncation_reasons"])
        entry = body["comparisons"][0]
        self.assertTrue(entry["comparison_truncated"])
        self.assertEqual(entry["comparison"]["counts"]["hosts_added"], 1)
        self.assertNotIn("fixture_full_evidence", entry["comparison"])
        download = self.client.get(entry["full_evidence_url"])
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.json()["comparison"], saved)
        self.assertIn("attachment", download.headers["content-disposition"])
        self.assertEqual(download.headers["cache-control"], "no-store")
        self.client.post("/api/workspaces", json={"name": "Other", "domain": "other-download-fixture.example"})
        self.assertEqual(self.client.get(entry["detail_url"]).status_code, 404)

    def test_history_full_entries_stop_at_response_byte_cap_with_reason(self):
        self.baseline()
        self.send(self.event("deep_scan_results", [{"ip": "192.168.1.2"}], 3))
        self.send(self.event("job_status", {"status": "completed", "job_type": "scan"}, 4))
        with self.session_factory() as db:
            original = db.scalar(select(ScannerRunComparison))
            original.comparison = {**original.comparison, "fixture_full_evidence": "x" * (2200 * 1024)}
            db.add(ScannerRunComparison(organization_id=original.organization_id, agent_id=original.agent_id,
                current_run_id=str(uuid4()), previous_run_id=original.previous_run_id,
                current_result_event_id=original.current_result_event_id,
                previous_result_event_id=original.previous_result_event_id, detected_at=server.utcnow(),
                meaningful_change_count=original.meaningful_change_count, comparison=original.comparison))
            db.commit()
        response = self.history()
        self.assertLessEqual(len(response.content), 4 * 1024 * 1024)
        body = response.json()
        self.assertEqual(body["returned_count"], 1)
        self.assertTrue(body["truncated"])
        self.assertEqual(body["truncation_reasons"], ["response_byte_limit"])
        self.assertFalse(body["comparisons"][0]["comparison_truncated"])
        self.assertIn("fixture_full_evidence", body["comparisons"][0]["comparison"])
