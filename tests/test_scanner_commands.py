import unittest
from datetime import timedelta
from sqlalchemy import select, text, inspect, update
from unittest.mock import patch
from daedalus import server
from daedalus.models import AgentCommand, AuditLog, Membership
try:
    from . import test_cis_pdf_flow as fixtures
except ImportError:
    import test_cis_pdf_flow as fixtures


class ScannerCommandLifecycleTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown
    create_scanner = fixtures.CISReportPDFFlowTests.create_scanner

    def ready(self, protocol=1):
        agent_id, _ = self.create_scanner()
        self.headers = {"Authorization": "Bearer test-scanner-token"}
        self.client.post(f"/api/agents/{agent_id}/heartbeat", headers=self.headers,
                         json={"nmapui_connected": False, "command_protocol_version": protocol})
        return agent_id

    def queue(self, agent_id, action="collect_diagnostics"):
        response = self.client.post(f"/api/agents/{agent_id}/commands", json={"action": action})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["id"]

    def result(self, agent_id, command_id, status, result="evidence"):
        return self.client.post(f"/api/agents/{agent_id}/commands/{command_id}/result",
                                headers=self.headers, json={"status": status, "result": result})

    def test_raw_command_history_is_admin_only(self):
        agent_id, admin_id = self.create_scanner()
        self.headers = {"Authorization": "Bearer test-scanner-token"}
        self.client.post(f"/api/agents/{agent_id}/heartbeat", headers=self.headers,
                         json={"nmapui_connected": False, "command_protocol_version": 1})
        command_id = self.queue(agent_id, "collect_diagnostics")
        delivered = self.client.get(f"/api/agents/{agent_id}/commands/next",
                                    headers=self.headers)
        self.assertEqual(delivered.json()["command"]["id"], command_id)
        private_result = "diagnostic detail containing internal hostnames"
        self.assertEqual(self.result(agent_id, command_id, "succeeded", private_result).status_code, 200)
        admin_history = self.client.get(f"/api/agents/{agent_id}/commands")
        self.assertEqual(admin_history.status_code, 200)
        self.assertEqual(admin_history.json()["commands"][0]["result"], private_result)

        with self.session_factory() as db:
            membership = db.scalar(select(Membership).where(Membership.user_id == admin_id))
            self.assertIsNotNone(membership)
            membership.role = "user"
            db.commit()

        member_history = self.client.get(f"/api/agents/{agent_id}/commands")
        self.assertEqual(member_history.status_code, 403, member_history.text)

    def test_delivery_completion_replay_and_undelivered_rejection(self):
        agent = self.ready()
        command = self.queue(agent)
        self.assertEqual(self.result(agent, command, "succeeded").status_code, 409)
        delivered = self.client.get(f"/api/agents/{agent}/commands/next", headers=self.headers).json()["command"]
        self.assertTrue(delivered["deadline_at"])
        self.assertEqual(self.result(agent, command, "accepted").status_code, 200)
        self.assertTrue(self.result(agent, command, "accepted").json()["duplicate"])
        self.assertEqual(self.result(agent, command, "accepted", "changed").status_code, 409)
        completed = self.result(agent, command, "succeeded")
        self.assertEqual(completed.status_code, 200, completed.text)
        self.assertTrue(self.result(agent, command, "succeeded").json()["duplicate"])
        self.assertEqual(self.result(agent, command, "failed").status_code, 409)
        history = self.client.get(f"/api/agents/{agent}/commands").json()["commands"][0]
        self.assertEqual(history["status"], "succeeded")
        self.assertTrue(history["completed_at"])
        with self.session_factory() as db:
            logs = db.scalars(select(AuditLog).where(AuditLog.action == "scanner.command_result_reported")).all()
            self.assertEqual(len(logs), 2)
            delivery_logs = db.scalars(select(AuditLog).where(AuditLog.action == "scanner.command_delivered")).all()
            self.assertEqual(len(delivery_logs), 1)
            self.assertEqual(delivery_logs[0].details["command_id"], command)
            self.assertEqual(delivery_logs[0].details["deadline_at"], delivered["deadline_at"])

    def test_capability_and_workspace_scope(self):
        agent = self.ready(protocol=0)
        for action in ("refresh_health", "collect_diagnostics"):
            self.assertEqual(self.client.post(f"/api/agents/{agent}/commands", json={"action": action}).status_code, 409)
        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"command_protocol_version": 1})
        self.queue(agent, "refresh_health")
        self.client.post("/api/workspaces", json={"name": "Another", "domain": "another-fixture.example"})
        self.assertEqual(self.client.get(f"/api/agents/{agent}/commands").status_code, 404)

    def test_macos_update_check_requires_online_darwin_protocol_three(self):
        agent = self.ready(protocol=2)
        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"platform": "Darwin", "nmapui_connected": True,
                               "command_protocol_version": 2})
        self.assertEqual(self.client.post(f"/api/agents/{agent}/commands",
                                          json={"action": "check_os_updates"}).status_code, 409)
        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"platform": "Linux", "nmapui_connected": True,
                               "command_protocol_version": 3})
        self.assertEqual(self.client.post(f"/api/agents/{agent}/commands",
                                          json={"action": "check_os_updates"}).status_code, 409)
        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"platform": "Darwin", "nmapui_connected": False,
                               "command_protocol_version": 3})
        with self.session_factory() as db:
            row = db.get(server.Agent, agent)
            row.last_seen_at = server.utcnow() - timedelta(minutes=2)
            db.commit()
        self.assertEqual(self.client.post(f"/api/agents/{agent}/commands",
                                          json={"action": "check_os_updates"}).status_code, 409)
        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"platform": "Darwin", "nmapui_connected": True,
                               "command_protocol_version": 3})
        queued = self.client.post(f"/api/agents/{agent}/commands",
                                  json={"action": "check_os_updates"})
        self.assertEqual(queued.status_code, 200, queued.text)
        delivered = self.client.get(f"/api/agents/{agent}/commands/next",
                                    headers=self.headers).json()["command"]
        self.assertEqual(delivered["action"], "check_os_updates")

    def test_timeout_does_not_claim_scan_success_and_is_audited_once(self):
        agent = self.ready()
        command = self.queue(agent)
        self.client.get(f"/api/agents/{agent}/commands/next", headers=self.headers)
        self.result(agent, command, "accepted")
        with self.session_factory() as db:
            saved = db.get(AgentCommand, command)
            saved.deadline_at = server.utcnow() - timedelta(seconds=1)
            db.commit()
        server.expire_scanner_commands()
        server.expire_scanner_commands()
        self.assertEqual(self.result(agent, command, "succeeded").status_code, 409)
        history = self.client.get(f"/api/agents/{agent}/commands").json()["commands"][0]
        self.assertEqual(history["status"], "timed_out")
        with self.session_factory() as db:
            logs = db.scalars(select(AuditLog).where(AuditLog.action == "scanner.command_timed_out")).all()
            self.assertEqual(len(logs), 1)

    def test_additive_migration_repeatable(self):
        with self.engine.begin() as connection:
            connection.execute(text("DROP TABLE agent_commands"))
            connection.execute(text("CREATE TABLE agent_commands (id INTEGER PRIMARY KEY)"))
            server.ensure_agent_command_columns(connection)
            server.ensure_agent_command_columns(connection)
            self.assertTrue({"delivered_at", "deadline_at", "completed_at"}.issubset(
                {col["name"] for col in inspect(connection).get_columns("agent_commands")}))
            self.assertIn("skip_host_discovery", {col["name"] for col in inspect(connection).get_columns("agent_commands")})

    def test_known_target_option_is_strict_scoped_audited_and_delivered(self):
        agent = self.ready(protocol=2)
        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"nmapui_connected": True, "command_protocol_version": 1})
        unsupported = self.client.post(f"/api/agents/{agent}/commands", json={
            "action": "start_scan", "target": "127.0.0.1", "skip_host_discovery": True,
        })
        self.assertEqual(unsupported.status_code, 409)

        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"nmapui_connected": True, "command_protocol_version": 2})
        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"nmapui_connected": True, "command_protocol_version": 1})
        for value in ("true", 1):
            invalid = self.client.post(f"/api/agents/{agent}/commands", json={
                "action": "start_scan", "target": "127.0.0.1", "skip_host_discovery": value,
            })
            self.assertEqual(invalid.status_code, 422)
        invalid_action = self.client.post(f"/api/agents/{agent}/commands", json={
            "action": "collect_diagnostics", "skip_host_discovery": True,
        })
        self.assertEqual(invalid_action.status_code, 422)

        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"nmapui_connected": True, "command_protocol_version": 2})
        queued = self.client.post(f"/api/agents/{agent}/commands", json={
            "action": "start_scan", "target": "127.0.0.1", "skip_host_discovery": True,
        })
        self.assertEqual(queued.status_code, 200, queued.text)
        command_id = queued.json()["id"]
        delivered = self.client.get(f"/api/agents/{agent}/commands/next", headers=self.headers).json()["command"]
        self.assertTrue(delivered["skip_host_discovery"])
        history = self.client.get(f"/api/agents/{agent}/commands").json()["commands"]
        self.assertTrue(next(row for row in history if row["id"] == command_id)["skip_host_discovery"])
        with self.session_factory() as db:
            audit_event = db.scalar(select(AuditLog).where(
                AuditLog.action == "scanner.command_queued",
                AuditLog.details["command_id"].as_integer() == command_id,
            ))
            self.assertTrue(audit_event.details["skip_host_discovery"])

    def test_scan_deadline_fixed_from_delivery_and_queued_offline_expiry(self):
        agent = self.ready()
        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"nmapui_connected": True, "command_protocol_version": 1})
        queued = self.client.post(f"/api/agents/{agent}/commands",
                                 json={"action": "start_scan", "target": "192.168.1.1"})
        self.assertEqual(queued.status_code, 200, queued.text)
        command_id = queued.json()["id"]
        self.client.get(f"/api/agents/{agent}/commands/next", headers=self.headers)
        with self.session_factory() as db:
            command = db.get(AgentCommand, command_id)
            deadline = command.deadline_at
            self.assertEqual(deadline - command.delivered_at, timedelta(hours=2))
        self.result(agent, command_id, "accepted")
        with self.session_factory() as db:
            self.assertEqual(db.get(AgentCommand, command_id).deadline_at, deadline)
        stale = self.queue(agent)
        with self.session_factory() as db:
            db.get(AgentCommand, stale).created_at = server.utcnow() - timedelta(minutes=6)
            db.commit()
        statuses = {entry["id"]: entry["status"] for entry in
                    self.client.get(f"/api/agents/{agent}/commands").json()["commands"]}
        self.assertEqual(statuses[stale], "expired")
        self.assertEqual(self.result(agent, stale, "succeeded").status_code, 409)

    def test_legacy_fallback_does_not_write_after_concurrent_completion(self):
        agent = self.ready()
        command_id = self.queue(agent)
        with self.session_factory() as db:
            command = db.get(AgentCommand, command_id)
            command.status = "accepted"
            command.updated_at = server.utcnow() - timedelta(minutes=10)
            db.commit()
            original_execute = db.execute
            raced = False

            def execute_with_completion(statement, *args, **kwargs):
                nonlocal raced
                if not raced and getattr(statement, "is_update", False):
                    raced = True
                    original_execute(update(AgentCommand).where(AgentCommand.id == command_id).values(
                        status="succeeded", result="completed evidence", completed_at=server.utcnow()),
                        execution_options={"synchronize_session": False})
                return original_execute(statement, *args, **kwargs)

            with patch.object(db, "execute", side_effect=execute_with_completion):
                server.expire_scanner_commands_in_session(db, agent_id=agent)
            db.commit()
            db.refresh(command)
            self.assertTrue(raced)
            self.assertEqual(command.status, "succeeded")
            self.assertEqual(command.result, "completed evidence")
            self.assertIsNone(command.delivered_at)
            self.assertIsNone(command.deadline_at)

    def test_scan_target_must_be_inside_the_selected_scanners_approved_networks(self):
        self.assertEqual(server.validate_scanner_network_scopes(["10.0.0.0/8"]), ["10.0.0.0/8"])
        agent = self.ready(protocol=2)
        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"nmapui_connected": True, "command_protocol_version": 2})
        with self.session_factory() as db:
            saved = db.get(server.Agent, agent)
            saved.authorized_networks = ["10.24.8.0/24", "192.168.44.0/24"]
            db.commit()

        allowed = self.client.post(f"/api/agents/{agent}/commands", json={
            "action": "start_scan", "target": "10.24.8.128/25",
        })
        self.assertEqual(allowed.status_code, 200, allowed.text)
        saved_command = self.client.get(f"/api/agents/{agent}/commands").json()["commands"][0]
        self.assertEqual(saved_command["target"], "10.24.8.128/25")

        outside = self.client.post(f"/api/agents/{agent}/commands", json={
            "action": "start_scan", "target": "10.24.9.0/24",
        })
        self.assertEqual(outside.status_code, 422)
        self.assertIn("outside the scanner's approved networks", outside.json()["detail"])

        invalid_scope = self.client.put(f"/api/agents/{agent}/network-scope", json={
            "authorized_networks": ["203.0.113.0/24"],
        })
        self.assertEqual(invalid_scope.status_code, 422)

        removed_scope = self.client.put(f"/api/agents/{agent}/network-scope", json={
            "authorized_networks": [],
        })
        self.assertEqual(removed_scope.status_code, 200, removed_scope.text)
        self.assertEqual(removed_scope.json()["authorized_networks"], [])
        now_unscoped = self.client.post(f"/api/agents/{agent}/commands", json={
            "action": "start_scan", "target": "10.24.8.2",
        })
        self.assertEqual(now_unscoped.status_code, 422)

    def test_scope_update_cancels_queued_scan_that_no_longer_fits(self):
        agent = self.ready(protocol=2)
        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"nmapui_connected": True, "command_protocol_version": 2})
        with self.session_factory() as db:
            db.get(server.Agent, agent).authorized_networks = ["127.0.0.0/24"]
            db.commit()
        queued = self.client.post(f"/api/agents/{agent}/commands", json={
            "action": "start_scan", "target": "127.0.0.0/24",
        })
        self.assertEqual(queued.status_code, 200, queued.text)
        narrowed = self.client.put(f"/api/agents/{agent}/network-scope", json={
            "authorized_networks": ["127.0.0.1/32"],
        })
        self.assertEqual(narrowed.status_code, 200, narrowed.text)
        self.assertEqual(narrowed.json()["cancelled_queued_scan_count"], 1)
        command = self.client.get(f"/api/agents/{agent}/commands").json()["commands"][0]
        self.assertEqual(command["status"], "cancelled")
        self.assertIn("scope changed", command["result"])

    def test_scope_update_reports_already_delivered_scan_as_unconfirmed(self):
        agent = self.ready(protocol=2)
        self.client.post(f"/api/agents/{agent}/heartbeat", headers=self.headers,
                         json={"nmapui_connected": True, "command_protocol_version": 2})
        with self.session_factory() as db:
            db.get(server.Agent, agent).authorized_networks = ["127.0.0.0/24"]
            db.commit()
        queued = self.client.post(f"/api/agents/{agent}/commands", json={
            "action": "start_scan", "target": "127.0.0.0/24",
        })
        self.assertEqual(queued.status_code, 200, queued.text)
        command_id = queued.json()["id"]
        self.client.get(f"/api/agents/{agent}/commands/next", headers=self.headers)
        narrowed = self.client.put(f"/api/agents/{agent}/network-scope", json={
            "authorized_networks": ["127.0.0.1/32"],
        })
        self.assertEqual(narrowed.status_code, 200, narrowed.text)
        self.assertEqual(narrowed.json()["unconfirmed_active_scan_count"], 1)
        with self.session_factory() as db:
            self.assertEqual(db.get(AgentCommand, command_id).status, "delivered")

    def test_enrollment_code_binds_scanner_name_and_network_scope(self):
        enrollment = self.client.post("/api/enrollment-tokens", json={
            "name": "Office VLAN 24",
            "authorized_networks": ["10.24.8.0/24", "192.168.44.0/24"],
        })
        self.assertEqual(enrollment.status_code, 200, enrollment.text)
        code = enrollment.json()["code"]
        mismatched_name = self.client.post("/api/agents/enroll", json={
            "code": code, "name": "Unapproved name",
        })
        self.assertEqual(mismatched_name.status_code, 409)
        enrolled = self.client.post("/api/agents/enroll", json={
            "code": code, "name": "Office VLAN 24",
        })
        self.assertEqual(enrolled.status_code, 200, enrolled.text)
        self.assertEqual(enrolled.json()["authorized_networks"], ["10.24.8.0/24", "192.168.44.0/24"])
        with self.session_factory() as db:
            saved = db.get(server.Agent, enrolled.json()["agent_id"])
            self.assertEqual(saved.authorized_networks, ["10.24.8.0/24", "192.168.44.0/24"])
