import json
import unittest
from uuid import uuid4
from unittest.mock import AsyncMock, patch
from sqlalchemy import select
from daedalus import server
from daedalus.models import Agent, AgentCommand, AuditLog, Membership, Organization, ScanEvent, User
try:
    from . import test_scanner_runs as fixtures
except ImportError:
    import test_scanner_runs as fixtures


class ScannerDisableTests(unittest.TestCase):
    setUp = fixtures.ScannerRunTests.setUp
    tearDown = fixtures.ScannerRunTests.tearDown
    create_scanner = fixtures.ScannerRunTests.create_scanner
    setup_scanner = fixtures.ScannerRunTests.setup_scanner
    envelope = fixtures.ScannerRunTests.envelope
    send = fixtures.ScannerRunTests.send

    def commands(self):
        with self.session_factory() as db:
            agent = db.get(Agent, self.agent)
            admin = db.scalar(select(User).where(User.google_subject == "daedalus-local-demo-admin"))
            ids = {}
            for status in ("queued", "delivered", "accepted", "succeeded"):
                command = AgentCommand(organization_id=agent.organization_id, agent_id=agent.id,
                    action="start_scan", target="192.168.1.1", status=status,
                    created_by_user_id=admin.id, result=None if status == "queued" else f"original {status} evidence",
                    created_at=server.utcnow(), updated_at=server.utcnow())
                db.add(command)
                db.flush()
                ids[status] = command.id
            db.commit()
            return ids

    def test_disable_audited_once_cancels_only_queued_and_preserves_evidence(self):
        self.setup_scanner()
        ids = self.commands()
        saved = self.send(self.envelope()).json()["event_id"]
        with patch.object(server.live_hub, "publish", new_callable=AsyncMock) as publish:
            disabled = self.client.post(f"/api/agents/{self.agent}/disable")
            self.assertEqual(disabled.status_code, 200, disabled.text)
            result = disabled.json()
            self.assertFalse(result["duplicate"])
            self.assertEqual(result["cancelled_queued_command_count"], 1)
            self.assertEqual(result["unconfirmed_active_command_count"], 2)
            retry = self.client.post(f"/api/agents/{self.agent}/disable")
            self.assertTrue(retry.json()["duplicate"])
            self.assertEqual(retry.json()["cancelled_queued_command_count"], 0)
            publish.assert_awaited_once()
            self.assertFalse(publish.call_args.args[1]["enabled"])
        with self.session_factory() as db:
            self.assertFalse(db.get(Agent, self.agent).enabled)
            self.assertIsNotNone(db.get(ScanEvent, saved))
            self.assertEqual(db.get(AgentCommand, ids["queued"]).status, "cancelled")
            for status in ("delivered", "accepted", "succeeded"):
                command = db.get(AgentCommand, ids[status])
                self.assertEqual(command.status, status)
                self.assertEqual(command.result, f"original {status} evidence")
            logs = db.scalars(select(AuditLog).where(AuditLog.action == "scanner.disabled")).all()
            self.assertEqual(len(logs), 1)
            self.assertFalse(logs[0].details["local_execution_stopped"])
        scanner = next(row for row in self.client.get("/api/dashboard").json()["agents"] if row["id"] == self.agent)
        self.assertFalse(scanner["enabled"])
        self.assertEqual(scanner["status"], "disabled")
        self.assertEqual(self.client.get(f"/api/agents/{self.agent}/runs").status_code, 200)

    def test_disabled_token_rejected_by_all_authenticated_agent_paths_and_admin_commands(self):
        self.setup_scanner()
        ids = self.commands()
        self.client.post(f"/api/agents/{self.agent}/disable")
        self.assertEqual(self.client.post(f"/api/agents/{self.agent}/heartbeat", headers=self.headers, json={}).status_code, 401)
        self.assertEqual(self.send(self.envelope()).status_code, 401)
        self.assertEqual(self.client.post(f"/api/agents/{self.agent}/event-artifacts", headers=self.headers,
            content=json.dumps(self.envelope())).status_code, 401)
        self.assertEqual(self.client.get(f"/api/agents/{self.agent}/commands/next", headers=self.headers).status_code, 401)
        self.assertEqual(self.client.post(f"/api/agents/{self.agent}/commands/{ids['delivered']}/result", headers=self.headers,
            json={"status": "succeeded", "result": "must not be accepted"}).status_code, 401)
        for action in ("start_scan", "cancel_scan", "check_nmapui_updates", "restart_nmapui", "refresh_health", "collect_diagnostics"):
            denied = self.client.post(f"/api/agents/{self.agent}/commands", json={"action": action, "target": "192.168.1.1"})
            self.assertEqual(denied.status_code, 409)

    def test_disable_is_workspace_admin_only_and_available_during_probation(self):
        self.setup_scanner()
        with self.session_factory() as db:
            agent = db.get(Agent, self.agent)
            org = db.get(Organization, agent.organization_id)
            org.verification_status = "probation"
            member = db.scalar(select(Membership).where(Membership.organization_id == org.id))
            member.role = "user"
            membership_id = member.id
            db.commit()
        self.assertEqual(self.client.post(f"/api/agents/{self.agent}/disable").status_code, 403)
        with self.session_factory() as db:
            db.get(Membership, membership_id).role = "admin"
            db.commit()
        accepted = self.client.post(f"/api/agents/{self.agent}/disable")
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.client.post("/api/workspaces", json={"name": "Other", "domain": "other-disable-fixture.example"})
        self.assertEqual(self.client.post(f"/api/agents/{self.agent}/disable").status_code, 404)
