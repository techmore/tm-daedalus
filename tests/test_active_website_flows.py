import copy
import unittest
from datetime import timedelta
from unittest.mock import patch
from sqlalchemy import select
from daedalus import server
from daedalus.models import Organization, Membership, ProbationOverride, ExternalCheckRun, AuditLog
try:
    from . import test_cis_pdf_flow as fixtures
except ImportError:
    import test_cis_pdf_flow as fixtures


class ActiveWebsiteFlowsTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown

    def context(self):
        with self.session_factory() as db:
            org = db.scalar(select(Organization).where(Organization.domain == "cybersecuritypilot.org"))
            member = db.scalar(select(Membership).where(Membership.organization_id == org.id))
            return org.id, member.user_id

    def snapshot(self, findings=None, complete=True, preset="fixed-exposure-v1"):
        return {"domain": "cybersecuritypilot.org", "preset_version": preset,
                "coverage_complete": complete, "findings": findings or [], "probes": [], "error_code": None}

    def finding(self, status=200):
        return {"signature_id": "exposed_git_head", "path": "/.git/HEAD", "http_status": status,
                "evidence_confidence": "signature_match_requires_review"}

    def run_check(self, snapshot=None):
        with patch.object(server, "run_active_website_check", return_value=snapshot or self.snapshot()) as collector:
            result = self.client.post("/api/external-checks/web-active/run")
        return result, collector

    def test_verified_run_actor_audit_history_and_immutable_snapshot(self):
        snapshot = self.snapshot([self.finding()])
        response, collector = self.run_check(snapshot)
        self.assertEqual(response.status_code, 200, response.text)
        collector.assert_called_once_with("cybersecuritypilot.org")
        frozen = copy.deepcopy(response.json()["snapshot"])
        snapshot["findings"].clear()
        history = self.client.get("/api/external-checks/web-active").json()
        self.assertEqual(history["runs"][0]["snapshot"], frozen)
        self.assertEqual(history["runs"][0]["source"], "manual")
        self.assertTrue(history["runs"][0]["actor"])
        with self.session_factory() as db:
            actions = db.scalars(select(AuditLog.action).where(AuditLog.action.like("external_check.%"))).all()
        self.assertEqual(actions.count("external_check.queued"), 1)
        self.assertEqual(actions.count("external_check.completed"), 1)
        self.assertEqual(len(history["runs"]), 1)

    def test_dashboard_exposes_load_older_controls_for_all_external_history(self):
        page = self.client.get("/dashboard")
        self.assertEqual(page.status_code, 200, page.text[:500])
        self.assertIn('data-load-older-checks="dns"', page.text)
        self.assertIn('data-load-older-checks="web"', page.text)
        self.assertIn('data-load-older-active="runs"', page.text)
        self.assertIn('data-load-older-active="changes"', page.text)

    def test_override_and_expiry_and_member_gates(self):
        org_id, user_id = self.context()
        with self.session_factory() as db:
            db.get(Organization, org_id).verification_status = "pending"
            db.commit()
        response, collector = self.run_check()
        self.assertEqual(response.status_code, 403)
        collector.assert_not_called()
        with self.session_factory() as db:
            override = ProbationOverride(organization_id=org_id, granted_by_user_id=user_id,
                reason="fixture authorization", starts_at=server.utcnow() - timedelta(seconds=1),
                expires_at=server.utcnow() + timedelta(days=14), created_at=server.utcnow())
            db.add(override)
            db.commit()
            override_id = override.id
        self.assertEqual(self.run_check()[0].status_code, 200)
        with self.session_factory() as db:
            db.get(ProbationOverride, override_id).expires_at = server.utcnow() - timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.run_check()[0].status_code, 403)
        with self.session_factory() as db:
            db.get(Organization, org_id).verification_status = "verified"
            membership = db.scalar(select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id))
            membership.role = "user"
            db.commit()
        self.assertEqual(self.run_check()[0].status_code, 403)
        self.assertEqual(self.client.get("/api/external-checks/web-active").status_code, 200)

    def test_worker_rechecks_before_insert_and_before_collection(self):
        org_id, user_id = self.context()
        with self.session_factory() as db:
            db.get(Organization, org_id).verification_status = "expired"
            db.commit()
        with patch.object(server, "run_active_website_check") as collector:
            with self.assertRaises(server.HTTPException):
                server.execute_external_check(org_id, user_id, "web-active")
            collector.assert_not_called()
        with self.session_factory() as db:
            db.get(Organization, org_id).verification_status = "verified"
            db.commit()
        with patch.object(server, "workspace_controls_available", side_effect=[True, False]), patch.object(server, "run_active_website_check") as collector:
            result = server.execute_external_check(org_id, user_id, "web-active")
            self.assertEqual(result["status"], "failed")
            collector.assert_not_called()

    def test_complete_comparison_add_resolve_and_incomplete_or_preset_blocks(self):
        self.assertEqual(self.run_check()[0].json()["change_count"], 0)
        added = self.run_check(self.snapshot([self.finding()]))[0].json()
        self.assertEqual(added["change_count"], 1)
        resolved = self.run_check()[0].json()
        self.assertEqual(resolved["change_count"], 1)
        incomplete = self.run_check(self.snapshot([self.finding()], complete=False))[0].json()
        self.assertEqual(incomplete["status"], "completed_with_warnings")
        self.assertEqual(incomplete["change_count"], 0)
        self.assertEqual(self.run_check()[0].json()["change_count"], 0)
        changed_preset = self.run_check(self.snapshot([self.finding()], preset="other"))[0].json()
        self.assertEqual(changed_preset["change_count"], 0)
        changes = self.client.get("/api/external-checks/web-active").json()["changes"]
        self.assertIsNone(changes[0]["current_value"])
        self.assertIsNone(changes[1]["previous_value"])

    def test_running_limit_and_failed_metadata_and_no_schedule(self):
        org_id, _ = self.context()
        with self.session_factory() as db:
            run = ExternalCheckRun(organization_id=org_id, check_type="web-active", domain="cybersecuritypilot.org", status="running", started_at=server.utcnow())
            db.add(run)
            db.commit()
            run_id = run.id
        response, collector = self.run_check()
        self.assertEqual(response.status_code, 409)
        collector.assert_not_called()
        with self.session_factory() as db:
            db.get(ExternalCheckRun, run_id).status = "failed"
            db.commit()
        with patch.object(server, "run_active_website_check", side_effect=RuntimeError("secret must not escape")):
            response = self.client.post("/api/external-checks/web-active/run")
        result = response.json()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_summary"], "Check failed (RuntimeError).")
        self.assertIsNotNone(result["completed_at"])
        self.assertEqual(result["change_count"], 0)
        self.assertEqual(self.client.put("/api/external-checks/web-active/schedule", json={"enabled": True, "interval_hours": 24}).status_code, 404)

    def test_history_workspace_scope_and_cursor_pagination(self):
        for index in range(14):
            findings = [self.finding()] if index % 2 else []
            self.assertEqual(self.run_check(self.snapshot(findings))[0].status_code, 200)
        first_page = self.client.get(
            "/api/external-checks/web-active", params={"changes_limit": 12}
        ).json()
        self.assertEqual(len(first_page["runs"]), 12)
        self.assertTrue(first_page["runs_has_more"])
        older_page = self.client.get(
            "/api/external-checks/web-active",
            params={"runs_before": first_page["runs_next_before"]},
        ).json()
        self.assertEqual(len(older_page["runs"]), 2)
        self.assertFalse(older_page["runs_has_more"])
        self.assertEqual(older_page["runs"][0]["id"], first_page["runs"][-1]["id"] - 1)
        self.assertEqual(older_page["latest_snapshot"], first_page["latest_snapshot"])
        self.assertEqual(len(first_page["changes"]), 12)
        self.assertTrue(first_page["changes_has_more"])
        older_changes = self.client.get(
            "/api/external-checks/web-active",
            params={"changes_before": first_page["changes_next_before"]},
        ).json()
        self.assertEqual(len(older_changes["changes"]), 1)
        self.assertFalse(older_changes["changes_has_more"])
        self.client.post("/api/workspaces", json={"name": "Other", "domain": "other-active.example"})
        history = self.client.get("/api/external-checks/web-active").json()
        self.assertEqual(history["runs"], [])
        self.assertFalse(history["runs_has_more"])
        self.assertEqual(history["changes"], [])
        self.assertIsNone(history["latest_snapshot"])


if __name__ == "__main__":
    unittest.main()
