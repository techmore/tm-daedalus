import unittest
from sqlalchemy.exc import IntegrityError
from sqlalchemy import create_engine, inspect, select
from fastapi.testclient import TestClient
from daedalus.db import Base
from daedalus import server
from daedalus.models import (
    Membership, Organization, User, WorkspaceNotification, WorkspaceNotificationRead, ExternalCheckRun,
)
try:
    from . import test_cis_pdf_flow as fixtures
except ImportError:
    import test_cis_pdf_flow as fixtures


class WorkspaceNotificationTests(unittest.TestCase):
    setUp = fixtures.CISReportPDFFlowTests.setUp
    tearDown = fixtures.CISReportPDFFlowTests.tearDown

    def workspace(self):
        with self.session_factory() as db:
            org = db.scalar(select(Organization).where(Organization.domain == "cybersecuritypilot.org"))
            admin = db.scalar(select(Membership).where(Membership.organization_id == org.id, Membership.role == "admin"))
            return org.id, admin.user_id

    def run_dns(self, snapshot):
        org_id, user_id = self.workspace()
        from unittest.mock import patch
        with patch.object(server, "run_dns_check", return_value=snapshot):
            return server.execute_external_check(org_id, user_id, "dns")

    def run_web(self, snapshot):
        from unittest.mock import patch
        org_id, user_id = self.workspace()
        with patch.object(server, "run_website_check", return_value=snapshot):
            return server.execute_external_check(org_id, user_id, "web")

    def test_interrupted_audit_creates_one_persistent_notice_and_preserves_history(self):
        org_id, user_id = self.workspace()
        with self.session_factory() as db:
            run = ExternalCheckRun(organization_id=org_id, check_type="web-nikto",
                domain="cybersecuritypilot.org", status="running", trigger_source="manual",
                triggered_by_user_id=user_id, started_at=server.utcnow(), change_count=0)
            db.add(run); db.commit(); run_id = run.id
        self.assertEqual(server.recover_interrupted_external_checks(), 1)
        self.assertEqual(server.recover_interrupted_external_checks(), 0)
        with self.session_factory() as db:
            run = db.get(ExternalCheckRun, run_id)
            self.assertEqual(run.status, "failed")
            self.assertIsNone(run.snapshot)
            self.assertIsNotNone(run.completed_at)
            notices = db.scalars(select(WorkspaceNotification).where(
                WorkspaceNotification.source_type == "external_check_run",
                WorkspaceNotification.source_id == run_id)).all()
            self.assertEqual(len(notices), 1)
            self.assertEqual(notices[0].organization_id, org_id)
            self.assertEqual(notices[0].reason, "check_failed")
            self.assertIn("interrupted", notices[0].title)

    def test_existing_database_gets_notification_tables_through_metadata_upgrade(self):
        engine = create_engine("sqlite://")
        try:
            prior_tables = [
                table for table in Base.metadata.sorted_tables
                if table.name not in {"workspace_notifications", "workspace_notification_reads"}
            ]
            Base.metadata.create_all(engine, tables=prior_tables)
            self.assertFalse(inspect(engine).has_table("workspace_notifications"))
            # This is the same additive Base.metadata.create_all path run at app startup.
            Base.metadata.create_all(engine)
            self.assertTrue(inspect(engine).has_table("workspace_notifications"))
            self.assertTrue(inspect(engine).has_table("workspace_notification_reads"))
        finally:
            engine.dispose()

    def test_probation_notice_is_scoped_to_the_selected_workspace(self):
        other = TestClient(server.app)
        try:
            self.assertEqual(other.post("/dev/login", follow_redirects=False).status_code, 303)
            created = other.post(
                "/api/workspaces",
                json={"name": "Other Workspace", "domain": "other-notices.example"},
            )
            self.assertEqual(created.status_code, 200, created.text)
            other_id = created.json()["organization_id"]
            with self.session_factory() as db:
                db.add(WorkspaceNotification(
                    organization_id=other_id,
                    source_type="probation_override_granted",
                    source_id=991,
                    title="Temporary probation override granted",
                    summary="Other Workspace administrator granted a 14-day override.",
                    reason="access_override",
                    detected_at=server.utcnow(),
                ))
                db.commit()

            self.assertEqual(self.client.get("/api/notifications").json()["notifications"], [])
            notices = other.get("/api/notifications").json()["notifications"]
            self.assertEqual(len(notices), 1)
            self.assertEqual(notices[0]["source_id"], 991)
            self.assertEqual(notices[0]["tab"], "members")
        finally:
            other.close()

    def test_baseline_and_failed_runs_do_not_create_notices_but_change_does(self):
        baseline = {"domain": "cybersecuritypilot.org", "records": {"A": ["192.0.2.1"]}, "resolver_errors": {}}
        self.run_dns(baseline)
        with self.session_factory() as db:
            self.assertEqual(db.scalar(select(WorkspaceNotification.id)), None)
        changed = {"domain": "cybersecuritypilot.org", "records": {"A": ["192.0.2.2"]}, "resolver_errors": {}}
        run = self.run_dns(changed)
        self.assertEqual(run["change_count"], 1)
        with self.session_factory() as db:
            notices = db.scalars(select(WorkspaceNotification)).all()
            self.assertEqual(len(notices), 1)
            self.assertEqual(notices[0].reason, "changes")
            self.assertEqual(notices[0].source_id, run["id"])
            self.assertIn("DNS records", notices[0].summary)
            self.assertIsNotNone(notices[0].detected_at)
        from unittest.mock import patch
        org_id, user_id = self.workspace()
        with patch.object(server, "run_dns_check", side_effect=RuntimeError("offline")):
            failed = server.execute_external_check(org_id, user_id, "dns")
        self.assertEqual(failed["status"], "failed")
        with self.session_factory() as db:
            self.assertEqual(len(db.scalars(select(WorkspaceNotification)).all()), 1)

    def test_warning_only_notice_keeps_unknown_checks_distinct_from_confirmed_changes(self):
        warning = {
            "domain": "cybersecuritypilot.org", "records": {"A": ["192.0.2.1"]},
            "resolver_errors": {"www A": "SERVFAIL", "www AAAA": "SERVFAIL"},
        }
        run = self.run_dns(warning)
        self.assertEqual(run["status"], "completed_with_warnings")
        self.assertEqual(run["change_count"], 0)
        response = self.client.get("/api/notifications")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["unread_count"], 1)
        notice = body["notifications"][0]
        self.assertEqual(notice["reason"], "warnings")
        self.assertIn("could not be confirmed", notice["summary"])
        self.assertIn("No confirmed changes", notice["summary"])
        self.assertTrue(notice["detected_at"])

    def test_repeated_warnings_keep_history_without_repeated_notices(self):
        warning = {"domain": "cybersecuritypilot.org", "records": {"A": ["192.0.2.1"]}, "resolver_errors": {"www A": "SERVFAIL"}}
        first = self.run_dns(warning)
        repeated = self.run_dns({**warning, "resolver_errors": {"www A": "LifetimeTimeout"}})
        self.assertEqual(repeated["change_count"], 0)
        notices = self.client.get("/api/notifications").json()["notifications"]
        self.assertEqual([n["source_id"] for n in notices], [first["id"]])
        history = self.client.get("/api/external-checks/dns").json()["runs"]
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["id"], repeated["id"])
        changed = self.run_dns({**warning, "records": {"A": ["192.0.2.2"]}})
        self.assertGreater(changed["change_count"], 0)
        self.assertEqual(len(self.client.get("/api/notifications").json()["notifications"]), 2)

    def test_partial_page_repeat_is_quiet_and_exposure_gap_has_reason(self):
        snapshot = {"http_status": 206, "page_content": {"partial": True, "comparison_eligible": False}}
        first = self.run_web(snapshot)
        repeat = self.run_web(snapshot)
        self.assertEqual(repeat["change_count"], 0)
        self.assertEqual([n["source_id"] for n in self.client.get("/api/notifications").json()["notifications"]], [first["id"]])
        self.assertIn("incomplete", server.external_check_warning_reasons("web-active", {"coverage_complete": False})[0])
        self.assertEqual(server.external_check_warning_reasons("web-active", {"coverage_complete": True}), [])

    def test_warning_recurrence_after_recovery_or_failure_notifies(self):
        from unittest.mock import patch
        warning = {"records": {"A": ["192.0.2.1"]}, "resolver_errors": {"www A": "SERVFAIL"}}
        self.run_dns(warning)
        self.run_dns({"records": warning["records"], "resolver_errors": {}})
        returned = self.run_dns(warning)
        notices = self.client.get("/api/notifications").json()["notifications"]
        self.assertEqual(notices[0]["source_id"], returned["id"])
        org_id, user_id = self.workspace()
        with patch.object(server, "run_dns_check", side_effect=RuntimeError("offline")):
            server.execute_external_check(org_id, user_id, "dns")
        after_failure = self.run_dns(warning)
        self.assertEqual(self.client.get("/api/notifications").json()["notifications"][0]["source_id"], after_failure["id"])

    def test_warning_identity_uses_query_names_not_only_count(self):
        first = self.run_dns({"records": {}, "resolver_errors": {"DS": "SERVFAIL"}})
        changed = self.run_dns({"records": {}, "resolver_errors": {"DNSKEY": "SERVFAIL"}})
        self.assertNotEqual(first["id"], changed["id"])
        self.assertEqual(len(self.client.get("/api/notifications").json()["notifications"]), 2)
        self.assertNotEqual(server.external_check_warning_signature("dns", {"resolver_errors": {"DS": "SERVFAIL"}}), server.external_check_warning_signature("dns", {"resolver_errors": {"DNSKEY": "SERVFAIL"}}))

    def test_website_change_notices_and_history_use_human_readable_labels(self):
        baseline = {
            "domain": "cybersecuritypilot.org", "http_status": 200,
            "final_url": "https://cybersecuritypilot.org/", "content_type": "text/html",
            "page_content": {"sampled_bytes": 100, "sha256": "a" * 64, "comparison_eligible": True},
        }
        self.run_web(baseline)
        changed = {
            "domain": "cybersecuritypilot.org", "http_status": 200,
            "final_url": "https://cybersecuritypilot.org/", "content_type": "text/html",
            "page_content": {"sampled_bytes": 120, "sha256": "b" * 64, "comparison_eligible": True},
        }
        run = self.run_web(changed)
        self.assertEqual(run["change_count"], 2)

        notice = self.client.get("/api/notifications").json()["notifications"][0]
        self.assertIn("2 material changes detected: page content", notice["summary"])
        self.assertNotIn("page_content", notice["summary"])

        self.assertEqual(server.external_check_field_label("records.A"), "DNS record A")
        self.assertEqual(server.external_check_field_label("records.WWW_A"), "DNS record www A")
        history = self.client.get("/api/external-checks/web").json()
        labels = {change["field_path"]: change["field_label"] for change in history["changes"]}
        self.assertEqual(labels["page_content.sampled_bytes"], "Page content size")
        self.assertEqual(labels["page_content.sha256"], "Page content fingerprint")

    def test_partial_website_evidence_creates_warning_only_notice_not_a_change_notice(self):
        snapshot = {
            "http_status": 206,
            "page_content": {"partial": True, "comparison_eligible": False},
            "title": "Partial response",
        }
        run = self.run_web(snapshot)
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["change_count"], 0)
        notice = self.client.get("/api/notifications").json()["notifications"][0]
        self.assertEqual(notice["reason"], "warnings")
        self.assertEqual(notice["tab"], "web")
        self.assertIn("partial", notice["summary"])
        self.assertIn("No confirmed changes", notice["summary"])

    def test_meraki_coverage_only_notice_is_durable_truthful_and_deduplicated(self):
        org_id, _user_id = self.workspace()
        detected_at = server.utcnow()
        with self.session_factory() as db:
            baseline = server.record_meraki_report_notification(
                db,
                organization_id=org_id,
                report_id=87,
                domain="cybersecuritypilot.org",
                comparison={
                    "changed_control_count": 0,
                    "coverage_change_count": 0,
                    "inventory_change_count": 0,
                    "inventory_coverage_change_count": 0,
                },
                detected_at=detected_at,
            )
            coverage_only = server.record_meraki_report_notification(
                db,
                organization_id=org_id,
                report_id=88,
                domain="cybersecuritypilot.org",
                comparison={
                    "changed_control_count": 0,
                    "coverage_change_count": 1,
                    "inventory_change_count": 0,
                    "inventory_coverage_change_count": 0,
                },
                detected_at=detected_at,
            )
            duplicate = server.record_meraki_report_notification(
                db,
                organization_id=org_id,
                report_id=88,
                domain="cybersecuritypilot.org",
                comparison={"coverage_change_count": 1},
                detected_at=detected_at,
            )
            db.commit()
        self.assertFalse(baseline)
        self.assertTrue(coverage_only)
        self.assertFalse(duplicate)
        body = self.client.get("/api/notifications").json()
        self.assertEqual(body["unread_count"], 1)
        notice = body["notifications"][0]
        self.assertEqual(notice["source_type"], "meraki_report")
        self.assertEqual(notice["source_id"], 88)
        self.assertEqual(notice["reason"], "coverage")
        self.assertEqual(notice["tab"], "meraki")
        self.assertIn("No confirmed control or inventory changes", notice["summary"])
        self.assertIn("1 control-coverage change", notice["summary"])

    def test_cis_status_changes_create_durable_notice_but_baselines_and_late_reports_stay_quiet(self):
        profile = {
            "name": "Notification fixture",
            "slug": "notification-fixture",
            "version": "1",
            "platform": "macos",
            "checks": [
                {"id": "firewall", "category": "macos", "description": "Firewall enabled"},
                {"id": "filevault", "category": "macos", "description": "FileVault enabled"},
            ],
        }
        published = self.client.post("/api/cis/profiles", json=profile)
        self.assertEqual(published.status_code, 200, published.text)
        api_key = self.client.post("/api/cis/api-key").json()["api_key"]
        headers = {"X-API-Key": api_key}

        def submit(report_id, timestamp, status):
            return self.client.post("/api/cis/report", headers=headers, json={
                "device_uuid": "notification-fixture-device",
                "report_id": report_id,
                "timestamp": timestamp,
                "profile_slug": profile["slug"],
                "profile_version": profile["version"],
                "system_info": {"hostname": "CSP endpoint fixture", "os_version": "26.0"},
                "results": [
                    {"id": check["id"], "category": "macos", "description": check["description"], "status": status}
                    for check in profile["checks"]
                ],
            })

        baseline = submit("cis-baseline", "2026-09-29T10:00:00Z", "pass")
        self.assertEqual(baseline.status_code, 200, baseline.text)
        self.assertEqual(self.client.get("/api/notifications").json()["notifications"], [])

        unchanged = submit("cis-unchanged", "2026-09-29T11:00:00Z", "pass")
        self.assertEqual(unchanged.json()["changed_check_count"], 0)
        self.assertEqual(self.client.get("/api/notifications").json()["notifications"], [])

        from unittest.mock import AsyncMock, patch
        with patch.object(server.live_hub, "publish", new_callable=AsyncMock) as publish:
            changed = submit("cis-changed", "2026-09-29T12:00:00Z", "fail")
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(changed.json()["changed_check_count"], 2)
        self.assertTrue(changed.json()["notification_created"])
        self.assertTrue(any(
            call.args[1].get("notification_created") is True
            for call in publish.call_args_list
            if call.args[1].get("type") == "cis_report_received"
        ))

        duplicate = submit("cis-changed", "2026-09-29T12:00:00Z", "fail")
        self.assertTrue(duplicate.json()["duplicate"])
        late = submit("cis-late", "2026-09-29T10:30:00Z", "fail")
        self.assertEqual(late.json()["changed_check_count"], 0)
        body = self.client.get("/api/notifications").json()
        self.assertEqual(body["unread_count"], 1)
        self.assertEqual(len(body["notifications"]), 1)
        notice = body["notifications"][0]
        self.assertEqual(notice["source_type"], "cis_report")
        self.assertEqual(notice["source_id"], changed.json()["report_id"])
        self.assertEqual(notice["tab"], "cis")
        self.assertEqual(notice["reason"], "changes")
        self.assertIn("2 CIS check results changed status", notice["summary"])
        self.assertIn("not a compliance conclusion", notice["summary"])

    def test_source_run_unique_key_prevents_duplicate_notice_on_retry(self):
        self.run_dns({"domain": "cybersecuritypilot.org", "records": {"A": ["192.0.2.1"]}, "resolver_errors": {"MX": "SERVFAIL"}})
        with self.session_factory() as db:
            original = db.scalar(select(WorkspaceNotification))
            duplicate = WorkspaceNotification(
                organization_id=original.organization_id,
                source_type=original.source_type,
                source_id=original.source_id,
                title=original.title,
                summary=original.summary,
                reason=original.reason,
                detected_at=original.detected_at,
            )
            db.add(duplicate)
            with self.assertRaises(IntegrityError):
                db.commit()
            db.rollback()
        with self.session_factory() as db:
            self.assertEqual(len(db.scalars(select(WorkspaceNotification)).all()), 1)

    def test_workspace_isolation_and_per_member_read_receipts(self):
        self.run_dns({"domain": "cybersecuritypilot.org", "records": {"A": ["192.0.2.1"]}, "resolver_errors": {"MX": "SERVFAIL"}})
        org_id, admin_id = self.workspace()
        with self.session_factory() as db:
            other_org = Organization(name="Other", slug="other-notifications", domain="other.example", verification_status="verified", created_at=server.utcnow())
            member_user = db.scalar(select(User).where(User.google_subject == "daedalus-local-demo-member"))
            db.add(other_org)
            db.flush()
            db.add(Membership(user_id=admin_id, organization_id=other_org.id, role="admin", status="approved", created_at=server.utcnow()))
            db.add(Membership(user_id=member_user.id, organization_id=org_id, role="user", status="approved", created_at=server.utcnow()))
            db.add(Membership(user_id=member_user.id, organization_id=other_org.id, role="user", status="approved", created_at=server.utcnow()))
            db.commit()
            other_org_id = other_org.id

        notice = self.client.get("/api/notifications").json()["notifications"][0]
        # Another approved member has a separate unread state.
        member_client = __import__("fastapi.testclient", fromlist=["TestClient"]).TestClient(server.app)
        try:
            self.assertEqual(member_client.post("/dev/login/member", follow_redirects=False).status_code, 303)
            self.assertEqual(member_client.post("/api/workspaces/select", json={"organization_id": org_id}).status_code, 200)
            self.assertEqual(member_client.get("/api/notifications").json()["unread_count"], 1)
            self.assertEqual(self.client.post(f"/api/notifications/{notice['id']}/read").status_code, 200)
            self.assertEqual(self.client.post(f"/api/notifications/{notice['id']}/read").status_code, 200)
            self.assertEqual(self.client.get("/api/notifications").json()["unread_count"], 0)
            self.assertEqual(member_client.get("/api/notifications").json()["unread_count"], 1)

            self.assertEqual(member_client.post("/api/workspaces/select", json={"organization_id": other_org_id}).status_code, 200)
            self.assertEqual(member_client.get("/api/notifications").json()["notifications"], [])
            self.assertEqual(member_client.post(f"/api/notifications/{notice['id']}/read").status_code, 404)
        finally:
            member_client.close()
        with self.session_factory() as db:
            receipts = db.scalars(select(WorkspaceNotificationRead)).all()
            self.assertEqual(len(receipts), 1)


if __name__ == "__main__":
    unittest.main()
