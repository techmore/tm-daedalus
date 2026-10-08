import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from daedalus.db import Base, get_db
from daedalus.models import AuditLog, Membership, Organization, ReportJob, User
from daedalus import server


class MerakiWorkspaceScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="daedalus-meraki-scope-")
        self.root = Path(self.temp_dir.name)
        self.engine = create_engine(
            f"sqlite:///{self.root / 'test.db'}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(
            bind=self.engine,
            autoflush=False,
            expire_on_commit=False,
        )

        def override_get_db():
            db = self.session_factory()
            try:
                yield db
            finally:
                db.close()

        self.dependency_overrides = server.app.dependency_overrides.copy()
        server.app.dependency_overrides[get_db] = override_get_db
        self.session_local_patch = patch.object(server, "SessionLocal", self.session_factory)
        self.list_orgs_patch = patch.object(
            server,
            "list_meraki_organizations",
            return_value=[
                {"id": "cisco-org-csp", "name": "CSP tenant"},
                {"id": "cisco-org-client", "name": "Client tenant"},
            ],
        )
        self.encrypt_patch = patch.object(
            server, "encrypt_secret", return_value="encrypted-test-credential"
        )
        self.decrypt_patch = patch.object(
            server, "decrypt_secret", return_value="test-meraki-credential"
        )
        self.report_patch = patch.object(server, "generate_report_job")
        for active_patch in (
            self.session_local_patch,
            self.list_orgs_patch,
            self.encrypt_patch,
            self.decrypt_patch,
            self.report_patch,
        ):
            active_patch.start()
        server.seed_demo_workspace()
        self.client = TestClient(server.app)
        login = self.client.post("/dev/login", follow_redirects=False)
        self.assertEqual(login.status_code, 303)

    def tearDown(self):
        self.client.close()
        server.app.dependency_overrides.clear()
        server.app.dependency_overrides.update(self.dependency_overrides)
        for active_patch in (
            self.report_patch,
            self.decrypt_patch,
            self.encrypt_patch,
            self.list_orgs_patch,
            self.session_local_patch,
        ):
            active_patch.stop()
        self.engine.dispose()
        self.temp_dir.cleanup()

    def _connect_key(self, api_key="test-meraki-key-123456"):
        response = self.client.put(
            "/api/meraki/credential", json={"api_key": api_key}
        )
        self.assertEqual(response.status_code, 200, response.text)

    def _create_second_workspace(self):
        with self.session_factory() as db:
            user = db.scalar(
                select(User).where(User.google_subject == "daedalus-local-demo-admin")
            )
            workspace = Organization(
                name="Independent workspace",
                slug="independent",
                domain="independent.example",
                verification_status="verified",
                created_at=server.utcnow(),
            )
            db.add(workspace)
            db.flush()
            db.add(
                Membership(
                    user_id=user.id,
                    organization_id=workspace.id,
                    role="admin",
                    status="approved",
                    created_at=server.utcnow(),
                )
            )
            db.commit()
            return workspace.id

    def test_meraki_org_requires_workspace_grant_and_grants_are_isolated(self):
        self._connect_key()
        listed = self.client.post("/api/meraki/organizations")
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(
            [item["authorized"] for item in listed.json()["organizations"]],
            [False, False],
        )

        denied = self.client.post(
            "/api/meraki/reports", json={"organization_id": "cisco-org-csp"}
        )
        self.assertEqual(denied.status_code, 403, denied.text)

        granted = self.client.post(
            "/api/meraki/organization-scope",
            json={"meraki_organization_id": "cisco-org-csp"},
        )
        self.assertEqual(granted.status_code, 200, granted.text)
        self.assertTrue(granted.json()["authorized"])

        listed = self.client.post("/api/meraki/organizations").json()["organizations"]
        self.assertEqual([item["authorized"] for item in listed], [True, False])

        accepted = self.client.post(
            "/api/meraki/reports", json={"organization_id": "cisco-org-csp"}
        )
        self.assertEqual(accepted.status_code, 200, accepted.text)
        report_job_id = accepted.json()["id"]

        # A separate Daedalus workspace has no inherited Cisco organization grants.
        other_workspace_id = self._create_second_workspace()
        selected = self.client.post(
            "/api/workspaces/select", json={"organization_id": other_workspace_id}
        )
        self.assertEqual(selected.status_code, 200, selected.text)
        self._connect_key()
        other_list = self.client.post("/api/meraki/organizations").json()["organizations"]
        self.assertEqual([item["authorized"] for item in other_list], [False, False])
        other_denied = self.client.post(
            "/api/meraki/reports", json={"organization_id": "cisco-org-csp"}
        )
        self.assertEqual(other_denied.status_code, 403, other_denied.text)

        with self.session_factory() as db:
            job = db.get(ReportJob, report_job_id)
            job.status = "completed"
            job.progress = 100
            job.updated_at = server.utcnow()
            db.commit()

        self.client.post(
            "/api/workspaces/select",
            json={"organization_id": 1},
        )
        revoked = self.client.request(
            "DELETE",
            "/api/meraki/organization-scope",
            json={"meraki_organization_id": "cisco-org-csp"},
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        after_revoke = self.client.post(
            "/api/meraki/reports", json={"organization_id": "cisco-org-csp"}
        )
        self.assertEqual(after_revoke.status_code, 403, after_revoke.text)

        actions = self.client.get("/api/audit-log").json()["events"]
        self.assertIn("meraki.organization_scope.granted", [row["action"] for row in actions])
        self.assertIn("meraki.organization_scope.revoked", [row["action"] for row in actions])

        with self.session_factory() as db:
            self.assertEqual(
                db.scalar(select(Organization).where(Organization.slug == "csp")).domain,
                "cybersecuritypilot.org",
            )
            self.assertGreaterEqual(
                db.scalar(
                    select(AuditLog.id).where(
                        AuditLog.action == "meraki.organization_scope.granted"
                    )
                ),
                1,
            )

    def test_replacing_the_workspace_key_clears_previous_org_approvals(self):
        self._connect_key()
        granted = self.client.post(
            "/api/meraki/organization-scope",
            json={"meraki_organization_id": "cisco-org-csp"},
        )
        self.assertEqual(granted.status_code, 200, granted.text)

        self._connect_key("replacement-meraki-key-654321")
        organizations = self.client.post("/api/meraki/organizations").json()[
            "organizations"
        ]
        self.assertEqual([item["authorized"] for item in organizations], [False, False])
        self.assertIn(
            "meraki.organization_scopes.cleared",
            [row["action"] for row in self.client.get("/api/audit-log").json()["events"]],
        )

    def test_completed_meraki_reports_save_scoped_changes_coverage_and_live_notification(self):
        self._connect_key()
        self.client.post("/api/meraki/organization-scope", json={"meraki_organization_id": "cisco-org-csp"})
        self.report_patch.stop()
        first_snapshot = {"organization": {"id": "cisco-org-csp"},
            "networks": [{"id": "n1", "name": "CSP office", "productTypes": ["appliance", "wireless"]}],
            "devices": [{"serial": "fixture-device", "name": "Edge appliance", "model": "MX fixture", "networkId": "n1", "firmware": "v1", "status": "online"}], "security_controls": [
            {"network_id": "n1", "control": "Intrusion protection", "status": "complete", "data": {"mode": "enabled"}},
            {"network_id": "n1", "control": "Malware protection", "status": "complete", "data": {"mode": "enabled"}},
        ]}
        second_snapshot = {"organization": {"id": "cisco-org-csp"},
            "summary": {"network_count": 1, "device_count": 1, "security_controls_collected": 1,
                "security_controls_unavailable": 1, "security_controls_unsupported": 0},
            "collected_at": "2026-10-02T12:00:00Z",
            "networks": [{"id": "n1", "name": "CSP office", "productTypes": ["appliance", "wireless"]}],
            "devices": [{"serial": "fixture-device", "name": "Edge appliance", "model": "MX fixture", "networkId": "n1", "firmware": "v2", "status": "offline"}], "security_controls": [
            {"network_id": "n1", "control": "Intrusion protection", "status": "complete", "data": {"mode": "disabled"}},
            {"network_id": "n1", "control": "Malware protection", "status": "unavailable", "data": None},
        ], "findings": [{"status": "Review", "title": "Check access policy", "detail": "Review this network."}],
            "warnings": ["One endpoint was unavailable."],
            "client_usage": {"status": "complete", "data": {"clients_with_usage_count": 7,
                "usage": {"total": 1200, "downstream": 900, "upstream": 300},
                "usage_unit": "kb (Meraki API)", "requested_timespan_seconds": 86400}},
            "topology": [{"network_name": "CSP office", "status": "complete", "data": {
                "nodes": [{"device_serial": "private-serial"}], "links": [{"link_count": 2}],
                "omitted_node_count": 4, "omitted_link_count": 3, "reported_error_count": 1,
                "scope": "Managed devices only."}}]}
        from daedalus.meraki_wan import summarize_wan_usage
        from daedalus.meraki_clients import summarize_wireless_clients
        second_snapshot["wireless_clients"] = [{"network_id": "n1", "network_name": "CSP office", "status": "complete", "data": summarize_wireless_clients([
            {"id": "private-client", "mac": "private-client-mac", "recentDeviceConnection": "Wireless", "ssid": "Guest", "os": "iOS", "vlan": "10", "status": "Online"}])}]
        second_snapshot["wan_usage"] = [{"network_id": "n1", "network_name": "CSP office", "status": "complete", "data": summarize_wan_usage([
            {"startTime": "2026-10-08T00:00:00Z", "endTime": "2026-10-08T01:00:00Z", "byInterface": [{"interface": "wan1", "sent": 450000000, "received": 0}]}])}]
        with (
            patch.object(server, "MerakiClient") as client_class,
            patch.object(server, "REPORTS_DIR", self.root / "reports"),
            patch.object(server, "build_meraki_security_pdf", return_value=b"%PDF-fixture"),
            patch.object(server.live_hub, "publish", new_callable=AsyncMock) as publish,
        ):
            client_class.return_value.__enter__.return_value.collect_security_report.side_effect = [first_snapshot, second_snapshot]
            first = self.client.post("/api/meraki/reports", json={"organization_id": "cisco-org-csp"})
            self.assertEqual(first.status_code, 200, first.text)
            first_id = first.json()["id"]
            self.assertEqual(self.client.get("/api/notifications").json()["notifications"], [])
            second = self.client.post("/api/meraki/reports", json={"organization_id": "cisco-org-csp"})
            self.assertEqual(second.status_code, 200, second.text)
            second_id = second.json()["id"]
            self.assertEqual(publish.await_count, 2)
            self.assertEqual(publish.await_args.args[1]["type"], "meraki_report_finished")
            self.assertEqual(publish.await_args.args[1]["changed_control_count"], 1)
            self.assertEqual(publish.await_args.args[1]["inventory_change_count"], 1)
        reports = self.client.get("/api/reports").json()["reports"]
        row = next(report for report in reports if report["id"] == second_id)
        inbox = self.client.get("/api/notifications").json()
        self.assertEqual(inbox["unread_count"], 1)
        self.assertEqual(len(inbox["notifications"]), 1)
        notice = inbox["notifications"][0]
        self.assertEqual(notice["source_type"], "meraki_report")
        self.assertEqual(notice["source_id"], second_id)
        self.assertEqual(notice["reason"], "changes_and_coverage")
        self.assertEqual(notice["tab"], "meraki")
        self.assertIn("network evidence change", notice["summary"])
        self.assertNotIn("security-control change", notice["summary"])
        self.assertIn("inventory change", notice["summary"])
        self.assertIn("coverage changed", notice["summary"])
        self.assertEqual(row["status"], "completed")
        self.assertEqual(row["meraki_comparison"]["changed_control_count"], 1)
        self.assertEqual(row["meraki_comparison"]["coverage_change_count"], 1)
        self.assertEqual(row["meraki_comparison"]["inventory_change_count"], 1)
        saved = self.client.get(row["meraki_changes_url"]).json()["comparison"]
        snapshot = self.client.get(row["meraki_snapshot_url"])
        self.assertEqual(snapshot.status_code, 200)
        self.assertEqual(snapshot.json()["meraki"], second_snapshot)
        self.assertEqual(snapshot.headers["cache-control"], "no-store")
        details_response = self.client.get(f"/api/meraki/reports/{second_id}/details")
        self.assertEqual(details_response.status_code, 200, details_response.text)
        self.assertEqual(details_response.headers["cache-control"], "no-store")
        details = details_response.json()
        self.assertEqual(details["summary"]["device_count"], 1)
        from daedalus.meraki_planning import project_unifi_plan
        self.assertEqual(details["unifi_plan"], project_unifi_plan(snapshot.json()["unifi_plan"]))
        self.assertEqual(details["unifi_plan"]["lifecycle"]["summary"]["unknown"], 1)
        self.assertEqual(details["action_plan"], snapshot.json()["meraki_action_plan"])
        self.assertTrue(details["action_plan"]["rows"])
        self.assertEqual(details["wan_usage"][0]["data"]["interfaces"], second_snapshot["wan_usage"][0]["data"]["interfaces"])
        self.assertNotIn("intervals", details["wan_usage"][0]["data"])
        self.assertEqual(len(snapshot.json()["meraki"]["wan_usage"][0]["data"]["intervals"]), 1)
        self.assertEqual(details["unifi_plan"]["price_observed_on"], "2026-10-07")
        self.assertEqual(len(details["unifi_plan"]["scenarios"]), 2)
        self.assertEqual(details["networks"][0]["name"], "CSP office")
        self.assertEqual(details["devices"][0]["name"], "Edge appliance")
        self.assertNotIn("serial", details["devices"][0])
        self.assertEqual(details["controls"][0]["evidence_preview"], '{"mode": "disabled"}')
        self.assertEqual(details["findings"][0]["title"], "Check access policy")
        self.assertEqual(details["warnings"], ["One endpoint was unavailable."])
        self.assertEqual(details["client_usage"]["clients_with_usage_count"], 7)
        self.assertEqual(details["client_usage"]["usage"]["downstream"], 900)
        from daedalus.meraki_paths import build_path_analysis, project_path_analysis
        saved_meraki = self.client.get(f"/api/meraki/reports/{second_id}/snapshot").json()
        self.assertEqual(saved_meraki["meraki_path_analysis"], build_path_analysis(saved_meraki["meraki"]))
        self.assertEqual(details["path_analysis"], project_path_analysis(saved_meraki["meraki_path_analysis"], saved_meraki["meraki"]))
        self.assertEqual(details["path_analysis"]["status"], "available")
        self.assertEqual(details["wireless_clients"][0]["data"]["wireless_client_count"], 1)
        self.assertEqual(details["wireless_clients"][0]["data"]["distributions"]["ssid"]["rows"], [{"label": "Guest", "count": 1}])
        self.assertNotIn("private-client", str(details["wireless_clients"]))
        self.assertEqual(details["topology"][0]["node_count"], 1)
        self.assertEqual(details["topology"][0]["omitted_node_count"], 4)
        self.assertNotIn("nodes", details["topology"][0])
        self.assertNotIn("private-serial", str(details["topology"]))
        self.assertEqual(saved["previous_report_id"], first_id)
        self.assertFalse(saved["baseline"])
        self.assertEqual(saved["changes"][0]["control"], "Intrusion protection")
        self.assertEqual(saved["inventory_changes"][0]["changed_fields"], ["firmware", "status"])
        self.assertEqual(saved["coverage_changes"][0]["control"], "Malware protection")
        baseline = self.client.get(f"/api/meraki/reports/{first_id}/changes").json()["comparison"]
        self.assertTrue(baseline["baseline"])
        with self.session_factory() as db:
            self.assertEqual(db.get(ReportJob, first_id).report_snapshot["meraki"], first_snapshot)
            self.assertIn("meraki.report.changes_detected", [event.action for event in db.scalars(select(AuditLog)).all()])

        with self.session_factory() as db:
            saved_job = db.get(ReportJob, second_id)
            saved_snapshot = dict(saved_job.report_snapshot)
            oversized_meraki = dict(saved_snapshot["meraki"])
            oversized_meraki["networks"] = [{"name": f"Network {index}"} for index in range(101)]
            oversized_meraki["devices"] = [{"name": f"Device {index}"} for index in range(201)]
            oversized_meraki["security_controls"] = [{
                "control": "Large control",
                "status": "complete",
                "data": {"large_value": "x" * 1_000_000, "many_values": list(range(1000))},
            }] + [{"control": f"Control {index}", "status": "complete", "data": {}} for index in range(200)]
            oversized_meraki["topology_detail_version"] = 1
            oversized_meraki["topology"] = [{"network_name": f"Network {index}", "status": "complete", "data": {"nodes": [], "links": []}} for index in range(101)]
            oversized_meraki["switch_power"] = [{"device_serial": "SW_1", "network_name": "HQ", "status": "complete", "data": {"measured_energy_wh": 240, "measured_average_watts": 10, "port_count": 24, "energy_coverage": "partial", "private": "never-serialize"}} for _ in range(101)]
            from daedalus.meraki_switch import summarize_switch_ports
            oversized_meraki["switch_ports"] = [{"device_serial": "SW_1", "status": "complete", "data": summarize_switch_ports([{"portId": str(i)} for i in range(70)])} for _ in range(22)]
            from daedalus.meraki_neighbors import summarize_neighbors
            oversized_meraki["devices"].append({"serial": "DISCOVERY_SWITCH", "model": "MS120", "networkId": "DISCOVERY_NET", "name": "Discovery Switch"})
            oversized_meraki["switch_neighbors"] = [{"device_serial": "DISCOVERY_SWITCH", "network_id": "DISCOVERY_NET", "network_name": "HQ", "status": "complete", "data": summarize_neighbors({"ports": {str(i): {} for i in range(70)}}, {}, "DISCOVERY_SWITCH")} for _ in range(22)]
            oversized_meraki["findings"] = [{"title": f"Finding {index}"} for index in range(101)]
            oversized_meraki["warnings"] = [f"Warning {index}" for index in range(101)]
            from daedalus.meraki_cis8 import build_cis8_assessment
            saved_snapshot["meraki_cis8"] = build_cis8_assessment(oversized_meraki)
            saved_snapshot["meraki_cis8"]["private"] = "never-serialize"
            saved_snapshot["meraki"] = oversized_meraki
            saved_job.report_snapshot = saved_snapshot
            db.commit()
        bounded = self.client.get(f"/api/meraki/reports/{second_id}/details").json()
        self.assertEqual(len(bounded["switch_neighbors"]["switches"]), 20)
        self.assertEqual(bounded["switch_neighbors"]["additional_switches"], 2)
        self.assertEqual(len(bounded["switch_neighbors"]["switches"][0]["data"]["rows"]), 50)
        self.assertEqual(bounded["switch_neighbors"]["switches"][0]["data"]["additional_rows"], 20)
        self.assertEqual(len(bounded["switch_ports"]["switches"]), 20)
        self.assertEqual(bounded["switch_ports"]["additional_switches"], 2)
        self.assertEqual(len(bounded["switch_ports"]["switches"][0]["data"]["rows"]), 50)
        self.assertEqual(bounded["switch_ports"]["switches"][0]["data"]["additional_rows"], 20)
        self.assertEqual(len(self.client.get(f"/api/meraki/reports/{second_id}/snapshot").json()["meraki"]["switch_ports"][0]["data"]["rows"]), 70)
        self.assertEqual(len(bounded["switch_power"]), 100)
        self.assertEqual(bounded["switch_power"][0]["data"]["measured_energy_wh"], 240)
        self.assertNotIn("private", bounded["switch_power"][0]["data"])
        self.assertEqual(len(bounded["networks"]), 100)
        self.assertEqual(len(bounded["devices"]), 200)
        self.assertEqual(len(bounded["controls"]), 200)
        self.assertEqual(len(bounded["findings"]), 100)
        self.assertEqual(len(bounded["warnings"]), 100)
        self.assertEqual(bounded["truncated"], {"networks": 1, "devices": 2, "controls": 1, "topology": 1, "switch_power": 1, "findings": 1, "warnings": 1})
        self.assertEqual(len(bounded["topology"]), 100)
        self.assertEqual(len(bounded["cis8_assessment"]["rows"]), 18)
        self.assertEqual(sum(bounded["cis8_assessment"]["summary"].values()), 18)
        self.assertNotIn("never-serialize", str(bounded["cis8_assessment"]))
        self.assertEqual(len(bounded["topology_graph"]["networks"]), 20)
        self.assertEqual(bounded["topology_graph"]["additional_networks"], 81)
        self.assertLessEqual(len(bounded["controls"][0]["evidence_preview"]), 3000)
        self.assertTrue(bounded["controls"][0]["evidence_truncated"])

        other = self._create_second_workspace()
        self.client.post("/api/workspaces/select", json={"organization_id": other})
        self.assertEqual(self.client.get(row["meraki_changes_url"]).status_code, 404)
        self.assertEqual(self.client.get(row["meraki_snapshot_url"]).status_code, 404)
        self.assertEqual(self.client.get(f"/api/meraki/reports/{second_id}/details").status_code, 404)


if __name__ == "__main__":
    unittest.main()
